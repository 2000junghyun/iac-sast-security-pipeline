package scanner

import (
	"fmt"
	"log"
	"os"
)

// Scanner는 Trivy 스캔 워크플로우를 오케스트레이션
type Scanner struct {
	pathManager    *PathManager
	trivyExecutor  *TrivyExecutor
	parserExecutor *ParserExecutor
}

// NewScanner는 Scanner 인스턴스를 생성
func NewScanner(trivyPath, parserPath, customPolicies, storagePath, scanResultsPath string) *Scanner {
	return &Scanner{
		pathManager:    NewPathManager(storagePath, scanResultsPath),
		trivyExecutor:  NewTrivyExecutor(trivyPath, customPolicies),
		parserExecutor: NewParserExecutor(parserPath),
	}
}

// 스캔 요청 정보를 담는 구조체
type ScanRequest struct {
	ProjectID    int
	ProjectPath  string
	MRIID        int
	SourceBranch string
	StoragePath  string
	FilePaths    []string
}

// ScanResult는 스캔 결과 정보를 담는 구조체
type ScanResult struct {
	Success            bool
	ParsedDir          string
	OriginalFile       string
	HasVulnerabilities bool
	ParserSuccess      bool
}

// Scan은 전체 스캔 워크플로우를 실행
func (s *Scanner) Scan(req ScanRequest) (*ScanResult, error) {
	log.Printf("Starting Trivy scan for Project %s, MR #%d", req.ProjectPath, req.MRIID)

	// 1. 경로 준비
	paths, err := s.pathManager.PrepareScanPaths(req)
	if err != nil {
		return nil, err
	}

	// 2. Trivy 스캔 실행
	if err := s.trivyExecutor.ExecuteScan(paths.TargetPath, paths.OriginalFilePath); err != nil {
		return nil, err
	}

	// 3. 취약점 유무 확인
	hasVulnerabilities, _ := CheckVulnerabilitiesInOriginal(paths.OriginalFilePath)

	// 4. Parser 실행 #1 - 파일 분리
	parserSuccess := true
	if err := s.parserExecutor.SplitResults(paths.OriginalFilePath, paths.ParsedOutputDir); err != nil {
		log.Printf("⚠️  Parser splitting failed: %v", err)
		log.Printf("⚠️  Original scan results are still available at: %s", paths.OriginalFilePath)
		parserSuccess = false
	}

	// 5. Parser 실행 #2 - Excel 생성 (실패해도 계속 진행)
	if err := s.parserExecutor.GenerateExcel(paths.OriginalFilePath, paths.ExcelFilePath); err != nil {
		log.Printf("⚠️  Excel generation failed: %v", err)
		log.Printf("⚠️  Excel file will not be available")
	}

	return &ScanResult{
		Success:            true,
		ParsedDir:          paths.ParsedOutputDir,
		OriginalFile:       paths.OriginalFilePath,
		HasVulnerabilities: hasVulnerabilities,
		ParserSuccess:      parserSuccess,
	}, nil
}

// ValidateSetup은 Scanner의 모든 의존성이 올바르게 설정되었는지 확인
func (s *Scanner) ValidateSetup() error {
	// Trivy executor 검증
	if err := s.trivyExecutor.Validate(); err != nil {
		return err
	}

	// Parser executor 검증
	if err := s.parserExecutor.Validate(); err != nil {
		return err
	}

	log.Printf("✓ Scanner setup validated successfully")
	return nil
}

// CheckVulnerabilitiesInOriginal은 원본 JSON 파일에서 취약점이 있는지 확인
func CheckVulnerabilitiesInOriginal(filePath string) (bool, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to read file: %w", err)
	}

	// Trivy 결과에서 "Results" 배열이 비어있지 않은지 확인
	// 간단한 문자열 검색으로 판단 (JSON 파싱 없이)
	content := string(data)

	// "Results":[] 또는 "Results": [] 패턴 확인
	if len(content) < 50 {
		// 파일이 너무 작으면 빈 결과로 판단
		return false, nil
	}

	// "Misconfigurations" 또는 "Results" 키워드가 있고 내용이 있는지 확인
	hasMisconfigurations := false
	hasResults := false

	// 간단한 휴리스틱: "Misconfigurations"가 있고 그 뒤에 내용이 있는지
	for i := 0; i < len(content)-20; i++ {
		if content[i:i+18] == `"Misconfigurations"` {
			hasMisconfigurations = true
			// "Misconfigurations":[ 다음에 ] 바로 오지 않으면 내용이 있음
			remaining := content[i+18:]
			for j := 0; j < len(remaining)-1; j++ {
				if remaining[j] == '[' {
					if j+1 < len(remaining) && remaining[j+1] != ']' {
						hasResults = true
					}
					break
				}
			}
			break
		}
	}

	return hasMisconfigurations && hasResults, nil
}