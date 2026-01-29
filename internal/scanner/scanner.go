package scanner

import (
	"fmt"
	"log"
	"os"
	"strings"
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

	content := string(data)

	// "Misconfigurations": [] 패턴 확인 (JSON 파싱 없이 문자열 검색)
	if len(content) < 50 {
		// 파일이 너무 작으면 빈 결과로 판단
		return false, nil
	}

	// "Misconfigurations" 또는 "Results" 키워드가 있고 내용이 있는지 확인

	// "Misconfigurations": [ 패턴을 찾아서 빈 배열인지 확인
	searchStr := `"Misconfigurations"`
	idx := strings.Index(content, searchStr)

	if idx == -1 {
		// "Misconfigurations" 키워드가 없으면 취약점 없음
		return false, nil
	}

	// "Misconfigurations" 이후 첫 번째 [ 찾기
	remaining := content[idx+len(searchStr):]
	bracketIdx := strings.IndexByte(remaining, '[')

	if bracketIdx == -1 {
		return false, nil
	}

	// [ 이후 공백을 건너뛰고 ] 가 바로 오는지 확인
	afterBracket := remaining[bracketIdx+1:]
	trimmed := strings.TrimLeft(afterBracket, " \t\n\r")

	// 빈 배열 "Misconfigurations": [] 이면 취약점 없음
	if len(trimmed) > 0 && trimmed[0] == ']' {
		return false, nil
	}

	// 빈 배열이 아니면 취약점 있음
	return true, nil
}
