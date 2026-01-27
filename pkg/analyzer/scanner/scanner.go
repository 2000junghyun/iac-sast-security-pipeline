package scanner

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// Trivy를 사용하여 Terraform 파일을 스캔하는 구조체
type Scanner struct {
	trivyPath       string
	parserPath      string
	customPolicies  string
	scanResultsPath string
}

// Scanner 인스턴스를 생성
func NewScanner(trivyPath, parserPath, customPolicies, scanResultsPath string) *Scanner {
	return &Scanner{
		trivyPath:       trivyPath,
		parserPath:      parserPath,
		customPolicies:  customPolicies,
		scanResultsPath: scanResultsPath,
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

// 스캔 결과 정보를 담는 구조체
type ScanResponse struct {
	Success      bool
	Comment      string
	ParsedDir    string
	OriginalFile string
}

// 다운로드된 Terraform 파일들을 Trivy로 스캔하고 결과를 반환
func (s *Scanner) Scan(req ScanRequest) (*ScanResponse, error) {
	log.Printf("Starting Trivy scan for Project %s, MR #%d", req.ProjectPath, req.MRIID)

	// 스캔 대상 경로: storage/{projectID}/mr-{mrIID}
	targetPath := filepath.Join(req.StoragePath, fmt.Sprintf("%d", req.ProjectID), fmt.Sprintf("mr-%d", req.MRIID))
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("target path does not exist: %s", targetPath)
	}

	// 원본 결과 저장 경로: scan-results/original/
	originalResultsPath := filepath.Join(s.scanResultsPath, "original")
	if err := os.MkdirAll(originalResultsPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create original results directory: %w", err)
	}

	// 원본 결과 파일명: {projectPath}-{mrIID}.json
	originalFileName := fmt.Sprintf("%s-%d.json",
		filepath.Base(req.ProjectPath),
		req.MRIID)
	originalFilePath := filepath.Join(originalResultsPath, originalFileName)

	// Parsed 스캔 결과 저장 디렉토리: scan-results/{projectPath}/mr-{mrIID}/
	parsedOutputDir := filepath.Join(s.scanResultsPath, filepath.Base(req.ProjectPath), fmt.Sprintf("mr-%d", req.MRIID))
	if err := os.MkdirAll(parsedOutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create parsed output directory: %w", err)
	}

	// Step 1: Trivy 스캔 실행
	// ./trivy config --config-check ./custom-policies --check-namespaces user \
	//   --format json -o ./scan-results/original/{project-MR}.json ./storage/{project}/{MR}
	trivyArgs := []string{
		"config",
		"--config-check", s.customPolicies,
		"--check-namespaces", "user",
		"--format", "json",
		"-o", originalFilePath,
		targetPath,
	}

	trivyCmd := exec.Command(s.trivyPath, trivyArgs...)
	trivyCmd.Stdout = os.Stdout
	trivyCmd.Stderr = os.Stderr

	if err := trivyCmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy scan failed: %w", err)
	}

	log.Printf("✓ Trivy scan completed successfully")
	log.Printf("✓ Original scan results saved to: %s", originalFilePath)

	// Step 2: trivy-parser 실행 (타겟별 파일 분리)
	// ./trivy-parser -input result-raw.json -output results/ -grouped -splitted -pretty
	parserArgs := []string{
		"-input", originalFilePath,
		"-output", parsedOutputDir + "/",
		"-grouped",
		"-splitted",
		"-pretty",
	}

	log.Printf("Executing trivy-parser command: %s %v", s.parserPath, parserArgs)

	parserCmd := exec.Command(s.parserPath, parserArgs...)
	parserCmd.Stdout = os.Stdout
	parserCmd.Stderr = os.Stderr

	parserSuccess := true
	if err := parserCmd.Run(); err != nil {
		log.Printf("⚠️  trivy-parser failed: %v", err)
		log.Printf("⚠️  Original scan results are still available at: %s", originalFilePath)
		parserSuccess = false
	} else {
		log.Printf("✓ trivy-parser completed successfully")
		log.Printf("✓ Parsed results saved to: %s", parsedOutputDir)
	}

	// 원본 JSON 파일에서 취약점 유무 확인
	hasVulnerabilities, err := checkVulnerabilitiesInOriginal(originalFilePath)
	if err != nil {
		log.Printf("⚠️  Failed to check vulnerabilities in original file: %v", err)
		// 파일 확인 실패 시 파서 결과로 판단
	}

	// Step 3: trivy-parser 실행 (Excel 파일 생성)
	// ./trivy-parser -input result-raw.json -output <프로젝트명>_#<MR번호>.xlsx -excel
	projectName := filepath.Base(req.ProjectPath)
	excelFileName := fmt.Sprintf("%s_#%d.xlsx", projectName, req.MRIID)
	excelFilePath := filepath.Join(parsedOutputDir, excelFileName)
	excelArgs := []string{
		"-input", originalFilePath,
		"-output", excelFilePath,
		"-excel",
	}

	log.Printf("Executing trivy-parser for Excel generation: %s %v", s.parserPath, excelArgs)

	excelCmd := exec.Command(s.parserPath, excelArgs...)
	excelCmd.Stdout = os.Stdout
	excelCmd.Stderr = os.Stderr

	if err := excelCmd.Run(); err != nil {
		log.Printf("⚠️  trivy-parser Excel generation failed: %v", err)
		log.Printf("⚠️  Excel file will not be available")
	} else {
		log.Printf("✓ trivy-parser Excel generation completed successfully")
		log.Printf("✓ Excel file saved to: %s", excelFilePath)
	}

	// Step 4: 스캔 결과를 기반으로 댓글 생성
	var comment string
	if !parserSuccess {
		// 파서 실행 자체가 실패한 경우 - 취약점 유무로 구분
		if err == nil && !hasVulnerabilities {
			// 취약점이 없어서 파서가 처리할 내용이 없는 경우
			comment = "## 🎉 취약점 스캔 완료\n\n**발견된 보안 문제가 없습니다.** 스캔한 파일들이 모든 보안 정책을 통과했습니다."
		} else {
			// 실제 파서 오류
			comment = "파일 스캔이 완료됐습니다.\n\n⚠️ 스캔 결과 파싱에 실패했습니다. 원본 스캔 결과 파일을 확인해주세요."
		}
	} else {
		// 파서 실행은 성공한 경우
		generatedComment, err := BuildScanComment(parsedOutputDir, req.FilePaths)
		if err != nil {
			log.Printf("⚠️  Failed to build scan comment: %v", err)
			// BuildScanComment 실패 - 취약점 유무로 구분
			if hasVulnerabilities {
				// 취약점은 있는데 댓글 생성 실패
				comment = "파일 스캔이 완료됐습니다.\n\n⚠️ 스캔 결과 요약 생성에 실패했습니다. 상세 결과는 스캔 결과 파일을 확인해주세요."
			} else {
				// 취약점이 없음
				comment = "## 🎉 취약점 스캔 완료\n\n**발견된 보안 문제가 없습니다.** 스캔한 파일들이 모든 보안 정책을 통과했습니다."
			}
		} else {
			// 정상적으로 댓글 생성됨
			comment = generatedComment
		}
	}

	return &ScanResponse{
		Success:      true,
		Comment:      comment,
		ParsedDir:    parsedOutputDir,
		OriginalFile: originalFilePath,
	}, nil
}

// 원본 JSON 파일에서 취약점이 있는지 확인
func checkVulnerabilitiesInOriginal(filePath string) (bool, error) {
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

// Trivy 실행 파일과 필요한 디렉토리가 존재하는지 확인
func (s *Scanner) ValidateSetup() error {
	// Trivy 실행 파일 확인
	if _, err := os.Stat(s.trivyPath); os.IsNotExist(err) {
		return fmt.Errorf("trivy executable not found at: %s", s.trivyPath)
	}

	// Trivy-parser 실행 파일 확인
	if _, err := os.Stat(s.parserPath); os.IsNotExist(err) {
		return fmt.Errorf("trivy-parser executable not found at: %s", s.parserPath)
	}

	// Custom policies 디렉토리 확인
	if _, err := os.Stat(s.customPolicies); os.IsNotExist(err) {
		return fmt.Errorf("custom policies directory not found at: %s", s.customPolicies)
	}

	log.Printf("✓ Scanner setup validated successfully")

	return nil
}