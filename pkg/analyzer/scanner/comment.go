package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 파싱된 스캔 결과 JSON 파일의 구조
type ScanResultFile struct {
	SchemaVersion   int             `json:"SchemaVersion"`
	CreatedAt       string          `json:"CreatedAt"`
	ArtifactName    string          `json:"ArtifactName"`
	ArtifactType    string          `json:"ArtifactType"`
	SeveritySummary SeveritySummary `json:"SeveritySummary"`
	Results         []Result        `json:"Results"`
}

// 심각도별 검출 개수
type SeveritySummary struct {
	CRITICAL int `json:"CRITICAL"`
	HIGH     int `json:"HIGH"`
	MEDIUM   int `json:"MEDIUM"`
	LOW      int `json:"LOW"`
}

// 스캔 결과의 개별 항목
type Result struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Type              string             `json:"Type"`
	MisconfSummary    MisconfSummary     `json:"MisconfSummary"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations"`
}

// 정책 위반 요약
type MisconfSummary struct {
	Successes int `json:"Successes"`
	Failures  int `json:"Failures"`
}

// 개별 정책 위반 정보
type Misconfiguration struct {
	ID          string      `json:"ID"`
	Title       string      `json:"Title"`
	Description string      `json:"Description"`
	Namespace   string      `json:"Namespace"`
	Resolution  string      `json:"Resolution"`
	Severity    string      `json:"Severity"`
	PrimaryURL  string      `json:"PrimaryURL"`
	Status      string      `json:"Status"`
	Violations  []Violation `json:"Violations,omitempty"`
}

// 정책 위반의 개별 발생 위치
type Violation struct {
	Resource  string `json:"Resource"`
	Provider  string `json:"Provider"`
	Service   string `json:"Service"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Message   string `json:"Message"`
}

// 파일별 스캔 결과
type FileScanResult struct {
	FileName         string            // 원본 파일명 (예: test-01-rename.tf)
	TrivyPassed      bool              // Trivy 기본 정책 통과 여부
	CustomPassed     bool              // 커스텀 정책 통과 여부
	TrivyViolations  []PolicyViolation // Trivy 기본 정책 위반 목록
	CustomViolations []PolicyViolation // 커스텀 정책 위반 목록
}

// 정책 위반 정보
type PolicyViolation struct {
	Title    string
	Severity string
}

// 스캔 결과를 기반으로 MR 댓글을 생성
func BuildScanComment(parsedOutputDir string, filePaths []string) (string, error) {
	totalTrivySummary := SeveritySummary{}
	totalCustomSummary := SeveritySummary{}

	fileResults := make(map[string]*FileScanResult) // 파일별 스캔 결과 수집

	for _, filePath := range filePaths {
		normalizedFileName := strings.ReplaceAll(filePath, "/", "%")       // 파일명 정규화 (슬래시를 퍼센트로 치환)
		normalizedFileName = strings.TrimSuffix(normalizedFileName, ".tf") // .tf 확장자 제거

		// [TV] 파일 읽기 (Trivy 기본 정책)
		tvFileName := "[TV]" + normalizedFileName + ".json"
		tvFilePath := filepath.Join(parsedOutputDir, tvFileName)
		tvResult, tvErr := parseScanResultFile(tvFilePath)

		// [KB] 파일 읽기 (커스텀 정책)
		kbFileName := "[KB]" + normalizedFileName + ".json"
		kbFilePath := filepath.Join(parsedOutputDir, kbFileName)
		kbResult, kbErr := parseScanResultFile(kbFilePath)

		if fileResults[filePath] == nil {
			fileResults[filePath] = &FileScanResult{
				FileName:         filePath,
				TrivyPassed:      true,
				CustomPassed:     true,
				TrivyViolations:  []PolicyViolation{},
				CustomViolations: []PolicyViolation{},
			}
		}

		// Trivy 기본 정책 결과 처리
		if tvErr == nil && tvResult != nil {
			// 전체 요약에 추가
			totalTrivySummary.CRITICAL += tvResult.SeveritySummary.CRITICAL
			totalTrivySummary.HIGH += tvResult.SeveritySummary.HIGH
			totalTrivySummary.MEDIUM += tvResult.SeveritySummary.MEDIUM
			totalTrivySummary.LOW += tvResult.SeveritySummary.LOW

			if tvResult.SeveritySummary.CRITICAL > 0 ||
				tvResult.SeveritySummary.HIGH > 0 ||
				tvResult.SeveritySummary.MEDIUM > 0 ||
				tvResult.SeveritySummary.LOW > 0 {
				fileResults[filePath].TrivyPassed = false
				// 위반 정책 수집
				for _, result := range tvResult.Results {
					for _, misconf := range result.Misconfigurations {
						fileResults[filePath].TrivyViolations = append(
							fileResults[filePath].TrivyViolations,
							PolicyViolation{
								Title:    misconf.Title,
								Severity: misconf.Severity,
							},
						)
					}
				}
			}
		}

		// 커스텀 정책 결과 처리
		if kbErr == nil && kbResult != nil {
			// 전체 요약에 추가
			totalCustomSummary.CRITICAL += kbResult.SeveritySummary.CRITICAL
			totalCustomSummary.HIGH += kbResult.SeveritySummary.HIGH
			totalCustomSummary.MEDIUM += kbResult.SeveritySummary.MEDIUM
			totalCustomSummary.LOW += kbResult.SeveritySummary.LOW

			if kbResult.SeveritySummary.CRITICAL > 0 ||
				kbResult.SeveritySummary.HIGH > 0 ||
				kbResult.SeveritySummary.MEDIUM > 0 ||
				kbResult.SeveritySummary.LOW > 0 {
				fileResults[filePath].CustomPassed = false
				// 위반 정책 수집
				for _, result := range kbResult.Results {
					for _, misconf := range result.Misconfigurations {
						fileResults[filePath].CustomViolations = append(
							fileResults[filePath].CustomViolations,
							PolicyViolation{
								Title:    misconf.Title,
								Severity: misconf.Severity,
							},
						)
					}
				}
			}
		}
	}

	// 댓글 생성
	var comment strings.Builder

	// 스캔된 파일 목록
	comment.WriteString("**[ Scanned files ]**\n")
	for _, filePath := range filePaths {
		comment.WriteString(fmt.Sprintf("- `%s`\n", filePath))
	}
	comment.WriteString("\n")

	// 스캔 요약
	comment.WriteString("---\n")
	comment.WriteString("**[ Scan Summary ]**\n")
	comment.WriteString("```\n")
	comment.WriteString(fmt.Sprintf("Severity Summary:\n- CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d\n\n",
		totalCustomSummary.CRITICAL+totalTrivySummary.CRITICAL,
		totalCustomSummary.HIGH+totalTrivySummary.HIGH,
		totalCustomSummary.MEDIUM+totalTrivySummary.MEDIUM,
		totalCustomSummary.LOW+totalTrivySummary.LOW))
	comment.WriteString(fmt.Sprintf("Policy Summary:\n- Trivy Built-in Policy: %d, Custom Policy: %d\n\n",
		totalTrivySummary.CRITICAL+totalTrivySummary.HIGH+totalTrivySummary.MEDIUM+totalTrivySummary.LOW,
		totalCustomSummary.CRITICAL+totalCustomSummary.HIGH+totalCustomSummary.MEDIUM+totalCustomSummary.LOW))
	comment.WriteString("```\n\n")

	// 파일별 위반 정책 목록
	for _, filePath := range filePaths {
		result, exists := fileResults[filePath]
		if !exists {
			continue
		}
		if !result.TrivyPassed || !result.CustomPassed {
			comment.WriteString(fmt.Sprintf("**`%s`:**\n", filePath))
			comment.WriteString("```\n")
			comment.WriteString("Violated Policies:\n")

			// 커스텀 정책 위반
			for _, violation := range result.CustomViolations {
				comment.WriteString(fmt.Sprintf("- %s\n", violation.Title))
			}

			// Trivy 기본 정책 위반
			for _, violation := range result.TrivyViolations {
				comment.WriteString(fmt.Sprintf("- %s\n", violation.Title))
			}

			comment.WriteString("```\n\n")
		}
	}

	return comment.String(), nil
}

// JSON 파일을 읽어서 스캔 결과를 파싱
func parseScanResultFile(filePath string) (*ScanResultFile, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var result ScanResultFile
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON %s: %w", filePath, err)
	}

	return &result, nil
}