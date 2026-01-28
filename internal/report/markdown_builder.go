package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// BuildScanComment는 스캔 결과를 기반으로 MR 댓글을 생성
func BuildScanComment(parsedOutputDir string) (string, error) {
	totalTrivySummary := SeveritySummary{}
	totalCustomSummary := SeveritySummary{}

	fileResults := make(map[string]*FileScanResult) // 파일별 스캔 결과 수집

	// 디렉토리 내 모든 JSON 파일 읽기
	files, err := os.ReadDir(parsedOutputDir)
	if err != nil {
		return "", fmt.Errorf("failed to read directory %s: %w", parsedOutputDir, err)
	}

	// 모든 JSON 파일 처리
	for _, file := range files {
		// 디렉토리이거나 JSON 파일이 아니면 스킵
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		fileName := file.Name()

		// 파일명 파싱하여 정책 타입과 원본 파일명 추출
		policyType, originalFile := parseFileName(fileName)
		if policyType == "" {
			// 파싱 실패 (인식할 수 없는 파일명)
			continue
		}

		// JSON 파일 읽기
		filePath := filepath.Join(parsedOutputDir, fileName)
		result, parseErr := parseScanResultFile(filePath)

		// 파일별 결과 초기화
		if fileResults[originalFile] == nil {
			fileResults[originalFile] = &FileScanResult{
				FileName:         originalFile,
				TrivyPassed:      true,
				CustomPassed:     true,
				TrivyViolations:  []PolicyViolation{},
				CustomViolations: []PolicyViolation{},
			}
		}

		// 파싱 실패 시 스킵
		if parseErr != nil || result == nil {
			continue
		}

		// 정책 타입에 따라 처리
		if policyType == "builtin" {
			processBuiltinPolicy(result, originalFile, fileResults, &totalTrivySummary)
		} else if policyType == "custom" {
			processCustomPolicy(result, originalFile, fileResults, &totalCustomSummary)
		}
	}

	// 파일명 정렬 (일관된 순서로 표시)
	sortedFiles := getSortedFileNames(fileResults)

	// 마크다운 생성
	return buildMarkdown(sortedFiles, fileResults, totalTrivySummary, totalCustomSummary), nil
}

// processBuiltinPolicy는 Trivy 기본 정책 결과 처리
func processBuiltinPolicy(result *ScanResultFile, originalFile string, fileResults map[string]*FileScanResult, totalSummary *SeveritySummary) {
	// 전체 요약에 추가
	totalSummary.CRITICAL += result.SeveritySummary.CRITICAL
	totalSummary.HIGH += result.SeveritySummary.HIGH
	totalSummary.MEDIUM += result.SeveritySummary.MEDIUM
	totalSummary.LOW += result.SeveritySummary.LOW

	if hasViolations(result.SeveritySummary) {
		fileResults[originalFile].TrivyPassed = false
		// 위반 정책 수집
		for _, res := range result.Results {
			for _, misconf := range res.Misconfigurations {
				fileResults[originalFile].TrivyViolations = append(
					fileResults[originalFile].TrivyViolations,
					PolicyViolation{
						Title:    misconf.Title,
						Severity: misconf.Severity,
					},
				)
			}
		}
	}
}

// processCustomPolicy는 커스텀 정책 결과 처리
func processCustomPolicy(result *ScanResultFile, originalFile string, fileResults map[string]*FileScanResult, totalSummary *SeveritySummary) {
	// 전체 요약에 추가
	totalSummary.CRITICAL += result.SeveritySummary.CRITICAL
	totalSummary.HIGH += result.SeveritySummary.HIGH
	totalSummary.MEDIUM += result.SeveritySummary.MEDIUM
	totalSummary.LOW += result.SeveritySummary.LOW

	if hasViolations(result.SeveritySummary) {
		fileResults[originalFile].CustomPassed = false
		// 위반 정책 수집
		for _, res := range result.Results {
			for _, misconf := range res.Misconfigurations {
				fileResults[originalFile].CustomViolations = append(
					fileResults[originalFile].CustomViolations,
					PolicyViolation{
						Title:    misconf.Title,
						Severity: misconf.Severity,
					},
				)
			}
		}
	}
}

// hasViolations는 심각도 요약에 위반 사항이 있는지 확인
func hasViolations(summary SeveritySummary) bool {
	return summary.CRITICAL > 0 || summary.HIGH > 0 || summary.MEDIUM > 0 || summary.LOW > 0
}

// getSortedFileNames는 파일명을 정렬된 슬라이스로 반환
func getSortedFileNames(fileResults map[string]*FileScanResult) []string {
	var sortedFiles []string
	for fileName := range fileResults {
		sortedFiles = append(sortedFiles, fileName)
	}
	sort.Strings(sortedFiles)
	return sortedFiles
}

// buildMarkdown는 최종 마크다운 댓글 생성
func buildMarkdown(sortedFiles []string, fileResults map[string]*FileScanResult, trivySummary, customSummary SeveritySummary) string {
	var comment strings.Builder

	// 스캔된 파일 목록
	buildFileListSection(&comment, sortedFiles)

	// 스캔 요약
	buildSummarySection(&comment, trivySummary, customSummary)

	// 파일별 위반 정책 목록
	buildViolationsSection(&comment, sortedFiles, fileResults)

	return comment.String()
}

// buildFileListSection는 스캔된 파일 목록 섹션 생성
func buildFileListSection(comment *strings.Builder, sortedFiles []string) {
	comment.WriteString("**[ Scanned files ]**\n")
	for _, fileName := range sortedFiles {
		comment.WriteString(fmt.Sprintf("- `%s`\n", fileName))
	}
	comment.WriteString("\n")
}

// buildSummarySection는 스캔 요약 섹션 생성
func buildSummarySection(comment *strings.Builder, trivySummary, customSummary SeveritySummary) {
	comment.WriteString("---\n")
	comment.WriteString("**[ Scan Summary ]**\n")
	comment.WriteString("```\n")

	// Severity Summary
	totalCritical := customSummary.CRITICAL + trivySummary.CRITICAL
	totalHigh := customSummary.HIGH + trivySummary.HIGH
	totalMedium := customSummary.MEDIUM + trivySummary.MEDIUM
	totalLow := customSummary.LOW + trivySummary.LOW

	comment.WriteString(fmt.Sprintf("Severity Summary:\n- CRITICAL: %d, HIGH: %d, MEDIUM: %d, LOW: %d\n\n",
		totalCritical, totalHigh, totalMedium, totalLow))

	// Policy Summary
	trivyTotal := trivySummary.CRITICAL + trivySummary.HIGH + trivySummary.MEDIUM + trivySummary.LOW
	customTotal := customSummary.CRITICAL + customSummary.HIGH + customSummary.MEDIUM + customSummary.LOW

	comment.WriteString(fmt.Sprintf("Policy Summary:\n- Trivy Built-in Policy: %d, Custom Policy: %d\n\n",
		trivyTotal, customTotal))

	comment.WriteString("```\n\n")
}

// buildViolationsSection는 파일별 위반 정책 목록 섹션 생성
func buildViolationsSection(comment *strings.Builder, sortedFiles []string, fileResults map[string]*FileScanResult) {
	for _, fileName := range sortedFiles {
		result := fileResults[fileName]
		if !result.TrivyPassed || !result.CustomPassed {
			comment.WriteString(fmt.Sprintf("**`%s`:**\n", fileName))
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
}
