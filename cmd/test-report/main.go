package main

import (
	"fmt"
	"os"

	"trivy-tf-scanner/internal/report"
)

func main() {
	// CommentBuilder 인스턴스 생성
	commentBuilder := report.NewCommentBuilder()
	if commentBuilder == nil {
		fmt.Println("❌ CommentBuilder 생성 실패")
		os.Exit(1)
	}
	fmt.Println("\n✅ CommentBuilder 생성 성공")

	// 테스트할 ParsedOutputDir (scanner 테스트 결과 사용)
	parsedDir := "scan-results/test-project/mr-100"

	// 테스트 케이스들
	testCases := []struct {
		name               string
		parserSuccess      bool
		hasVulnerabilities bool
		parsedOutputDir    string
	}{
		{
			name:               "Case 1: Parser 성공 + 취약점 있음",
			parserSuccess:      true,
			hasVulnerabilities: true,
			parsedOutputDir:    parsedDir,
		},
		{
			name:               "Case 2: Parser 성공 + 취약점 없음",
			parserSuccess:      true,
			hasVulnerabilities: false,
			parsedOutputDir:    parsedDir,
		},
		{
			name:               "Case 3: Parser 실패 + 취약점 있음",
			parserSuccess:      false,
			hasVulnerabilities: true,
			parsedOutputDir:    parsedDir,
		},
		{
			name:               "Case 4: Parser 실패 + 취약점 없음",
			parserSuccess:      false,
			hasVulnerabilities: false,
			parsedOutputDir:    parsedDir,
		},
		{
			name:               "Case 5: 잘못된 경로 (Parser 성공)",
			parserSuccess:      true,
			hasVulnerabilities: true,
			parsedOutputDir:    "scan-results/invalid-path",
		},
	}

	// 각 테스트 케이스 실행
	for i, tc := range testCases {
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("%s\n", tc.name)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

		// ScanResult 생성 (ScanHandler.buildScanComment과 동일)
		result := report.ScanResult{
			ParserSuccess:      tc.parserSuccess,
			HasVulnerabilities: tc.hasVulnerabilities,
			ParsedOutputDir:    tc.parsedOutputDir,
		}

		fmt.Printf("입력:\n")
		fmt.Printf("  ParserSuccess:      %v\n", result.ParserSuccess)
		fmt.Printf("  HasVulnerabilities: %v\n", result.HasVulnerabilities)
		fmt.Printf("  ParsedOutputDir:    %s\n\n", result.ParsedOutputDir)

		// 댓글 생성
		comment := commentBuilder.BuildComment(result)

		fmt.Printf("출력:\n")
		fmt.Printf("─────────────────────────────────────────\n")
		fmt.Println(comment)
		fmt.Printf("─────────────────────────────────────────\n")

		if i < len(testCases)-1 {
			fmt.Println()
		}
	}

	fmt.Println("\n✅ 모든 테스트 완료!")
}
