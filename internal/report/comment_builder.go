package report

import (
	"log"
)

// CommentBuilder는 스캔 결과를 기반으로 댓글을 생성
type CommentBuilder struct{}

// NewCommentBuilder는 CommentBuilder 인스턴스를 생성
func NewCommentBuilder() *CommentBuilder {
	return &CommentBuilder{}
}

// ScanResult는 스캔 실행 결과를 담는 구조체
type ScanResult struct {
	ParserSuccess      bool
	HasVulnerabilities bool
	ParsedOutputDir    string
}

// BuildComment는 스캔 결과를 기반으로 MR 댓글을 생성
func (cb *CommentBuilder) BuildComment(result ScanResult) string {
	// 파서 실행 실패한 경우
	if !result.ParserSuccess {
		return cb.buildParserFailedComment(result.HasVulnerabilities)
	}

	// 파서 실행 성공한 경우 - formatter.go의 BuildScanComment 호출
	generatedComment, err := BuildScanComment(result.ParsedOutputDir)
	if err != nil {
		log.Printf("⚠️  Failed to build scan comment: %v", err)
		return cb.buildCommentGenerationFailedComment(result.HasVulnerabilities)
	}

	return generatedComment
}

// buildParserFailedComment는 파서 실행 실패 시 댓글 생성
func (cb *CommentBuilder) buildParserFailedComment(hasVulnerabilities bool) string {
	if !hasVulnerabilities {
		return "## 🎉 취약점 스캔 완료\n\n**발견된 보안 문제가 없습니다.** 스캔한 파일들이 모든 보안 정책을 통과했습니다."
	}
	return "파일 스캔이 완료됐습니다.\n\n⚠️ 스캔 결과 파싱에 실패했습니다. 원본 스캔 결과 파일을 확인해주세요."
}

// buildCommentGenerationFailedComment는 댓글 생성 실패 시 댓글 생성
func (cb *CommentBuilder) buildCommentGenerationFailedComment(hasVulnerabilities bool) string {
	if hasVulnerabilities {
		return "파일 스캔이 완료됐습니다.\n\n⚠️ 스캔 결과 요약 생성에 실패했습니다. 상세 결과는 스캔 결과 파일을 확인해주세요."
	}
	return "## 🎉 취약점 스캔 완료\n\n**발견된 보안 문제가 없습니다.** 스캔한 파일들이 모든 보안 정책을 통과했습니다."
}
