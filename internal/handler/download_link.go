package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/2000junghyun/iac-sast-security-pipeline/internal/gitlab"
)

// DownloadLinkRequest는 다운로드 링크 댓글 작성 요청 구조체
type DownloadLinkRequest struct {
	ProjectPath  string `json:"project_path"`
	MRIID        int    `json:"mr_iid"`
	ArtifactsURL string `json:"artifacts_url"`
	FileName     string `json:"file_name"`
}

// DownloadLinkResponse는 다운로드 링크 댓글 작성 응답 구조체
type DownloadLinkResponse struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	ProjectPath string `json:"project_path"`
	MRIID       int    `json:"mr_iid"`
}

// DownloadLinkHandler는 GitLab MR에 다운로드 링크 댓글을 작성하는 핸들러
type DownloadLinkHandler struct {
	apiSecret    string         // API 인증 Secret
	gitlabClient *gitlab.Client // GitLab API 클라이언트
}

// NewDownloadLinkHandler는 DownloadLinkHandler를 생성
func NewDownloadLinkHandler(apiSecret string, gitlabClient *gitlab.Client) *DownloadLinkHandler {
	return &DownloadLinkHandler{
		apiSecret:    apiSecret,
		gitlabClient: gitlabClient,
	}
}

// http.Handler 인터페이스를 구현
// POST /api/download-link
func (h *DownloadLinkHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received download link request from %s", r.RemoteAddr)

	// 1. HTTP 메서드 검증 (공통)
	if err := ValidateMethod(r, http.MethodPost); err != nil {
		http.Error(w, err.Error(), http.StatusMethodNotAllowed)
		return
	}

	// 2. API Secret 검증 (공통)
	if err := ValidateAPISecret(r, h.apiSecret); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// 3. JSON 파싱 (공통)
	var req DownloadLinkRequest
	if err := ParseJSONRequest(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 4. 비즈니스 검증 (download-link 전용)
	if req.ProjectPath == "" || req.MRIID == 0 || req.ArtifactsURL == "" || req.FileName == "" {
		log.Printf("Missing required fields")
		http.Error(w, "Missing required fields: project_path, mr_iid, artifacts_url, file_name", http.StatusBadRequest)
		return
	}

	log.Printf("Comment Request:")
	log.Printf("  - Project Path: %s", req.ProjectPath)
	log.Printf("  - MR IID: %d", req.MRIID)
	log.Printf("  - Artifacts URL: %s", req.ArtifactsURL)
	log.Printf("  - File Name: %s", req.FileName)

	// 댓글 내용 생성
	comment := fmt.Sprintf(`## 📥 스캔 결과 다운로드

[%s 다운로드](%s)`, req.FileName, req.ArtifactsURL)

	// GitLab MR에 댓글 작성
	if err := h.gitlabClient.PostMRComment(req.ProjectPath, req.MRIID, comment); err != nil {
		log.Printf("Failed to post MR comment: %v", err)
		http.Error(w, "Failed to post comment to GitLab", http.StatusInternalServerError)
		return
	}

	log.Printf("✓ Successfully posted download link comment to MR #%d", req.MRIID)

	// 응답 (타입화된 구조체 사용)
	response := DownloadLinkResponse{
		Status:      "success",
		Message:     "Download link comment posted successfully",
		ProjectPath: req.ProjectPath,
		MRIID:       req.MRIID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
