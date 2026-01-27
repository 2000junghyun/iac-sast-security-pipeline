package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"trivy-tf-scanner/internal/gitlab"
)

// Excel 다운로드 링크를 MR에 댓글로 작성하는 핸들러
type PostURLHandler struct {
	apiSecret    string         // API 인증 Secret
	gitlabClient *gitlab.Client // GitLab API 클라이언트
}

// 다운로드 URL 댓글 작성 요청 구조체
type PostURLRequest struct {
	ProjectPath  string `json:"project_path"`
	MRIID        int    `json:"mr_iid"`
	ArtifactsURL string `json:"artifacts_url"`
	FileName     string `json:"file_name"`
}

// Post URL 핸들러를 생성
func NewPostURLHandler(apiSecret string, gitlabClient *gitlab.Client) *PostURLHandler {
	return &PostURLHandler{
		apiSecret:    apiSecret,
		gitlabClient: gitlabClient,
	}
}

// http.Handler 인터페이스를 구현
// POST /api/post-comment
func (h *PostURLHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received post URL comment request from %s", r.RemoteAddr)

	// POST만 허용
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// API Secret 검증
	receivedSecret := r.Header.Get("X-API-Secret")
	if receivedSecret != h.apiSecret {
		log.Printf("Invalid API secret received")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// JSON 파싱
	var req PostURLRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to parse JSON: %v", err)
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// 필수 필드 검증
	if req.ProjectPath == "" || req.MRIID == 0 || req.ArtifactsURL == "" || req.FileName == "" {
		log.Printf("Missing required fields")
		http.Error(w, "Missing required fields: project_path, mr_iid, artifacts_url, file_name", http.StatusBadRequest)
		return
	}

	log.Printf("Post URL Comment Request:")
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

	// 응답
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "success",
		"message":      "Comment posted successfully",
		"project_path": req.ProjectPath,
		"mr_iid":       req.MRIID,
	})
}