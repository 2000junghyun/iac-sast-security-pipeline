package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"trivy-tf-scanner/internal/gitlab"
	"trivy-tf-scanner/internal/scanner"
)

// 파일 경로만 받아서 GitLab에서 다운로드하는 구조체
type PathUploadHandler struct {
	apiSecret    string
	storagePath  string
	gitlabClient *gitlab.Client
	scanner      *scanner.Scanner
}

// 파일 경로만 전송하는 요청 구조체
type PathUploadRequest struct {
	ProjectID    int      `json:"project_id"`
	ProjectPath  string   `json:"project_path"`
	MRIID        int      `json:"mr_iid"`
	SourceBranch string   `json:"source_branch"`
	MRTitle      string   `json:"mr_title"`
	FilePaths    []string `json:"file_paths"`
	IsPublic     bool     `json:"is_public"`
}

func NewPathUploadHandler(apiSecret, storagePath string, gitlabClient *gitlab.Client, scannerInstance *scanner.Scanner) *PathUploadHandler {
	return &PathUploadHandler{
		apiSecret:    apiSecret,
		storagePath:  storagePath,
		gitlabClient: gitlabClient,
		scanner:      scannerInstance,
	}
}

// http.Handler 인터페이스 구현
func (h *PathUploadHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received path upload request from %s", r.RemoteAddr)

	// 1. HTTP 요청 검증 & 파싱
	req, err := h.validateAndParseRequest(r)
	if err != nil {
		h.handleError(w, err)
		return
	}

	// 2. GitLab으로부터 파일 다운로드 & 저장
	successfulFiles, failedFiles := h.downloadAndSaveFiles(req)

	// 3. 취약점 스캔 & MR에 댓글 작성
	if len(successfulFiles) > 0 {
		h.scanAndComment(req, successfulFiles)
	}

	// 4. 불필요 파일 정리
	h.cleanupFiles(req)

	// 5. HTTP 응답 전송
	h.sendResponse(w, req, successfulFiles, failedFiles)
}

func (h *PathUploadHandler) validateAndParseRequest(r *http.Request) (*PathUploadRequest, error) {
	// POST만 허용
	if r.Method != http.MethodPost {
		return nil, fmt.Errorf("method not allowed")
	}

	// API Secret 검증
	receivedSecret := r.Header.Get("X-API-Secret")
	if receivedSecret != h.apiSecret {
		log.Printf("Invalid API secret received")
		return nil, fmt.Errorf("unauthorized")
	}

	// JSON 파싱
	var req PathUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Failed to parse JSON: %v", err)
		return nil, fmt.Errorf("invalid JSON payload")
	}

	// 필수 필드 검증
	if req.ProjectID == 0 || req.MRIID == 0 || len(req.FilePaths) == 0 {
		log.Printf("Missing required fields")
		return nil, fmt.Errorf("missing required fields: project_id, mr_iid, file_paths")
	}

	return &req, nil
}

func (h *PathUploadHandler) downloadAndSaveFiles(req *PathUploadRequest) (successfulFiles []string, failedFiles []string) {
	for _, filePath := range req.FilePaths {
		log.Printf("Processing file: %s", filePath)

		// GitLab에서 파일 다운로드
		content, err := h.gitlabClient.GetFileRaw(req.ProjectPath, filePath, req.SourceBranch)
		if err != nil {
			log.Printf("❌ Failed to download file %s: %v", filePath, err)
			failedFiles = append(failedFiles, filePath)
			continue
		}

		// 파일 저장
		if err := h.saveFile(req.ProjectID, req.MRIID, filePath, content); err != nil {
			log.Printf("❌ Failed to save file %s: %v", filePath, err)
			failedFiles = append(failedFiles, filePath)
			continue
		}

		successfulFiles = append(successfulFiles, filePath)
		log.Printf("✓ Successfully processed: %s (%d bytes)", filePath, len(content))
	}

	log.Printf("Path upload completed: %d/%d files succeeded", len(successfulFiles), len(req.FilePaths))
	return successfulFiles, failedFiles
}

func (h *PathUploadHandler) scanAndComment(req *PathUploadRequest, successfulFiles []string) {
	if h.scanner == nil {
		log.Println("⚠️  Scanner is not available, skipping scan")
		return
	}

	log.Println("Starting Trivy scan...")

	// 스캔 요청 생성
	scanReq := scanner.ScanRequest{
		ProjectID:    req.ProjectID,
		ProjectPath:  req.ProjectPath,
		MRIID:        req.MRIID,
		SourceBranch: req.SourceBranch,
		StoragePath:  h.storagePath,
		FilePaths:    successfulFiles,
	}

	// 스캔 실행
	scanResp, err := h.scanner.Scan(scanReq)
	if err != nil {
		log.Printf("⚠️  Trivy scan failed: %v", err)
		return
	}

	// 댓글 작성
	if scanResp != nil && scanResp.Comment != "" {
		if err := h.gitlabClient.PostMRComment(req.ProjectPath, req.MRIID, scanResp.Comment); err != nil {
			log.Printf("⚠️  Failed to post MR comment: %v", err)
		} else {
			log.Printf("✓ Posted comment to MR #%d", req.MRIID)
		}
	}
}

func (h *PathUploadHandler) cleanupFiles(req *PathUploadRequest) {
	// storage 디렉토리 삭제: storage/{projectID}/mr-{mrIID}
	mrDirPath := filepath.Join(
		h.storagePath,
		fmt.Sprintf("%d", req.ProjectID),
		fmt.Sprintf("mr-%d", req.MRIID),
	)

	if err := os.RemoveAll(mrDirPath); err != nil {
		log.Printf("⚠️  Failed to cleanup MR directory at %s: %v", mrDirPath, err)
	} else {
		log.Printf("✓ Cleaned up MR directory: %s", mrDirPath)
	}

	// 상위 프로젝트 디렉토리 삭제 (비어있을 경우)
	projectDirPath := filepath.Join(h.storagePath, fmt.Sprintf("%d", req.ProjectID))
	if err := os.Remove(projectDirPath); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️  Failed to cleanup project directory at %s: %v (may not be empty)", projectDirPath, err)
		}
	} else {
		log.Printf("✓ Cleaned up project directory: %s", projectDirPath)
	}

	// 원본 스캔 결과 삭제: scan-results/original/{projectName}-{mrIID}.json
	projectName := filepath.Base(req.ProjectPath)
	originalFilePath := filepath.Join(
		"./scan-results",
		"original",
		fmt.Sprintf("%s-%d.json", projectName, req.MRIID),
	)

	if err := os.Remove(originalFilePath); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("⚠️  Failed to cleanup original scan result at %s: %v", originalFilePath, err)
		}
	} else {
		log.Printf("✓ Cleaned up original scan result: %s", originalFilePath)
	}
}

func (h *PathUploadHandler) sendResponse(w http.ResponseWriter, req *PathUploadRequest, successfulFiles, failedFiles []string) {
	w.Header().Set("Content-Type", "application/json")

	// 상태 코드 결정
	statusCode := http.StatusOK
	if len(successfulFiles) == 0 {
		statusCode = http.StatusInternalServerError
	} else if len(failedFiles) > 0 {
		statusCode = http.StatusPartialContent // 206
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "completed",
		"message":       fmt.Sprintf("Processed %d/%d files", len(successfulFiles), len(req.FilePaths)),
		"project_id":    req.ProjectID,
		"mr_iid":        req.MRIID,
		"files_total":   len(req.FilePaths),
		"files_success": len(successfulFiles),
		"files_failed":  len(failedFiles),
		"failed_files":  failedFiles,
	})
}

// 에러를 HTTP 응답으로 변환
func (h *PathUploadHandler) handleError(w http.ResponseWriter, err error) {
	switch err.Error() {
	case "method not allowed":
		http.Error(w, err.Error(), http.StatusMethodNotAllowed)
	case "unauthorized":
		http.Error(w, err.Error(), http.StatusUnauthorized)
	case "invalid JSON payload":
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// 파일을 로컬 저장소에 저장
func (h *PathUploadHandler) saveFile(projectID, mrIID int, filePath string, content []byte) error {
	// 저장 경로 생성: storage/{projectID}/mr-{mrIID}/{filePath}
	savePath := filepath.Join(
		h.storagePath,
		fmt.Sprintf("%d", projectID),
		fmt.Sprintf("mr-%d", mrIID),
		filePath,
	)

	// 디렉토리 생성
	dir := filepath.Dir(savePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 파일 저장
	if err := os.WriteFile(savePath, content, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	log.Printf("Saved: %s", savePath)
	return nil
}