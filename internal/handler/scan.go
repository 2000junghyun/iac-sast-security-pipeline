package handler

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"trivy-tf-scanner/internal/gitlab"
	"trivy-tf-scanner/internal/report"
	"trivy-tf-scanner/internal/scanner"
)

// ScanRequest는 스캔 요청 구조체
type ScanRequest struct {
	ProjectID    int      `json:"project_id"`
	ProjectPath  string   `json:"project_path"`
	MRIID        int      `json:"mr_iid"`
	SourceBranch string   `json:"source_branch"`
	MRTitle      string   `json:"mr_title"`
	FilePaths    []string `json:"file_paths"`
	IsPublic     bool     `json:"is_public"`
}

// DownloadResult는 파일 다운로드 결과를 담는 구조체
type DownloadResult struct {
	SuccessfulFiles []string
	FailedFiles     []string
}

// ScanHandler는 보안 스캔 워크플로우를 처리하는 HTTP 핸들러
type ScanHandler struct {
	apiSecret      string
	storagePath    string
	gitlabClient   *gitlab.Client
	scanner        *scanner.Scanner
	commentBuilder *report.CommentBuilder
}

func NewScanHandler(apiSecret, storagePath string, gitlabClient *gitlab.Client, scannerInstance *scanner.Scanner) *ScanHandler {
	return &ScanHandler{
		apiSecret:      apiSecret,
		storagePath:    storagePath,
		gitlabClient:   gitlabClient,
		scanner:        scannerInstance,
		commentBuilder: report.NewCommentBuilder(),
	}
}

// http.Handler 인터페이스 구현
func (h *ScanHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received scan request from %s", r.RemoteAddr)

	// 1. HTTP 요청 검증 & 파싱
	req, err := h.validateAndParseRequest(r)
	if err != nil {
		h.handleError(w, err)
		return
	}

	// 2. GitLab으로부터 파일 다운로드 & 저장
	downloadResult := h.downloadAndSaveFiles(req)

	// 3. 취약점 스캔 실행
	var scanResult *scanner.ScanResult
	if len(downloadResult.SuccessfulFiles) > 0 {
		scanResult = h.executeScan(req, downloadResult.SuccessfulFiles)
	}

	// 4. MR에 스캔 결과 댓글 작성 + 스캔 실패 시 알림 댓글 작성
	if scanResult != nil {
		comment := h.buildScanComment(scanResult)
		h.postScanComment(req, comment)
	} else if len(downloadResult.SuccessfulFiles) > 0 {
		h.postScanComment(req, "⚠️ 보안 스캔에 실패했습니다. 관리자에게 문의해주세요.")
	}

	// 5. 불필요 파일 정리
	h.cleanupFiles(req)

	// 6. HTTP 응답 전송
	h.sendResponse(w, req, downloadResult.SuccessfulFiles, downloadResult.FailedFiles)
}

// validateAndParseRequest는 HTTP 요청을 검증하고 파싱
func (h *ScanHandler) validateAndParseRequest(r *http.Request) (*ScanRequest, error) {
	// HTTP 메서드 검증 (공통)
	if err := ValidateMethod(r, http.MethodPost); err != nil {
		return nil, err
	}

	// API Secret 검증 (공통)
	if err := ValidateAPISecret(r, h.apiSecret); err != nil {
		return nil, err
	}

	// JSON 파싱 (공통)
	var req ScanRequest
	if err := ParseJSONRequest(r, &req); err != nil {
		return nil, err
	}

	// 비즈니스 검증 (scan.go 전용)
	if req.ProjectID == 0 || req.MRIID == 0 || len(req.FilePaths) == 0 {
		log.Printf("Missing required fields")
		return nil, fmt.Errorf("missing required fields: project_id, mr_iid, file_paths")
	}

	return &req, nil
}

// downloadAndSaveFiles는 GitLab에서 파일을 다운로드하고 로컬에 저장
func (h *ScanHandler) downloadAndSaveFiles(req *ScanRequest) *DownloadResult {
	result := &DownloadResult{
		SuccessfulFiles: []string{},
		FailedFiles:     []string{},
	}

	for _, filePath := range req.FilePaths {
		log.Printf("Processing file: %s", filePath)

		// GitLab에서 파일 다운로드
		content, err := h.gitlabClient.GetFileRaw(req.ProjectPath, filePath, req.SourceBranch)
		if err != nil {
			log.Printf("❌ Failed to download file %s: %v", filePath, err)
			result.FailedFiles = append(result.FailedFiles, filePath)
			continue
		}

		// 파일 저장
		if err := h.saveFile(req.ProjectID, req.MRIID, filePath, content); err != nil {
			log.Printf("❌ Failed to save file %s: %v", filePath, err)
			result.FailedFiles = append(result.FailedFiles, filePath)
			continue
		}

		result.SuccessfulFiles = append(result.SuccessfulFiles, filePath)
		log.Printf("✓ Successfully processed: %s (%d bytes)", filePath, len(content))
	}

	log.Printf("Path upload completed: %d/%d files succeeded",
		len(result.SuccessfulFiles), len(req.FilePaths))

	return result
}

// saveFile은 파일을 로컬 저장소에 저장
func (h *ScanHandler) saveFile(projectID, mrIID int, filePath string, content []byte) error {
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

// executeScan은 스캔 요청을 생성하고 Trivy 스캔을 실행
func (h *ScanHandler) executeScan(req *ScanRequest, successfulFiles []string) *scanner.ScanResult {
	if h.scanner == nil {
		log.Println("⚠️  Scanner is not available, skipping scan")
		return nil
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
	scanResult, err := h.scanner.Scan(scanReq)
	if err != nil {
		log.Printf("⚠️  Trivy scan failed: %v", err)
		return nil
	}

	log.Printf("✓ Scan completed successfully")
	return scanResult
}

// buildScanComment는 스캔 결과를 기반으로 댓글을 생성
func (h *ScanHandler) buildScanComment(scanResult *scanner.ScanResult) string {
	return h.commentBuilder.BuildComment(report.ScanResult{
		ParserSuccess:      scanResult.ParserSuccess,
		HasVulnerabilities: scanResult.HasVulnerabilities,
		ParsedOutputDir:    scanResult.ParsedDir,
	})
}

// postScanComment는 스캔 결과를 MR 댓글로 작성
func (h *ScanHandler) postScanComment(req *ScanRequest, comment string) {
	if comment == "" {
		log.Println("⚠️  No comment to post (empty comment)")
		return
	}

	if err := h.gitlabClient.PostMRComment(req.ProjectPath, req.MRIID, comment); err != nil {
		log.Printf("⚠️  Failed to post MR comment: %v", err)
		return
	}

	log.Printf("✓ Posted comment to MR #%d", req.MRIID)
}

func (h *ScanHandler) cleanupFiles(req *ScanRequest) {
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
}

func (h *ScanHandler) sendResponse(w http.ResponseWriter, req *ScanRequest, successfulFiles, failedFiles []string) {
	response := NewScanResponse(req, successfulFiles, failedFiles)
	if err := response.WriteTo(w); err != nil {
		log.Printf("⚠️  Failed to write response: %v", err)
	}
}

// 에러를 HTTP 응답으로 변환
func (h *ScanHandler) handleError(w http.ResponseWriter, err error) {
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
