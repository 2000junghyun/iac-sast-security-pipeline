package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ScanResponse는 스캔 처리 결과를 담는 HTTP 응답 구조체
type ScanResponse struct {
	Status       string   `json:"status"`
	Message      string   `json:"message"`
	ProjectID    int      `json:"project_id"`
	MRIID        int      `json:"mr_iid"`
	FilesTotal   int      `json:"files_total"`
	FilesSuccess int      `json:"files_success"`
	FilesFailed  int      `json:"files_failed"`
	FailedFiles  []string `json:"failed_files"`
}

// NewScanResponse는 스캔 결과를 기반으로 응답 객체를 생성
func NewScanResponse(req *ScanRequest, successfulFiles, failedFiles []string) *ScanResponse {
	return &ScanResponse{
		Status:       "completed",
		Message:      fmt.Sprintf("Processed %d/%d files", len(successfulFiles), len(req.FilePaths)),
		ProjectID:    req.ProjectID,
		MRIID:        req.MRIID,
		FilesTotal:   len(req.FilePaths),
		FilesSuccess: len(successfulFiles),
		FilesFailed:  len(failedFiles),
		FailedFiles:  failedFiles,
	}
}

// StatusCode는 응답 상태에 따른 HTTP 상태 코드를 반환
func (r *ScanResponse) StatusCode() int {
	if r.FilesSuccess == 0 {
		return http.StatusInternalServerError
	} else if r.FilesFailed > 0 {
		return http.StatusPartialContent // 206
	}
	return http.StatusOK
}

// WriteTo는 응답을 HTTP ResponseWriter에 작성
func (r *ScanResponse) WriteTo(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.StatusCode())
	return json.NewEncoder(w).Encode(r)
}
