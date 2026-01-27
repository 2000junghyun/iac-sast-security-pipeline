package handler

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

// 스캔 결과를 다운로드하는 핸들러
type DownloadResultsHandler struct {
	scanResultsPath string
}

// DownloadResultsHandler를 생성
func NewDownloadResultsHandler(scanResultsPath string) *DownloadResultsHandler {
	return &DownloadResultsHandler{
		scanResultsPath: scanResultsPath,
	}
}

// http.Handler 인터페이스를 구현
// GET/HEAD /api/scan-results?project=<project-name>&mr=<mr-iid>
func (h *DownloadResultsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received scan results request (%s) from %s", r.Method, r.RemoteAddr)

	// GET, HEAD 허용
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Query 파라미터 추출
	projectName := r.URL.Query().Get("project")
	mrIID := r.URL.Query().Get("mr")

	if projectName == "" || mrIID == "" {
		log.Printf("Missing required parameters: project=%s, mr=%s", projectName, mrIID)
		http.Error(w, "Missing required parameters: project and mr", http.StatusBadRequest)
		return
	}

	log.Printf("Download request: project=%s, mr=%s", projectName, mrIID)

	// Excel 파일 경로: scan-results/{project}/mr-{iid}/{project}_#{mr}.xlsx
	excelFileName := fmt.Sprintf("%s_#%s.xlsx", projectName, mrIID)
	excelFilePath := filepath.Join(h.scanResultsPath, projectName, fmt.Sprintf("mr-%s", mrIID), excelFileName)

	// 파일 존재 확인
	if _, err := os.Stat(excelFilePath); os.IsNotExist(err) {
		log.Printf("Excel file not found: %s", excelFilePath)
		http.Error(w, "Excel file not found", http.StatusNotFound)
		return
	}

	log.Printf("Excel file found: %s", excelFilePath)

	// HEAD 요청인 경우 헤더만 반환 (파일 존재 확인용)
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.WriteHeader(http.StatusOK)
		log.Printf("✓ HEAD request: Excel file exists")
		return
	}

	// GET 요청인 경우 Excel 파일 전송
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", excelFileName))

	http.ServeFile(w, r, excelFilePath)

	log.Printf("✓ Successfully sent Excel file: %s", excelFilePath)
}