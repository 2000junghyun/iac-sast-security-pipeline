package main

import (
	"log"
	"net/http"
	"os"

	"github.com/2000junghyun/iac-sast-security-pipeline/internal/config"
	"github.com/2000junghyun/iac-sast-security-pipeline/internal/gitlab"
	"github.com/2000junghyun/iac-sast-security-pipeline/internal/handler"
	"github.com/2000junghyun/iac-sast-security-pipeline/internal/scanner"

	"github.com/joho/godotenv"
)

func main() {
	// .env 파일 로드 (선택적)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// 설정 로드
	cfg := config.Load()

	log.Println("🚀 Starting trivy-tf-scanner server...")

	// Storage 디렉토리 생성
	if err := os.MkdirAll(cfg.StoragePath, 0755); err != nil {
		log.Fatalf("Failed to create storage directory: %v", err)
	}

	// Trivy Scanner 초기화
	scannerInstance := scanner.NewScanner(
		cfg.TrivyBinPath,
		cfg.ParserBinPath,
		cfg.CustomPoliciesPath,
		cfg.StoragePath,
		cfg.ScanResultsPath,
	)

	// Scanner 설정 검증
	if err := scannerInstance.ValidateSetup(); err != nil {
		log.Printf("⚠️  Trivy scanner validation failed: %v", err)
		log.Println("⚠️  Scanner will be disabled - file scanning will be skipped")
		scannerInstance = nil
	}

	// GitLab 클라이언트 생성
	gitlabClient := gitlab.NewClient(cfg.GitLabURL, cfg.GitLabTokens)
	log.Printf("✓ GitLab client initialized with %d project token(s)", len(cfg.GitLabTokens))

	// 핸들러 등록
	registerHandlers(cfg, gitlabClient, scannerInstance)

	// 서버 시작
	port := ":" + cfg.ServerPort
	log.Printf("🌐 Server listening on %s", port)
	logEndpoints()

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// registerHandlers는 모든 HTTP 핸들러를 등록
func registerHandlers(cfg *config.Config, gitlabClient *gitlab.Client, scannerInstance *scanner.Scanner) {
	log.Println()
	log.Println("Registering HTTP handlers...")

	// Health check
	http.HandleFunc("/health", healthCheckHandler)
	log.Println("✓ Health check handler registered: GET /health")

	// Root handler
	http.HandleFunc("/", rootHandler)
	log.Println("✓ Root handler registered: GET /")

	// Scan 핸들러
	scanHandler := handler.NewScanHandler(
		cfg.WebhookSecret,
		cfg.StoragePath,
		gitlabClient,
		scannerInstance,
	)
	http.Handle("/api/scan", scanHandler)
	log.Println("✓ Scan handler registered: POST /api/scan")

	// Scan Results 핸들러
	scanResultsHandler := handler.NewScanResultsHandler(cfg.ScanResultsPath)
	http.Handle("/api/scan-results", scanResultsHandler)
	log.Println("✓ Scan results handler registered: GET /api/scan-results")

	// Download Link 핸들러
	downloadLinkHandler := handler.NewDownloadLinkHandler(
		cfg.WebhookSecret,
		gitlabClient,
	)
	http.Handle("/api/download-link", downloadLinkHandler)
	log.Println("✓ Download link handler registered: POST /api/download-link")
	log.Println()
}

// healthCheckHandler는 헬스 체크 엔드포인트 핸들러
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy","service":"trivy-tf-scanner"}`))
}

// rootHandler는 루트 엔드포인트 핸들러
func rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"service":"trivy-tf-scanner","version":"1.0.0","status":"running"}`))
}

// logEndpoints는 사용 가능한 엔드포인트를 로그로 출력
func logEndpoints() {
	log.Println("---")
	log.Println("Available endpoints:")
	log.Println("  GET  /                  - Service info")
	log.Println("  GET  /health            - Health check")
	log.Println("  POST /api/scan          - Security scan")
	log.Println("  GET  /api/scan-results  - Download scan results (Excel)")
	log.Println("  POST /api/download-link - Post download link comment")
	log.Println("---")
	log.Println()
}
