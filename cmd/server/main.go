package main

import (
	"log"
	"net/http"
	"os"

	"trivy-tf-scanner/internal/gitlab"
	"trivy-tf-scanner/internal/handler"
	"trivy-tf-scanner/internal/scanner"
	"trivy-tf-scanner/internal/config"

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
	log.Printf("Storage path: %s", cfg.StoragePath)
	log.Printf("GitLab URL: %s", cfg.GitLabURL)

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
	var gitlabClient *gitlab.Client
	hasToken := len(cfg.GitLabTokens) > 0

	if hasToken {
		gitlabClient = gitlab.NewClient(cfg.GitLabURL, cfg.GitLabTokens)
		log.Printf("✓ GitLab client initialized with %d project token(s)", len(cfg.GitLabTokens))
	} else {
		log.Println("⚠️  No GitLab tokens configured - some features will be limited")
	}

	// 핸들러 등록
	log.Println()
	log.Println("Registering HTTP handlers...")

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"trivy-tf-scanner"}`))
	})
	log.Println("✓ Health check handler registered: GET /health")

	// Root handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"service":"trivy-tf-scanner","version":"1.0.0","status":"running"}`))
	})
	log.Println("✓ Root handler registered: GET /")

	// Scan 핸들러 (Token 필요)
	if hasToken {
		scanHandler := handler.NewScanHandler(
			cfg.WebhookSecret,
			cfg.StoragePath,
			gitlabClient,
			scannerInstance,
		)
		http.Handle("/api/scan", scanHandler)
		log.Println("✓ Scan handler registered: POST /api/scan")
	} else {
		log.Println("⚠️  Scan handler NOT registered (requires GitLab token)")
	}

	// Scan Results 핸들러
	scanResultsHandler := handler.NewScanResultsHandler(cfg.ScanResultsPath)
	http.Handle("/api/scan-results", scanResultsHandler)
	log.Println("✓ Scan results handler registered: GET /api/scan-results")

	// Download Link 핸들러 (Token 필요)
	if hasToken {
		downloadLinkHandler := handler.NewDownloadLinkHandler(
			cfg.WebhookSecret,
			gitlabClient,
		)
		http.Handle("/api/download-link", downloadLinkHandler)
		log.Println("✓ Download link handler registered: POST /api/download-link")
	} else {
		log.Println("⚠️  Download link handler NOT registered (requires GitLab token)")
	}

	// 서버 시작
	log.Println()
	port := ":" + cfg.ServerPort
	log.Printf("🌐 Server listening on %s", port)
	log.Println("---")
	log.Println("Available endpoints:")
	log.Println("  GET  /               - Service info")
	log.Println("  GET  /health         - Health check")
	if hasToken {
		log.Println("  POST /api/scan         - Security scan")
	}
	log.Println("  GET  /api/scan-results - Download scan results (Excel)")
	if hasToken {
		log.Println("  POST /api/download-link - Post download link comment")
	}
	log.Println("---")
	log.Println()

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}