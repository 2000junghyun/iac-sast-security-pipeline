package config

import (
	"log"
	"os"
)

// 환경변수에서 로드된 애플리케이션 설정을 담음
type Config struct {
	GitLabURL          string
	GitLabTokens       map[string]string // 프로젝트별 토큰 (project_path -> token)
	WebhookSecret      string
	ServerPort         string
	StoragePath        string
	TrivyBinPath       string // Trivy 바이너리 경로
	ParserBinPath      string // Trivy-parser 바이너리 경로
	CustomPoliciesPath string // Custom policies 디렉토리 경로
	ScanResultsPath    string // 스캔 결과 저장 경로
}

// 환경변수에서 설정을 로드
func Load() *Config {
	cfg := &Config{
		GitLabURL:          getEnv("GITLAB_URL", "https://gitlab.com"),
		GitLabTokens:       parseGitLabTokens(getEnv("GITLAB_TOKENS", "")),
		WebhookSecret:      getEnv("WEBHOOK_SECRET", ""),
		ServerPort:         getEnv("SERVER_PORT", "8080"),
		StoragePath:        getEnv("STORAGE_PATH", "./storage"),
		TrivyBinPath:       getEnv("TRIVY_BIN_PATH", "./bin/trivy"),
		ParserBinPath:      getEnv("PARSER_BIN_PATH", "./bin/trivy-parser"),
		CustomPoliciesPath: getEnv("CUSTOM_POLICIES_PATH", "./custom-policies"),
		ScanResultsPath:    getEnv("SCAN_RESULTS_PATH", "./scan-results"),
	}

	if len(cfg.GitLabTokens) == 0 {
		log.Fatal("GITLAB_TOKENS environment variable is required (format: project_path:token,project_path:token)")
	}

	if cfg.WebhookSecret == "" {
		log.Fatal("WEBHOOK_SECRET environment variable is required")
	}

	log.Printf("Configuration loaded successfully")
	log.Printf("  - GitLab URL: %s", cfg.GitLabURL)
	log.Printf("  - Server Port: %s", cfg.ServerPort)
	log.Printf("  - Storage Path: %s", cfg.StoragePath)
	log.Printf("  - GitLab Project Tokens: %d configured", len(cfg.GitLabTokens))
	log.Printf("  - Webhook Secret: %s", maskToken(cfg.WebhookSecret))

	return cfg
}

// 환경변수를 가져오거나 기본값을 반환
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// GITLAB_TOKENS 환경변수를 파싱 (project_path:token,project_path:token)
func parseGitLabTokens(tokensEnv string) map[string]string {
	tokens := make(map[string]string)

	if tokensEnv == "" {
		return tokens
	}

	// 콤마로 분리
	entries := splitAndTrim(tokensEnv, ",")
	for _, entry := range entries {
		// 콜론으로 분리 (project_path:token)
		parts := splitAndTrim(entry, ":")
		if len(parts) != 2 {
			log.Printf("⚠️  Invalid GITLAB_TOKENS entry (expected 'project_path:token'): %s", entry)
			continue
		}

		projectPath := parts[0]
		token := parts[1]

		if projectPath == "" || token == "" {
			log.Printf("⚠️  Invalid GITLAB_TOKENS entry (empty project_path or token): %s", entry)
			continue
		}

		tokens[projectPath] = token
		log.Printf("  - Registered token for project: %s", projectPath)
	}

	return tokens
}

// 문자열을 구분자로 split하고 trim
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return []string{}
	}

	parts := []string{}
	for _, part := range splitString(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

// 문자열을 구분자로 split (strings.Split 대체)
func splitString(s, sep string) []string {
	result := []string{}
	start := 0

	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

// 문자열 앞뒤 공백 제거 (strings.TrimSpace 대체)
func trimSpace(s string) string {
	start := 0
	end := len(s)

	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}

// 로깅을 위한 민감한 토큰을 마스킹
func maskToken(token string) string {
	if len(token) <= 4 {
		return "****"
	}
	return token[:4] + "************"
}