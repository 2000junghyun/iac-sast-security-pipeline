package handler

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed swagger/*
var swaggerFS embed.FS

// NewSwaggerHandler는 Swagger UI를 서빙하는 핸들러를 생성
func NewSwaggerHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /swagger 경로 처리
		path := strings.TrimPrefix(r.URL.Path, "/swagger")
		if path == "" || path == "/" {
			path = "/index.html"
		}

		// swagger/ 디렉토리에서 파일 읽기
		content, err := fs.ReadFile(swaggerFS, "swagger"+path)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// Content-Type 설정
		contentType := getContentType(path)
		w.Header().Set("Content-Type", contentType)
		w.Write(content)
	})
}

// getContentType은 파일 확장자에 따라 Content-Type을 반환
func getContentType(path string) string {
	if strings.HasSuffix(path, ".html") {
		return "text/html; charset=utf-8"
	}
	if strings.HasSuffix(path, ".css") {
		return "text/css; charset=utf-8"
	}
	if strings.HasSuffix(path, ".js") {
		return "application/javascript; charset=utf-8"
	}
	if strings.HasSuffix(path, ".json") {
		return "application/json; charset=utf-8"
	}
	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		return "text/yaml; charset=utf-8"
	}
	return "application/octet-stream"
}
