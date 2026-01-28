package gitlab

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// Client는 GitLab API 통신을 처리
type Client struct {
	baseURL    string
	tokens     map[string]string // 프로젝트별 토큰 (project_path -> token)
	httpClient *http.Client
}

// NewClient는 새로운 GitLab API 클라이언트를 생성
func NewClient(baseURL string, projectTokens map[string]string) *Client {
	return &Client{
		baseURL: baseURL,
		tokens:  projectTokens,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// getTokenForProject는 프로젝트에 맞는 토큰을 반환 (매핑이 없으면 에러)
func (c *Client) getTokenForProject(projectPath string) (string, error) {
	if token, exists := c.tokens[projectPath]; exists {
		log.Printf("Using configured token for project: %s", projectPath)
		return token, nil
	}
	return "", fmt.Errorf("no token configured for project: %s", projectPath)
}