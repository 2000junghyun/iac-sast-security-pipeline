package gitlab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"
)

// GitLab API 통신을 처리
type Client struct {
	baseURL    string
	tokens     map[string]string // 프로젝트별 토큰 (project_path -> token)
	httpClient *http.Client
}

// 새로운 GitLab API 클라이언트를 생성
func NewClient(baseURL string, projectTokens map[string]string) *Client {
	return &Client{
		baseURL: baseURL,
		tokens:  projectTokens,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// 프로젝트에 맞는 토큰을 반환 (매핑이 없으면 에러)
func (c *Client) getTokenForProject(projectPath string) (string, error) {
	if token, exists := c.tokens[projectPath]; exists {
		log.Printf("Using configured token for project: %s", projectPath)
		return token, nil
	}
	return "", fmt.Errorf("no token configured for project: %s", projectPath)
}

// GitLab에서 원본 파일 콘텐츠를 다운로드
func (c *Client) GetFileRaw(projectPath, filePath, ref string) ([]byte, error) {
	encodedProjectPath := url.PathEscape(projectPath)
	encodedFilePath := url.PathEscape(filePath)

	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/repository/files/%s/raw?ref=%s",
		c.baseURL,
		encodedProjectPath,
		encodedFilePath,
		url.QueryEscape(ref),
	)

	log.Printf("Downloading file via API: %s (ref: %s)", filePath, ref)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// 프로젝트에 맞는 토큰 선택
	token, err := c.getTokenForProject(projectPath)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("authentication failed - private repository requires token")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to download file (status %d): %s", resp.StatusCode, string(body))
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("Successfully downloaded raw file: %s (%d bytes)", filePath, len(content))

	return content, nil
}

// PostMRComment는 MR에 댓글을 작성
func (c *Client) PostMRComment(projectPath string, mrIID int, comment string) error {
	encodedProjectPath := url.PathEscape(projectPath)

	apiURL := fmt.Sprintf("%s/api/v4/projects/%s/merge_requests/%d/notes",
		c.baseURL,
		encodedProjectPath,
		mrIID,
	)

	log.Printf("Posting comment to MR #%d", mrIID)

	payload := map[string]string{
		"body": comment,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// 프로젝트에 맞는 토큰 선택
	token, err := c.getTokenForProject(projectPath)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to post comment (status %d): %s", resp.StatusCode, string(body))
	}

	log.Printf("Successfully posted comment to MR #%d", mrIID)
	return nil
}