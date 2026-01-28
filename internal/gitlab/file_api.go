package gitlab

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

// GetFileRaw는 GitLab에서 원본 파일 콘텐츠를 다운로드
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
