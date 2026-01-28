package gitlab

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

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
