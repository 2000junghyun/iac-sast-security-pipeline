package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// parseScanResultFile은 JSON 파일을 읽어서 스캔 결과를 파싱
func parseScanResultFile(filePath string) (*ScanResultFile, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var result ScanResultFile
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON %s: %w", filePath, err)
	}

	return &result, nil
}

// parseFileName은 JSON 파일명을 파싱하여 정책 타입과 원본 파일명 추출
// "builtin-main.json" → ("builtin", "main.tf")
// "custom-modules%vpc%network.json" → ("custom", "modules/vpc/network.tf")
func parseFileName(fileName string) (policyType string, originalFile string) {
	// 1. 프리픽스 확인 및 제거
	if strings.HasPrefix(fileName, "builtin-") {
		policyType = "builtin"
		fileName = strings.TrimPrefix(fileName, "builtin-")
	} else if strings.HasPrefix(fileName, "custom-") {
		policyType = "custom"
		fileName = strings.TrimPrefix(fileName, "custom-")
	} else {
		// 인식할 수 없는 파일명
		return "", ""
	}

	// 2. .json 확장자 제거
	fileName = strings.TrimSuffix(fileName, ".json")

	// 3. % 를 / 로 복원 (경로 디코딩)
	originalFile = strings.ReplaceAll(fileName, "%", "/")

	// 4. .tf 확장자 추가
	originalFile = originalFile + ".tf"

	return policyType, originalFile
}
