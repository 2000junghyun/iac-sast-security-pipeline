package scanner

import (
	"fmt"
	"os"
	"path/filepath"
)

// ScanPaths는 스캔에 필요한 모든 경로를 담는 구조체
type ScanPaths struct {
	TargetPath       string // storage/12345/mr-42
	OriginalFilePath string // scan-results/original/project-42.json
	ParsedOutputDir  string // scan-results/project/mr-42
	ExcelFilePath    string // scan-results/project/mr-42/project_#42.xlsx
}

// PathManager는 스캔 경로를 관리
type PathManager struct {
	storagePath     string
	scanResultsPath string
}

// NewPathManager는 PathManager 인스턴스를 생성
func NewPathManager(storagePath, scanResultsPath string) *PathManager {
	return &PathManager{
		storagePath:     storagePath,
		scanResultsPath: scanResultsPath,
	}
}

// PrepareScanPaths는 스캔에 필요한 모든 경로를 생성하고 검증
func (pm *PathManager) PrepareScanPaths(req ScanRequest) (*ScanPaths, error) {
	// 1. 스캔 대상 경로 검증: storage/{projectID}/mr-{mrIID}
	targetPath := filepath.Join(
		pm.storagePath,
		fmt.Sprintf("%d", req.ProjectID),
		fmt.Sprintf("mr-%d", req.MRIID),
	)

	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("target path does not exist: %s", targetPath)
	}

	// 2. 원본 결과 저장 경로 생성: scan-results/original/
	originalResultsPath := filepath.Join(pm.scanResultsPath, "original")
	if err := os.MkdirAll(originalResultsPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create original results directory: %w", err)
	}

	// 원본 결과 파일명: {projectName}-{mrIID}.json
	originalFileName := fmt.Sprintf("%s-%d.json",
		filepath.Base(req.ProjectPath),
		req.MRIID)
	originalFilePath := filepath.Join(originalResultsPath, originalFileName)

	// 3. Parsed 스캔 결과 저장 디렉토리: scan-results/{projectName}/mr-{mrIID}/
	parsedOutputDir := filepath.Join(
		pm.scanResultsPath,
		filepath.Base(req.ProjectPath),
		fmt.Sprintf("mr-%d", req.MRIID),
	)

	if err := os.MkdirAll(parsedOutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create parsed output directory: %w", err)
	}

	// 4. Excel 파일 경로: scan-results/{projectName}/mr-{mrIID}/{projectName}_#{mrIID}.xlsx
	projectName := filepath.Base(req.ProjectPath)
	excelFileName := fmt.Sprintf("%s_#%d.xlsx", projectName, req.MRIID)
	excelFilePath := filepath.Join(parsedOutputDir, excelFileName)

	return &ScanPaths{
		TargetPath:       targetPath,
		OriginalFilePath: originalFilePath,
		ParsedOutputDir:  parsedOutputDir,
		ExcelFilePath:    excelFilePath,
	}, nil
}
