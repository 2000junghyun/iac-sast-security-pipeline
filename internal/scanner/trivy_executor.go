package scanner

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

// TrivyExecutor는 Trivy 스캔을 실행
type TrivyExecutor struct {
	trivyPath      string
	customPolicies string
}

// NewTrivyExecutor는 TrivyExecutor 인스턴스를 생성
func NewTrivyExecutor(trivyPath, customPolicies string) *TrivyExecutor {
	return &TrivyExecutor{
		trivyPath:      trivyPath,
		customPolicies: customPolicies,
	}
}

// ExecuteScan은 Trivy config 스캔을 실행
func (te *TrivyExecutor) ExecuteScan(targetPath, outputPath string) error {
	// ./trivy config --config-check ./custom-policies --check-namespaces user \
	//   --format json -o ./scan-results/original/{project-MR}.json ./storage/{project}/{MR}
	trivyArgs := []string{
		"config",
		"--config-check", te.customPolicies,
		"--check-namespaces", "user",
		"--format", "json",
		"-o", outputPath,
		targetPath,
	}

	trivyCmd := exec.Command(te.trivyPath, trivyArgs...)
	trivyCmd.Stdout = os.Stdout
	trivyCmd.Stderr = os.Stderr

	if err := trivyCmd.Run(); err != nil {
		return fmt.Errorf("trivy scan failed: %w", err)
	}

	log.Printf("✓ Trivy scan completed successfully")
	log.Printf("✓ Original scan results saved to: %s", outputPath)
	return nil
}

// Validate는 Trivy 실행 파일과 커스텀 정책 디렉토리가 존재하는지 확인
func (te *TrivyExecutor) Validate() error {
	// Trivy 실행 파일 확인
	if _, err := os.Stat(te.trivyPath); os.IsNotExist(err) {
		return fmt.Errorf("trivy executable not found at: %s", te.trivyPath)
	}

	// Custom policies 디렉토리 확인
	if _, err := os.Stat(te.customPolicies); os.IsNotExist(err) {
		return fmt.Errorf("custom policies directory not found at: %s", te.customPolicies)
	}

	log.Printf("✓ Trivy executor validated successfully")
	return nil
}
