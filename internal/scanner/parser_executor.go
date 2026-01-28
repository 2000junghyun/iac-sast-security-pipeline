package scanner

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

// ParserExecutor는 trivy-parser를 실행
type ParserExecutor struct {
	parserPath string
}

// NewParserExecutor는 ParserExecutor 인스턴스를 생성
func NewParserExecutor(parserPath string) *ParserExecutor {
	return &ParserExecutor{parserPath: parserPath}
}

// SplitResults는 원본 JSON을 파일별로 분리
func (pe *ParserExecutor) SplitResults(inputPath, outputDir string) error {
	// ./trivy-parser -input result-raw.json -output results/ -preprocess -pretty
	parserArgs := []string{
		"-input", inputPath,
		"-output", outputDir + "/",
		"-preprocess",
		"-pretty",
	}

	log.Printf("Executing trivy-parser for splitting: %s %v", pe.parserPath, parserArgs)

	parserCmd := exec.Command(pe.parserPath, parserArgs...)
	parserCmd.Stdout = os.Stdout
	parserCmd.Stderr = os.Stderr

	if err := parserCmd.Run(); err != nil {
		return fmt.Errorf("trivy-parser splitting failed: %w", err)
	}

	log.Printf("✓ trivy-parser completed successfully")
	log.Printf("✓ Parsed results saved to: %s", outputDir)
	return nil
}

// GenerateExcel은 Excel 파일을 생성
func (pe *ParserExecutor) GenerateExcel(inputPath, outputPath string) error {
	// ./trivy-parser -input result-raw.json -output <프로젝트명>_#<MR번호>.xlsx -excel
	excelArgs := []string{
		"-input", inputPath,
		"-output", outputPath,
		"-excel",
	}

	log.Printf("Executing trivy-parser for Excel generation: %s %v", pe.parserPath, excelArgs)

	excelCmd := exec.Command(pe.parserPath, excelArgs...)
	excelCmd.Stdout = os.Stdout
	excelCmd.Stderr = os.Stderr

	if err := excelCmd.Run(); err != nil {
		return fmt.Errorf("trivy-parser Excel generation failed: %w", err)
	}

	log.Printf("✓ Excel file saved to: %s", outputPath)
	return nil
}

// Validate는 trivy-parser 실행 파일이 존재하는지 확인
func (pe *ParserExecutor) Validate() error {
	// trivy-parser 실행 파일 확인
	if _, err := os.Stat(pe.parserPath); os.IsNotExist(err) {
		return fmt.Errorf("trivy-parser executable not found at: %s", pe.parserPath)
	}

	log.Printf("✓ Parser executor validated successfully")
	return nil
}
