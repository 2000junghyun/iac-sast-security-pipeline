package main

import (
	"fmt"
	"log"
	"os"

	"github.com/2000junghyun/iac-sast-security-pipeline/internal/scanner"
)

func main() {
	// Scanner 인스턴스 생성 및 검증
	scannerInstance := scanner.NewScanner(
		"./bin/trivy",
		"./bin/trivy-parser",
		"./custom-policies",
		"./storage",
		"./scan-results",
	)

	if scannerInstance == nil {
		log.Fatal("❌ Scanner 인스턴스 생성 실패")
	}

	if err := scannerInstance.ValidateSetup(); err != nil {
		log.Fatalf("❌ Scanner 설정 검증 실패: %v", err)
	}
	fmt.Println("✅ Scanner 설정 검증 완료")

	// 테스트 데이터 확인
	testStoragePath := "./storage/12345/mr-100"
	if _, err := os.Stat(testStoragePath); os.IsNotExist(err) {
		log.Fatalf("❌ 테스트 데이터 없음: %s\n   먼저 실행: ./test-scanner.sh", testStoragePath)
	}

	files, err := os.ReadDir(testStoragePath)
	if err != nil {
		log.Fatalf("❌ 테스트 디렉토리 읽기 실패: %v", err)
	}
	fmt.Printf("✅ 테스트 파일 확인: %d개\n", len(files))

	// 스캔 요청 생성 (ScanHandler.executeScan과 동일 구조)
	req := scanner.ScanRequest{
		ProjectID:    12345,
		ProjectPath:  "test-project",
		MRIID:        100,
		SourceBranch: "feature/scanner-test",
		StoragePath:  "./storage",
		FilePaths:    []string{"main.tf", "variables.tf"},
	}

	// 스캔 실행
	fmt.Println("\n🚀 스캔 실행 중...")
	result, err := scannerInstance.Scan(req)
	if err != nil {
		log.Fatalf("❌ 스캔 실패: %v", err)
	}

	// 결과 출력 (ScanResult 구조체와 동일한 순서)
	fmt.Println("\n📊 스캔 결과")
	fmt.Printf("   Success:            %v\n", result.Success)
	fmt.Printf("   ParsedDir:          %s\n", result.ParsedDir)
	fmt.Printf("   OriginalFile:       %s\n", result.OriginalFile)
	fmt.Printf("   HasVulnerabilities: %v\n", result.HasVulnerabilities)
	fmt.Printf("   ParserSuccess:      %v\n", result.ParserSuccess)

	// 파일 검증
	if parsedFiles, err := os.ReadDir(result.ParsedDir); err == nil {
		fmt.Printf("\n✅ 생성된 파일: %d개\n", len(parsedFiles))
		for _, file := range parsedFiles {
			if !file.IsDir() {
				info, _ := file.Info()
				fmt.Printf("   - %s (%.1f KB)\n", file.Name(), float64(info.Size())/1024)
			}
		}
	}

	fmt.Println("\n✅ 테스트 완료!")
}
