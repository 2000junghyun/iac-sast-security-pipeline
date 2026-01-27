# bin/ Directory

이 디렉토리에는 Trivy 스캔에 필요한 실행 파일들을 저장합니다.

## 필요한 파일

- `trivy` - Trivy 보안 스캐너 실행 파일
- `trivy-parser` - Trivy 결과 파싱 도구 실행 파일

## 로컬 개발 환경 설정

### macOS (Apple Silicon - M1/M2/M3)

```bash
# Trivy 다운로드
curl -LO https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_macOS-ARM64.tar.gz
tar -xzf trivy_0.58.1_macOS-ARM64.tar.gz
mv trivy bin/
chmod +x bin/trivy
rm trivy_0.58.1_macOS-ARM64.tar.gz

# trivy-parser 복사 (macOS용 빌드 필요)
cp /path/to/trivy-parser-macos bin/trivy-parser
chmod +x bin/trivy-parser
```

### macOS (Intel)

```bash
# Trivy 다운로드
curl -LO https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_macOS-64bit.tar.gz
tar -xzf trivy_0.58.1_macOS-64bit.tar.gz
mv trivy bin/
chmod +x bin/trivy
rm trivy_0.58.1_macOS-64bit.tar.gz

# trivy-parser 복사 (macOS용 빌드 필요)
cp /path/to/trivy-parser-macos bin/trivy-parser
chmod +x bin/trivy-parser
```

### Linux

```bash
# Trivy 다운로드
wget https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_Linux-64bit.tar.gz
tar -xzf trivy_0.58.1_Linux-64bit.tar.gz
mv trivy bin/
chmod +x bin/trivy
rm trivy_0.58.1_Linux-64bit.tar.gz

# trivy-parser 복사
cp trivy-parser-linux bin/trivy-parser
chmod +x bin/trivy-parser
```

## 검증

```bash
# Trivy 버전 확인
./bin/trivy --version

# trivy-parser 확인
./bin/trivy-parser --help
```

## Docker

Docker 환경에서는 Dockerfile이 자동으로 bin 디렉토리에 실행 파일을 설치합니다.
