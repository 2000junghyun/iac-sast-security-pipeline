# bin 디렉토리 사용 가이드

## 📂 변경된 디렉토리 구조

```
iac-sast-security-pipeline/
├── bin/                           ← 실행 파일 저장 (새로 추가)
│   ├── trivy                      ← Trivy 실행 파일
│   ├── trivy-parser               ← trivy-parser 실행 파일
│   └── README.md                  ← bin 디렉토리 가이드
├── scripts/                       ← 설치 스크립트 (새로 추가)
│   └── setup-bin.sh               ← 자동 설치 스크립트
├── custom-policies/
├── storage/
├── scan-results/
├── cmd/
├── internal/
├── pkg/
└── .gitignore                     ← bin/ 실행 파일 제외
```

## 🔧 수정된 파일

### 1. **cmd/server/main.go**

실행 파일 경로를 `bin/` 디렉토리로 변경:

```go
// 변경 전
scannerInstance := scanner.NewScanner(
    "./trivy",           
    "./trivy-parser",    
    "./custom-policies",
    "./scan-results",
)

// 변경 후
scannerInstance := scanner.NewScanner(
    "./bin/trivy",           // ✅ bin 디렉토리 사용
    "./bin/trivy-parser",    // ✅ bin 디렉토리 사용
    "./custom-policies",
    "./scan-results",
)
```

### 2. **Dockerfile**

Docker 이미지 빌드 시 `bin/` 디렉토리 사용:

```dockerfile
# 변경 전
RUN ... && mv trivy /app/trivy && chmod +x /app/trivy
COPY trivy-parser-linux ./trivy-parser

# 변경 후
RUN mkdir -p /app/bin
RUN ... && mv trivy /app/bin/trivy && chmod +x /app/bin/trivy
COPY trivy-parser-linux ./bin/trivy-parser
RUN chmod +x /app/bin/trivy-parser
```

### 3. **.gitignore (신규)**

실행 파일을 Git에서 제외:

```gitignore
# Binaries
bin/trivy
bin/trivy-parser
bin/trivy-*
bin/*.exe

# Runtime directories
storage/
scan-results/

# Environment files
.env
```

## 🚀 로컬 개발 환경 설정

### 방법 1: 자동 설치 스크립트 사용 (권장)

```bash
# 프로젝트 루트에서 실행
./scripts/setup-bin.sh
```

스크립트가 자동으로:
- OS와 아키텍처 감지 (macOS/Linux, Intel/ARM)
- 적절한 Trivy 버전 다운로드
- `bin/` 디렉토리에 설치

### 방법 2: 수동 설치

#### macOS (Apple Silicon - M1/M2/M3)

```bash
# bin 디렉토리 생성
mkdir -p bin

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

#### macOS (Intel)

```bash
# bin 디렉토리 생성
mkdir -p bin

# Trivy 다운로드
curl -LO https://github.com/aquasecurity/trivy/releases/download/v0.58.1/trivy_0.58.1_macOS-64bit.tar.gz
tar -xzf trivy_0.58.1_macOS-64bit.tar.gz
mv trivy bin/
chmod +x bin/trivy
rm trivy_0.58.1_macOS-64bit.tar.gz

# trivy-parser 복사
cp /path/to/trivy-parser-macos bin/trivy-parser
chmod +x bin/trivy-parser
```

#### Linux

```bash
# bin 디렉토리 생성
mkdir -p bin

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

## ✅ 설치 확인

```bash
# Trivy 버전 확인
./bin/trivy --version

# trivy-parser 확인
./bin/trivy-parser --help  # 또는 -version

# bin 디렉토리 구조 확인
ls -lh bin/
```

예상 출력:
```
total 150M
-rwxr-xr-x  1 user  staff   75M  Jan 27 10:00 trivy
-rwxr-xr-x  1 user  staff   12M  Jan 27 10:01 trivy-parser
-rw-r--r--  1 user  staff  2.1K  Jan 27 10:00 README.md
```

## 🐳 Docker 환경

Docker 환경에서는 추가 작업이 필요 없습니다:

```bash
# Docker 이미지 빌드
docker-compose build

# 컨테이너 실행
docker-compose up -d
```

Dockerfile이 자동으로 `bin/` 디렉토리에 필요한 파일들을 설치합니다.

## 🔄 기존 프로젝트에서 마이그레이션

기존에 루트 디렉토리에 실행 파일이 있었다면:

```bash
# bin 디렉토리 생성
mkdir -p bin

# 기존 파일 이동
mv trivy bin/ 2>/dev/null || true
mv trivy-parser bin/ 2>/dev/null || true

# 권한 확인
chmod +x bin/trivy bin/trivy-parser 2>/dev/null || true
```

## 📋 장점

### 1. **명확한 구조**
   - 실행 파일과 소스 코드 분리
   - 프로젝트 루트 디렉토리 정리

### 2. **Git 관리 용이**
   - `.gitignore`로 바이너리 자동 제외
   - 클린한 저장소 유지

### 3. **표준 관례**
   - Unix/Linux 표준 디렉토리 구조 (`/usr/local/bin` 등)
   - Go 프로젝트에서도 일반적으로 사용

### 4. **멀티 플랫폼 지원**
   - 플랫폼별 바이너리 쉽게 관리
   - 개발/운영 환경 일관성 유지

## ⚠️ 주의사항

1. **trivy-parser**는 별도 설치 필요
   - Trivy는 공식 릴리스에서 다운로드 가능
   - trivy-parser는 프로젝트에서 직접 제공하거나 빌드 필요

2. **실행 권한**
   - 다운로드 후 반드시 `chmod +x` 실행
   - 스크립트 사용 시 자동 설정됨

3. **.gitignore 확인**
   - 실행 파일이 Git에 커밋되지 않도록 주의
   - 이미 커밋된 경우 `git rm --cached` 사용

## 🆘 문제 해결

### "trivy executable not found" 오류

```bash
# bin 디렉토리 확인
ls -la bin/

# trivy가 없다면 다시 설치
./scripts/setup-bin.sh
```

### 권한 오류

```bash
# 실행 권한 부여
chmod +x bin/trivy bin/trivy-parser
```

### Docker에서 실행 안됨

```bash
# 이미지 재빌드
docker-compose build --no-cache

# 컨테이너 로그 확인
docker-compose logs
```
