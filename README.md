# IaC SAST Security Pipeline

## 개요

IaC SAST 보안 파이프라인은 **GitLab과 연동되는 보안 스캐닝 서비스**로,
Merge Request에서 변경된 Terraform 코드를 자동으로 분석합니다.

GitLab API를 통해 변경된 `.tf` 파일만 다운로드하고, Trivy로 스캔한 뒤
보안 결과를 Merge Request에 직접 코멘트로 등록합니다.

<br>

**주요 기능**:

- **자동 파일 수집**: GitLab MR에서 변경된 Terraform 파일만 다운로드
- **보안 스캔**: Trivy를 사용한 IaC 보안 설정 점검
- **결과 처리**: trivy-parser를 이용한 파일 단위 결과 분리
- **GitLab 연동**: 스캔 결과를 MR 코멘트로 자동 등록
- **엑셀 리포트 생성**: 스캔 결과를 다운로드 가능한 Excel 파일로 제공

<br>

**파이프라인 실행 영상**:

https://github.com/user-attachments/assets/bba7d94d-bee4-475c-8311-f9ddef5a6a16

<br>

## 기술 스택

- **언어**: Go 1.21+
- **스캐너**: Trivy v0.58.1 (Misconfiguration 스캔)
- **파서**: trivy-parser (커스텀 결과 처리기)
  - `https://github.com/2000junghyun/trivy-parser`
- **라이브러리**
  - `github.com/joho/godotenv` – 환경 변수 관리
  - `github.com/xuri/excelize/v2` – Excel 파일 생성
- **실행 환경**: 단일 바이너리 HTTP 서버, Docker 실행 가능

<br>

## API 문서

Swagger UI를 통해 **대화형 API 문서**를 확인 가능

- **Local**: http://localhost:8080/swagger/
- **Docker**: http://iac-scanner:8080/swagger/

OpenAPI 명세 파일은 `docs/openapi.yaml`에서 확인 가능

### 제공 API 목록

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/` | Service information | No |
| GET | `/health` | Health check | No |
| GET | `/swagger/` | API Documentation (Swagger UI) | No |
| POST | `/api/scan` | Trigger security scan | Yes (X-API-Secret) |
| GET | `/api/scan-results` | Download Excel report | No |
| POST | `/api/download-link` | Post MR comment with download link | Yes (X-API-Secret) |


### Swagger UI 사용 방법

1. [http://localhost:8080/swagger/](http://localhost:8080/swagger/) 접속
2. 우측 상단 **Authorize** 클릭
3. `.env`의 `WEBHOOK_SECRET` 값을 입력
4. 브라우저에서 직접 API 테스트 가능

<br>

## 디렉터리 구조

```
.
├── cmd/
│   ├── server/
│   │   └── main.go                    # HTTP 서버 엔트리포인트
│   ├── test-scanner/
│   │   └── main.go                    # 스캐너 통합 테스트
│   └── test-report/
│       └── main.go                    # 리포트 생성 테스트
│
├── internal/
│   ├── config/
│   │   └── config.go                  # 환경 변수 기반 설정
│   │
│   ├── gitlab/
│   │   ├── client.go                  # GitLab API 클라이언트
│   │   ├── file_api.go                # 파일 다운로드 처리
│   │   └── comment_api.go             # MR 코멘트 처리
│   │
│   ├── handler/
│   │   ├── scan.go                    # POST /api/scan
│   │   ├── results.go                 # GET /api/scan-results
│   │   ├── download_link.go           # POST /api/download-link
│   │   ├── middleware.go              # 인증 미들웨어
│   │   └── response.go                # HTTP 응답 헬퍼
│   │
│   ├── scanner/
│   │   ├── scanner.go                 # 스캔 전체 흐름 제어
│   │   ├── trivy_executor.go          # Trivy 실행
│   │   ├── parser_executor.go         # trivy-parser 실행
│   │   └── path_manager.go            # 파일 경로 관리
│   │
│   └── report/
│       ├── comment_builder.go         # MR 코멘트 생성
│       ├── markdown_builder.go        # Markdown 포맷팅
│       ├── parser.go                  # 결과 파싱
│       └── models.go                  # 리포트 데이터 구조
│
├── bin/
│   ├── trivy                          # Trivy 바이너리 (미포함)
│   └── trivy-parser                   # Parser 바이너리 (미포함)
│
├── custom-policies/                   # 커스텀 Rego 정책 예시
│   ├── s3-001.rego
│   ├── s3-002.rego
│   └── ...
│
├── storage/                           # Terraform 파일 임시 저장소
│   └── {project-id}/
│       └── mr-{mr-iid}/
│           └── *.tf
│
├── scan-results/                      # 스캔 결과 저장
│   ├── original/
│   │   └── {project}-{mr}.json        # Trivy 원본 결과
│   └── {project}/
│       └── mr-{mr-iid}/
│           ├── builtin-main.json
│           ├── custom-main.json
│           └── summary.xlsx
│
├── gitlab-ci/
│   └── ci-entrypoint.yml              # GitLab CI 연동 템플릿
│
├── go.mod
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## 동작 방식

파이프라인은 다음 6단계로 동작:

1. **요청 검증**: API Secret 검증 및 요청 파싱
2. **파일 다운로드**: GitLab MR에서 변경된 `.tf` 파일 수집
3. **보안 스캔**: Trivy + 커스텀 정책 실행
4. **결과 처리**: trivy-parser로 파일 단위 결과 분리
5. **MR 피드백**: 스캔 결과를 MR 코멘트로 등록
6. **정리 작업**: 임시 파일 삭제 및 응답 반환

<br>

**핵심 컴포넌트**:

- **Scanner** (`internal/scanner/`): Trivy 및 parser 실행 제어
- **Report Builder** (`internal/report/`): MR용 Markdown 리포트 생성
- **GitLab Client** (`internal/gitlab/`): 파일 다운로드 및 코멘트 처리

<br>

## 주요 기능 / 핵심 로직

- **GitLab 연동**: MR 기반 워크플로우에 자연스럽게 통합되어 변경 파일 자동 다운로드 및 코멘트 등록 수행
- **커스텀 정책 지원**: Trivy 기본 정책과 함께 조직별 Rego 정책 적용 가능
- **결과 분리 처리**: Terraform 파일 단위로 개별 리포트를 생성하여 정확한 수정 지점 제공
- **Excel 리포트 출력**: 비개발자도 확인할 수 있는 다운로드 가능한 스프레드시트 제공
- **심각도 분류**: CRITICAL / HIGH / MEDIUM / LOW 기준으로 취약점 등급화
- **스캐너 사전 검증**: 실행 전 필수 바이너리 존재 여부를 확인하여 안정성 확보

<br>

## 로컬 실행 방법

### 1. Setup

```bash
# 레포토리 복제
git clone https://github.com/2000junghyun/iac-sast-security-pipeline
cd iac-sast-security-pipeline

# Trivy 바이너리 bin 디렉토리에 설치 (선택)
./scripts/setup-bin.sh

# trivy-parser 바이너리 bin 디렉토리에 설치 (필수)
# link: https://github.com/2000junghyun/trivy-parser
```

### 2. 환경 구성

`.env` 파일 생성:

```bash
# GitLab Configuration
GITLAB_URL=https://gitlab.com
GITLAB_TOKENS=project/path:glpat-xxxxx,another/project:glpat-yyyyy
WEBHOOK_SECRET=your-secret-here

# Server Configuration
SERVER_PORT=8080

# Path Configuration (optional)
STORAGE_PATH=./storage
TRIVY_BIN_PATH=./bin/trivy
PARSER_BIN_PATH=./bin/trivy-parser
CUSTOM_POLICIES_PATH=./custom-policies
SCAN_RESULTS_PATH=./scan-results
```

### 3-1. 로컬 서버 실행

```bash
# Development mode
go run cmd/server/main.go

# Or build and run
go build -o server cmd/server/main.go
./server
```

### 3-2. 도커에 배포

```bash
# Build image
docker build -t iac-scanner .

# Run with docker-compose
docker-compose up -d
```

<br>

## GitLab CI 통합 방법

`.gitlab-ci.yml` 추가:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/2000junghyun/iac-sast-security-pipeline/main/gitlab-ci/ci-entrypoint.yml'

variables:
  SCANNER_URL: "https://your-scanner-service.com"
  SCANNER_SECRET: "your-webhook-secret"
```

<br>

## GitLab 토큰 설정 방법

**Project Access Token** (필수):
1. Navigate to `Settings` > `Access Tokens`
2. Create token with:
   - Role: `Developer` or higher
   - Scopes: `api`, `read_repository`
3. Add to `GITLAB_TOKENS`: `project/path:glpat-xxxxx`

**여러 프로젝트 등록:**
```bash
GITLAB_TOKENS=group1/project1:glpat-xxxxx,group2/project2:glpat-yyyyy
```

<br>

## 기대 효과

- **Shift-left 보안**: 배포 이후가 아닌 Merge 이전 단계에서 IaC 설정 오류 사전 탐지
- **개발자 피드백 루프 개선**: MR 내 즉각적이고 실행 가능한 피드백으로 커뮤니케이션 비용 감소
- **정책 준수 강제화**: 조직 표준에 맞춘 커스텀 정책으로 보안 기준 일관성 유지
- **노이즈 감소**: 파일 단위 결과 제공으로 개발자가 본인 변경 사항에만 집중 가능
- **CI/CD 친화적 설계**: 수동 개입 없이 자동화 중심 워크플로우에 최적화됨
