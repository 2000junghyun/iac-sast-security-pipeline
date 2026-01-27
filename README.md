GitLab MR에서 변경된 Terraform 파일을 자동으로 다운로드하고 Trivy로 보안 스캔을 수행하는 경량 HTTP 서버입니다.

## 📋 목차

- [개요](#개요)
- [주요 기능](#주요-기능)
- [아키텍처](#아키텍처)
- [프로젝트 구조](#프로젝트-구조)
- [시퀀스 다이어그램](#시퀀스-다이어그램)
- [환경 설정](#환경-설정)
- [실행 방법](#실행-방법)
- [API 명세](#api-명세)
- [개발](#개발)

## 개요

drops-mini는 GitLab과 연동하여 Merge Request의 Terraform 파일을 자동으로 수집하고, Trivy 보안 스캐너로 분석하여 결과를 제공하는 서비스입니다. CI/CD 파이프라인에서 API 호출을 통해 사용할 수 있습니다.

### 핵심 워크플로우

1. **파일 다운로드**: GitLab API를 통해 MR에서 변경된 Terraform 파일 다운로드
2. **보안 스캔**: Trivy를 사용하여 다운로드된 파일 스캔
3. **결과 파싱**: trivy-parser로 스캔 결과를 타겟(파일)별로 분리하여 저장
4. **MR 피드백**: GitLab MR에 스캔 완료 댓글 자동 작성

## 주요 기능

### ✅ GitLab 통합
- GitLab API를 통한 파일 다운로드 (Private Repository 지원)
- MR에 자동 댓글 작성
- Project Access Token 인증

### 🔍 보안 스캔
- Trivy를 사용한 Terraform 코드 보안 스캔
- Custom policies 지원
- 타겟별 스캔 결과 분리 (각 .tf 파일별 JSON 생성)

### 🚀 경량 HTTP 서버
- 단일 바이너리 실행
- 환경변수 기반 설정
- Health check 엔드포인트 제공

## 아키텍처

```
┌─────────────────┐
│   GitLab CI/CD  │
└────────┬────────┘
         │ POST /api/upload-paths
         │ (파일 경로 정보)
         ▼
┌─────────────────────────────────────┐
│         drops-mini Server           │
│  ┌──────────────────────────────┐  │
│  │  Path Upload Handler         │  │
│  │  - API Secret 검증           │  │
│  │  - 파일 경로 수신            │  │
│  └──────────┬───────────────────┘  │
│             ▼                       │
│  ┌──────────────────────────────┐  │
│  │  GitLab Client               │  │
│  │  - 파일 다운로드 (Raw API)   │  │
│  │  - MR 댓글 작성              │  │
│  └──────────┬───────────────────┘  │
│             ▼                       │
│  ┌──────────────────────────────┐  │
│  │  Scanner                     │  │
│  │  1. Trivy 스캔 실행          │  │
│  │  2. trivy-parser 실행        │  │
│  │  3. 결과 파일 생성           │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│        파일 시스템                  │
│                                     │
│  storage/                           │
│  └── {project-id}/                  │
│      └── mr-{mr-iid}/               │
│          ├── main.tf                │
│          └── variables.tf           │
│                                     │
│  scan-results/                      │
│  ├── original/                      │
│  │   └── {project}-{mr}.json       │
│  └── {project}/                     │
│      └── mr-{mr-iid}/               │
│          ├── main.json              │
│          └── variables.json         │
└─────────────────────────────────────┘
```

## 프로젝트 구조

```
drops-mini/
├── cmd/
│   └── server/
│       └── main.go                    # 서버 진입점
│
├── internal/
│   ├── config/
│   │   └── config.go                  # 환경변수 기반 설정 관리
│   │
│   ├── gitlab/
│   │   └── client.go                  # GitLab API 클라이언트
│   │
│   ├── handler/
│   │   └── path_upload.go             # HTTP 핸들러 (파일 업로드 처리)
│   │
│   └── scanner/
│       ├── scanner.go                 # Trivy 스캔 및 Parser 실행
│       └── types.go                   # 스캔 관련 타입 정의
│
├── storage/                           # 다운로드된 Terraform 파일 저장
│   └── {project-id}/
│       └── mr-{mr-iid}/
│           └── *.tf
│
├── scan-results/                      # 스캔 결과 저장
│   ├── original/                      # Trivy 원본 결과
│   │   └── {project}-{mr}.json
│   └── {project}/                     # Parser로 분리된 결과
│       └── mr-{mr-iid}/
│           └── {file}.json
│
├── custom-policies/                   # Trivy Custom Policies
│
├── trivy                              # Trivy 실행 파일
├── trivy-parser                       # trivy-parser 실행 파일
│
├── .env                               # 로컬 환경변수 설정
├── .env.docker                        # Docker 환경변수 설정
├── go.mod                             # Go 모듈 정의
├── go.sum                             # Go 의존성 체크섬
└── README.md                          # 이 문서
```

## 시퀀스 다이어그램

### 전체 워크플로우

```mermaid
sequenceDiagram
    participant CI as GitLab CI/CD
    participant API as drops-mini API
    participant Handler as PathUploadHandler
    participant GitLab as GitLab API
    participant Scanner as Scanner
    participant Trivy as Trivy
    participant Parser as trivy-parser
    participant FS as File System

    CI->>API: POST /api/upload-paths
    Note over CI,API: X-API-Secret: {webhook_secret}<br/>Body: {project_id, mr_iid, file_paths}
    
    API->>Handler: ServeHTTP()
    Handler->>Handler: Validate API Secret
    Handler->>Handler: Parse JSON Body
    
    loop For each file path
        Handler->>GitLab: GetFileRaw(project, file, branch)
        GitLab-->>Handler: File Content (bytes)
        Handler->>FS: Save file to storage/{project}/mr-{mr}/
    end
    
    Handler->>Scanner: Scan(ScanRequest)
    
    Scanner->>FS: Create scan-results/original/
    Scanner->>Trivy: Execute trivy config
    Note over Scanner,Trivy: trivy config --config-check ./custom-policies<br/>--format json -o result.json ./storage/
    Trivy->>FS: Write original scan result
    Trivy-->>Scanner: Success
    
    Scanner->>Parser: Execute trivy-parser
    Note over Scanner,Parser: trivy-parser -input result.json<br/>-output ./results/ -group-by-policy<br/>-split-by-target -pretty
    Parser->>FS: Write parsed results (per .tf file)
    Parser-->>Scanner: Success
    
    Scanner-->>Handler: Scan Complete
    
    Handler->>GitLab: PostMRComment(project, mr_iid, comment)
    Note over Handler,GitLab: "✅ 파일 다운로드 완료<br/>🔍 Trivy 스캔 완료"
    GitLab-->>Handler: Comment Posted
    
    Handler-->>API: HTTP 200 OK
    API-->>CI: JSON Response
    Note over API,CI: {status: "completed",<br/>files_success: N,<br/>files_failed: 0}
```

### API 요청/응답 흐름

```mermaid
sequenceDiagram
    participant Client
    participant Server
    participant Handler
    participant GitLab
    participant Scanner

    Client->>Server: POST /api/upload-paths
    Note over Client,Server: Headers:<br/>X-API-Secret: secret<br/>Content-Type: application/json

    Server->>Handler: Route to PathUploadHandler
    
    alt Invalid API Secret
        Handler-->>Client: 401 Unauthorized
    end
    
    alt Invalid JSON
        Handler-->>Client: 400 Bad Request
    end
    
    alt Missing Required Fields
        Handler-->>Client: 400 Bad Request
    end
    
    Handler->>GitLab: Download files
    GitLab-->>Handler: File contents
    
    Handler->>Scanner: Scan files
    Scanner-->>Handler: Scan results
    
    Handler->>GitLab: Post MR comment
    
    alt All files processed
        Handler-->>Client: 200 OK + JSON
    else Partial success
        Handler-->>Client: 206 Partial Content + JSON
    else All failed
        Handler-->>Client: 500 Internal Server Error + JSON
    end
```

## 환경 설정

### 필수 환경변수

```bash
# GitLab 설정
GITLAB_URL=http://localhost:3080              # GitLab 인스턴스 URL
GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx       # GitLab API Token

# 서버 설정
SERVER_PORT=9090                              # HTTP 서버 포트
WEBHOOK_SECRET=your-secret-here               # API 인증 Secret

# 저장 경로 (선택적)
STORAGE_PATH=./storage                        # 다운로드된 파일 저장 경로
```

### .env 파일 예시

```bash
# .env
GITLAB_URL=http://localhost:3080
GITLAB_TOKEN=glpat-ogWZWhU2W9DA57DJ8ADN2m86MQp1OjgH.01.0w1re2h1x
WEBHOOK_SECRET=test-webhook-secret-2025
SERVER_PORT=9090
STORAGE_PATH=./storage
```

### GitLab Token 발급

1. **Project Access Token** (권장)
   - GitLab 프로젝트 → Settings → Access Tokens
   - Token name: `drops-mini-scanner`
   - Role: `Developer` 이상
   - Scopes: `api`, `read_repository`

2. **Personal Access Token**
   - User Settings → Access Tokens
   - Scopes: `api`, `read_api`, `read_repository`

## 실행 방법

### 1. 의존성 설치

```bash
# Go 모듈 다운로드
go mod download
```

### 2. 실행 파일 준비

프로젝트 루트에 다음 파일들이 있어야 합니다:
- `trivy`: Trivy 실행 파일
- `trivy-parser`: trivy-parser 실행 파일
- `custom-policies/`: Custom policies 디렉토리 (선택적)

### 3. 서버 실행

```bash
# .env 파일이 있는 경우
cd drops-mini
go run cmd/server/main.go

# 또는 빌드 후 실행
go build -o drops-mini cmd/server/main.go
./drops-mini
```

### 4. 서버 확인

```bash
# Health check
curl http://localhost:9090/health

# 서비스 정보
curl http://localhost:9090/
```

## API 명세

### POST /api/upload-paths

GitLab MR에서 변경된 Terraform 파일을 다운로드하고 스캔합니다.

#### Request Headers

```
X-API-Secret: {WEBHOOK_SECRET}
Content-Type: application/json
```

#### Request Body

```json
{
  "project_id": 1,
  "project_path": "platform-engineering/provision/test",
  "mr_iid": 23,
  "source_branch": "feature-branch",
  "mr_title": "Add security improvements",
  "file_paths": [
    "main.tf",
    "variables.tf",
    "modules/vpc/main.tf"
  ]
}
```

#### Response (200 OK)

```json
{
  "status": "completed",
  "message": "Processed 3/3 files",
  "project_id": 1,
  "mr_iid": 23,
  "files_total": 3,
  "files_success": 3,
  "files_failed": 0,
  "failed_files": []
}
```

#### Response (206 Partial Content)

```json
{
  "status": "completed",
  "message": "Processed 2/3 files",
  "project_id": 1,
  "mr_iid": 23,
  "files_total": 3,
  "files_success": 2,
  "files_failed": 1,
  "failed_files": ["modules/vpc/main.tf"]
}
```

#### Error Responses

- **401 Unauthorized**: Invalid API Secret
- **400 Bad Request**: Invalid JSON or missing required fields
- **500 Internal Server Error**: All files failed to download

### GET /health

서버 상태를 확인합니다.

#### Response (200 OK)

```json
{
  "status": "healthy",
  "service": "drops-mini"
}
```

### GET /

서비스 정보를 반환합니다.

#### Response (200 OK)

```json
{
  "service": "drops-mini",
  "version": "1.0.0",
  "status": "running"
}
```

## 개발

### 디렉토리별 책임

#### `cmd/server/`
- 서버 진입점
- 의존성 초기화 및 주입
- HTTP 라우팅 설정

#### `internal/config/`
- 환경변수 로딩
- 설정 검증
- 민감 정보 마스킹

#### `internal/gitlab/`
- GitLab API 클라이언트
- 파일 다운로드
- MR 댓글 작성

#### `internal/handler/`
- HTTP 요청 처리
- API 인증
- 파일 다운로드 오케스트레이션

#### `internal/scanner/`
- Trivy 스캔 실행
- trivy-parser 실행
- 결과 파일 관리

### 빌드

```bash
# 로컬 빌드
go build -o drops-mini cmd/server/main.go

# 크로스 컴파일 (Linux)
GOOS=linux GOARCH=amd64 go build -o drops-mini-linux cmd/server/main.go
```

### 테스트

```bash
# 유닛 테스트
go test ./...

# 커버리지 확인
go test -cover ./...
```

### CI/CD 통합 예시

```yaml
# .gitlab-ci.yml
stages:
  - scan

terraform-scan:
  stage: scan
  script:
    - |
      curl -X POST http://drops-mini:9090/api/upload-paths \
        -H "X-API-Secret: ${DROPS_MINI_SECRET}" \
        -H "Content-Type: application/json" \
        -d "{
          \"project_id\": ${CI_PROJECT_ID},
          \"project_path\": \"${CI_PROJECT_PATH}\",
          \"mr_iid\": ${CI_MERGE_REQUEST_IID},
          \"source_branch\": \"${CI_MERGE_REQUEST_SOURCE_BRANCH_NAME}\",
          \"mr_title\": \"${CI_MERGE_REQUEST_TITLE}\",
          \"file_paths\": $(git diff --name-only origin/${CI_MERGE_REQUEST_TARGET_BRANCH_NAME}...HEAD | grep '\.tf$' | jq -R . | jq -s .)
        }"
  only:
    - merge_requests
```

## 스캔 결과 구조

### Original Results (Trivy 원본)

```
scan-results/original/test-23.json
```

전체 스캔 결과가 하나의 JSON 파일에 저장됩니다.

### Parsed Results (타겟별 분리)

```
scan-results/test/mr-23/
├── main.json
├── variables.json
└── modules%vpc%main.json
```

각 Terraform 파일별로 개별 JSON 파일이 생성되며, 파일명의 슬래시(`/`)는 퍼센트(`%`)로 치환됩니다.

각 파일에는 심각도별 요약(`SeveritySummary`)이 포함됩니다:

```json
{
  "SeveritySummary": {
    "CRITICAL": 0,
    "HIGH": 3,
    "MEDIUM": 1,
    "LOW": 2
  },
  "Results": [...]
}
```

## 라이센스

MIT License