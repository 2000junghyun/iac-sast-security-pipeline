# IaC SAST Security Pipeline

## Overview

IaC SAST Security Pipeline is a **GitLab-integrated security scanning service** that automatically analyzes Terraform code changes in Merge Requests.
It downloads changed `.tf` files via GitLab API, scans them with Trivy, and posts detailed security feedback directly to the MR.

It supports:

- **Automated file collection**: downloads only changed Terraform files from GitLab MRs
- **Security scanning**: runs Trivy with custom policies against Infrastructure as Code
- **Result processing**: splits scan results per file using trivy-parser
- **GitLab integration**: posts formatted scan results as MR comments
- **Excel export**: generates downloadable Excel reports for scan results

## Tech Stack

- **Language**: Go 1.21+ (see `go.mod`)
- **Scanner**: Trivy v0.58.1 (misconfiguration scanning)
- **Parser**: trivy-parser (custom result processor)
  - `https://github.com/2000junghyun/trivy-parser`
- **Libraries**: 
  - `github.com/joho/godotenv` for environment configuration
  - `github.com/xuri/excelize/v2` for Excel generation
- **Environment**: single binary HTTP server, Docker-ready

## Directory Structure

```
.
├── cmd/
│   ├── server/
│   │   └── main.go                    # HTTP server entry point
│   ├── test-scanner/
│   │   └── main.go                    # Scanner integration test
│   └── test-report/
│       └── main.go                    # Report builder test
│
├── internal/
│   ├── config/
│   │   └── config.go                  # Environment-based configuration
│   │
│   ├── gitlab/
│   │   ├── client.go                  # GitLab API client
│   │   ├── file_api.go                # File download operations
│   │   └── comment_api.go             # MR comment operations
│   │
│   ├── handler/
│   │   ├── scan.go                    # POST /api/scan handler
│   │   ├── results.go                 # GET /api/scan-results handler
│   │   ├── download_link.go           # POST /api/download-link handler
│   │   ├── middleware.go              # Authentication middleware
│   │   └── response.go                # HTTP response helpers
│   │
│   ├── scanner/
│   │   ├── scanner.go                 # Scan orchestration
│   │   ├── trivy_executor.go          # trivy execution
│   │   ├── parser_executor.go         # trivy-parser execution
│   │   └── path_manager.go            # File path management
│   │
│   └── report/
│       ├── comment_builder.go         # MR comment generation
│       ├── markdown_builder.go        # Markdown formatting
│       ├── parser.go                  # Scan result parsing
│       └── models.go                  # Report data structures
│
├── bin/
│   ├── trivy                          # Trivy binary (Not included)
│   └── trivy-parser                   # Parser binary (Not included)
│
├── custom-policies/                   # Sample custom policies (.rego)
│   ├── s3-001.rego
│   ├── s3-002.rego
│   └── ...
│
├── storage/                           # Downloaded Terraform files (temporary)
│   └── {project-id}/
│       └── mr-{mr-iid}/
│           └── *.tf
│
├── scan-results/                      # Scan result outputs
│   ├── original/
│   │   └── {project}-{mr}.json        # Trivy raw output
│   └── {project}/
│       └── mr-{mr-iid}/
│           ├── builtin-main.json      # Built-in policies per file
│           ├── custom-main.json       # Custom policies per file
│           └── summary.xlsx           # Excel report
│
├── gitlab-ci/
│   └── ci-entrypoint.yml              # GitLab CI integration template
│
├── go.mod                             # Go module definition
├── Dockerfile                         # Docker image definition
├── docker-compose.yml                 # Local development setup
└── README.md                          # This document
```

## How It Works

The pipeline follows a simple six-stage workflow:

1. **Request Validation** → Verifies API secret and parses scan request
2. **File Download** → Fetches changed `.tf` files from GitLab MR
3. **Security Scan** → Runs Trivy with custom policies
4. **Result Processing** → Splits results per file using trivy-parser
5. **MR Feedback** → Posts formatted scan results as MR comment
6. **Cleanup** → Removes temporary files and returns response

Key components:

- **Scanner** (`internal/scanner/`): orchestrates Trivy + trivy-parser execution
- **Report Builder** (`internal/report/`): generates Markdown comments from scan results
- **GitLab Client** (`internal/gitlab/`): handles file downloads and MR comments

## How to Run Locally

### 1. Setup

```bash
# Clone repository
git clone https://github.com/2000junghyun/iac-sast-security-pipeline
cd iac-sast-security-pipeline

# Install trivy binary
./scripts/setup-bin.sh

# Install trivy-parser binary in bin directory
# link: https://github.com/2000junghyun/trivy-parser
```

### 2. Configure Environment

Create `.env` file:

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

### 3-1. Run Local Server

```bash
# Development mode
go run cmd/server/main.go

# Or build and run
go build -o server cmd/server/main.go
./server
```

### 3-2. Docker Deployment

```bash
# Build image
docker build -t iac-scanner .

# Run with docker-compose
docker-compose up -d
```

## GitLab CI Integration

Add to your `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/2000junghyun/iac-sast-security-pipeline/main/gitlab-ci/ci-entrypoint.yml'

variables:
  SCANNER_URL: "https://your-scanner-service.com"
  SCANNER_SECRET: "your-webhook-secret"
```

## Configuration Details

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITLAB_URL` | Yes | `https://gitlab.com` | GitLab instance URL |
| `GITLAB_TOKENS` | Yes | - | Project tokens (format: `path:token,path:token`) |
| `WEBHOOK_SECRET` | Yes | - | API authentication secret |
| `SERVER_PORT` | No | `8080` | HTTP server port |
| `STORAGE_PATH` | No | `./storage` | Temporary file storage path |
| `TRIVY_BIN_PATH` | No | `./bin/trivy` | Trivy binary path |
| `PARSER_BIN_PATH` | No | `./bin/trivy-parser` | Parser binary path |
| `CUSTOM_POLICIES_PATH` | No | `./custom-policies` | Custom policies directory |
| `SCAN_RESULTS_PATH` | No | `./scan-results` | Scan results output path |

### GitLab Token Setup

**Project Access Token** (recommended):
1. Navigate to `Settings` > `Access Tokens`
2. Create token with:
   - Role: `Developer` or higher
   - Scopes: `api`, `read_repository`
3. Add to `GITLAB_TOKENS`: `project/path:glpat-xxxxx`

**Multiple Projects:**
```bash
GITLAB_TOKENS=group1/project1:glpat-xxxxx,group2/project2:glpat-yyyyy
```

## Features / Main Logic

- **GitLab integration**: seamless MR workflow with automatic file download and comment posting
- **Custom policies**: support for organization-specific Rego policies alongside Trivy built-ins
- **Result splitting**: generates individual reports per Terraform file for targeted remediation
- **Excel export**: downloadable spreadsheet reports for non-technical stakeholders
- **Severity tracking**: categorizes findings by CRITICAL/HIGH/MEDIUM/LOW severity
- **Scanner validation**: pre-flight checks ensure all required binaries are available

## Motivation / Impact

- **Shift-left security**: catches IaC misconfigurations before merge, not after deployment
- **Developer feedback loop**: immediate, actionable feedback in the MR reduces back-and-forth
- **Policy enforcement**: custom policies ensure compliance with organizational standards
- **Reduced noise**: file-by-file splitting helps developers focus on their changes only
- **CI/CD native**: designed for automation-first workflows, no manual intervention needed

## License

This project is open source under the MIT License.
