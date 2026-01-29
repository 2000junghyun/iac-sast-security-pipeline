# Sequence Diagrams

## 1. Complete Scan Workflow

```mermaid
sequenceDiagram
    participant CI as GitLab CI/CD
    participant API as HTTP Server
    participant Handler as ScanHandler
    participant GitLab as GitLab API
    participant Scanner as Scanner
    participant Trivy as Trivy Binary
    participant Parser as trivy-parser
    participant Report as Report Builder
    participant FS as File System

    Note over CI: Merge Request Created/Updated
    CI->>API: POST /api/scan
    Note over CI,API: Headers:<br/>X-API-Secret: {secret}<br/>Content-Type: application/json
    
    API->>Handler: Route to ScanHandler
    
    rect rgb(240, 240, 240)
        Note over Handler: 1. Request Validation
        Handler->>Handler: Validate API Secret
        alt Invalid Secret
            Handler-->>CI: 401 Unauthorized
        end
        Handler->>Handler: Parse JSON Body
        alt Invalid JSON
            Handler-->>CI: 400 Bad Request
        end
    end
    
    rect rgb(230, 245, 255)
        Note over Handler,GitLab: 2. File Download
        loop For each file path
            Handler->>GitLab: GET /api/v4/projects/{id}/repository/files/{path}/raw
            Note over Handler,GitLab: Ref: {source_branch}
            GitLab-->>Handler: File Content (bytes)
            Handler->>FS: Save to storage/{project-id}/mr-{mr-iid}/{file}
        end
    end
    
    rect rgb(255, 245, 230)
        Note over Handler,Parser: 3. Security Scan
        Handler->>Scanner: Scan(ScanRequest)
        
        Scanner->>Scanner: ValidateSetup()
        Note over Scanner: Check trivy & parser binaries
        
        Scanner->>FS: Create scan-results/original/
        Scanner->>Trivy: Execute trivy config
        Note over Scanner,Trivy: Command:<br/>trivy config<br/>--config-policy ./custom-policies<br/>--format json<br/>--output {result.json}<br/>{storage-path}
        
        Trivy->>FS: Scan Terraform files
        Trivy->>FS: Write scan-results/original/{project}-{mr}.json
        Trivy-->>Scanner: Exit Code 0
        
        Scanner->>Scanner: CheckVulnerabilitiesInOriginal()
        Note over Scanner: Parse JSON to detect<br/>"Misconfigurations": [...]
        
        Scanner->>Parser: Execute trivy-parser
        Note over Scanner,Parser: Command:<br/>trivy-parser<br/>-input {original.json}<br/>-output {scan-results}/{project}/mr-{mr}/<br/>-preprocess -pretty
        
        Parser->>FS: Read original scan result
        Parser->>Parser: Group by policy ID
        Parser->>Parser: Split by target (.tf file)
        Parser->>Parser: Separate builtin vs custom
        Parser->>FS: Write builtin-{file}.json
        Parser->>FS: Write custom-{file}.json
        Parser->>FS: Write summary.xlsx
        Parser-->>Scanner: Exit Code 0
        
        Scanner-->>Handler: ScanResult{<br/>  ParserSuccess: true,<br/>  HasVulnerabilities: true,<br/>  ParsedDir: "..."<br/>}
    end
    
    rect rgb(240, 255, 240)
        Note over Handler,GitLab: 4. MR Feedback
        alt ScanResult != nil
            Handler->>Report: BuildComment(ScanResult)
            
            alt HasVulnerabilities == true
                Report->>FS: Read scan-results/{project}/mr-{mr}/*.json
                Report->>Report: Parse severity summaries
                Report->>Report: Build Markdown with violations
                Report-->>Handler: Detailed comment with findings
            else No vulnerabilities
                Report-->>Handler: Success message
            end
            
            Handler->>GitLab: POST /api/v4/projects/{id}/merge_requests/{iid}/notes
            Note over Handler,GitLab: Body: {body: markdown_comment}
            GitLab-->>Handler: 201 Created
        else Scan failed
            Handler->>GitLab: POST /api/v4/projects/{id}/merge_requests/{iid}/notes
            Note over Handler,GitLab: Body: "⚠️ 보안 스캔을 수행할 수 없습니다.<br/>관리자에게 문의해주세요."
        end
    end
    
    rect rgb(255, 240, 240)
        Note over Handler,FS: 5. Cleanup
        Handler->>FS: Remove storage/{project-id}/mr-{mr-iid}/
        Handler->>FS: Remove storage/{project-id}/ (if empty)
    end
    
    Handler-->>API: HTTP 200 OK
    API-->>CI: JSON Response
    Note over API,CI: {<br/>  "status": "completed",<br/>  "files_success": N,<br/>  "files_failed": 0<br/>}
```

## 2. Download Link Workflow

```mermaid
sequenceDiagram
    participant CI as GitLab CI/CD
    participant API as HTTP Server
    participant Handler as DownloadLinkHandler
    participant GitLab as GitLab API

    Note over CI: After scan completes
    CI->>API: POST /api/download-link
    Note over CI,API: Headers:<br/>X-API-Secret: {secret}<br/>Content-Type: application/json<br/>Body: {project_path, mr_iid, download_url}
    
    API->>Handler: Route to DownloadLinkHandler
    
    Handler->>Handler: Validate API Secret
    alt Invalid Secret
        Handler-->>CI: 401 Unauthorized
    end
    
    Handler->>Handler: Parse JSON Body
    alt Invalid JSON
        Handler-->>CI: 400 Bad Request
    end
    
    Handler->>Handler: Build download link comment
    Note over Handler: Format:<br/>📊 Scan Results Available<br/>Click to download Excel report
    
    Handler->>GitLab: POST /api/v4/projects/{path}/merge_requests/{iid}/notes
    Note over Handler,GitLab: Body: {body: download_link_comment}
    
    alt Success
        GitLab-->>Handler: 201 Created
        Handler-->>API: HTTP 200 OK
        API-->>CI: {"status": "success"}
    else GitLab Error
        GitLab-->>Handler: 4xx/5xx Error
        Handler-->>API: HTTP 500 Internal Server Error
        API-->>CI: {"status": "failed"}
    end
```

## 3. Scan Results Download Workflow

```mermaid
sequenceDiagram
    participant User as Developer/Reviewer
    participant Browser as Web Browser
    participant API as HTTP Server
    participant Handler as ScanResultsHandler
    participant Excel as Excel Builder
    participant FS as File System

    Note over User: Clicks download link in MR comment
    User->>Browser: Click Download Link
    Browser->>API: GET /api/scan-results?project={path}&mr={iid}
    Note over Browser,API: Headers:<br/>X-API-Secret: {secret}
    
    API->>Handler: Route to ScanResultsHandler
    
    Handler->>Handler: Validate API Secret
    alt Invalid Secret
        Handler-->>Browser: 401 Unauthorized
    end
    
    Handler->>Handler: Parse query parameters
    alt Missing parameters
        Handler-->>Browser: 400 Bad Request
    end
    
    Handler->>FS: Check scan-results/{project}/mr-{mr}/
    alt Directory not found
        Handler-->>Browser: 404 Not Found
    end
    
    Handler->>Excel: BuildExcelFromResults(result_dir)
    
    Excel->>FS: Read builtin-*.json files
    Excel->>FS: Read custom-*.json files
    
    Excel->>Excel: Parse scan results
    Excel->>Excel: Create XLSX with 2 sheets
    Note over Excel: Sheets:<br/>- Custom Policies<br/>- Built-in Policies
    
    Excel->>Excel: Add columns:<br/>Target, Title, Resource,<br/>Severity, Resolution,<br/>StartLine, EndLine, URL
    
    Excel->>Excel: Apply styling:<br/>- Header: bold + yellow<br/>- CRITICAL/HIGH: red text
    
    Excel-->>Handler: Excel file (bytes)
    
    Handler-->>Browser: HTTP 200 OK
    Note over Handler,Browser: Headers:<br/>Content-Type: application/vnd...sheet<br/>Content-Disposition: attachment;<br/>  filename="{project}-{mr}-results.xlsx"
    
    Browser->>User: Download {project}-{mr}-results.xlsx
```

## 4. Error Handling Scenarios

```mermaid
sequenceDiagram
    participant CI as GitLab CI/CD
    participant Handler as ScanHandler
    participant GitLab as GitLab API
    participant Scanner as Scanner

    Note over CI,Scanner: Scenario 1: GitLab File Download Failure
    CI->>Handler: POST /api/scan
    Handler->>GitLab: GET file content
    GitLab-->>Handler: 404 Not Found
    Handler->>Handler: Track as failed_files
    Handler->>GitLab: POST comment (partial success)
    Handler-->>CI: 200 OK (files_failed: N)
    
    Note over CI,Scanner: Scenario 2: Scanner Binary Missing
    CI->>Handler: POST /api/scan
    Handler->>Scanner: Scan()
    Scanner->>Scanner: ValidateSetup()
    Scanner-->>Handler: Error: binary not found
    Handler->>GitLab: POST comment (scan unavailable)
    Handler-->>CI: 200 OK (with error info)
    
    Note over CI,Scanner: Scenario 3: Trivy Execution Failure
    CI->>Handler: POST /api/scan
    Handler->>Scanner: Scan()
    Scanner->>Scanner: Execute Trivy
    Note over Scanner: Trivy exits with error
    Scanner-->>Handler: ScanResult = nil
    Handler->>GitLab: POST comment (scan failed)
    Handler-->>CI: 200 OK
    
    Note over CI,Scanner: Scenario 4: Parser Execution Failure
    CI->>Handler: POST /api/scan
    Handler->>Scanner: Scan()
    Scanner->>Scanner: Execute trivy-parser
    Note over Scanner: Parser exits with error
    Scanner-->>Handler: ScanResult{ParserSuccess: false}
    Handler->>GitLab: POST comment (parser failed)
    Handler-->>CI: 200 OK
```

## Key Components Interaction

### Scanner Internal Flow

```mermaid
sequenceDiagram
    participant S as Scanner
    participant PM as PathManager
    participant TE as TrivyExecutor
    participant PE as ParserExecutor

    S->>PM: CreatePaths(project, mr)
    PM-->>S: PathSet{storage, original, parsed}
    
    S->>TE: ValidateSetup()
    TE->>TE: Check trivy binary exists
    TE-->>S: nil (success)
    
    S->>TE: Execute(paths)
    TE->>TE: Build trivy command
    TE->>TE: Run trivy config
    TE-->>S: original_result.json path
    
    S->>S: CheckVulnerabilitiesInOriginal()
    Note over S: Fast JSON parsing to detect<br/>"Misconfigurations": [...]
    
    S->>PE: ValidateSetup()
    PE->>PE: Check parser binary exists
    PE-->>S: nil (success)
    
    S->>PE: Execute(original, output_dir)
    PE->>PE: Build parser command
    PE->>PE: Run trivy-parser
    PE-->>S: parsed_dir path
    
    S-->>S: Return ScanResult
```

### Report Builder Internal Flow

```mermaid
sequenceDiagram
    participant CB as CommentBuilder
    participant MB as MarkdownBuilder
    participant P as Parser

    CB->>CB: BuildComment(ScanResult)
    
    alt ParserSuccess == false
        CB-->>CB: Return parser failed message
    else HasVulnerabilities == false
        CB-->>CB: Return success message
    else
        CB->>MB: BuildScanComment(parsed_dir)
        
        MB->>P: List JSON files in parsed_dir
        P-->>MB: [builtin-*.json, custom-*.json]
        
        loop For each JSON file
            MB->>P: ParseScanResultFile(file)
            P->>P: Extract severity summary
            P->>P: Extract violations
            P-->>MB: FileScanResult
        end
        
        MB->>MB: Sort files alphabetically
        MB->>MB: Build Markdown sections
        Note over MB: - Scanned files list<br/>- Severity summary<br/>- Policy summary<br/>- Per-file violations
        
        MB-->>CB: Formatted Markdown comment
        CB-->>CB: Return comment
    end
```

## Notes

- **Asynchronous operations**: File downloads happen sequentially, not in parallel
- **Error resilience**: Partial failures are tracked and reported, not fatal
- **Cleanup strategy**: Temporary files removed regardless of scan success/failure
- **GitLab API rate limiting**: Not currently handled, may need retry logic for production
- **Scanner validation**: Pre-flight checks prevent runtime errors from missing binaries
