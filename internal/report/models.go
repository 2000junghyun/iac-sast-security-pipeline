package report

// 파싱된 스캔 결과 JSON 파일의 구조
type ScanResultFile struct {
	SchemaVersion   int             `json:"SchemaVersion"`
	CreatedAt       string          `json:"CreatedAt"`
	ArtifactName    string          `json:"ArtifactName"`
	ArtifactType    string          `json:"ArtifactType"`
	SeveritySummary SeveritySummary `json:"SeveritySummary"`
	Results         []Result        `json:"Results"`
}

// 심각도별 검출 개수
type SeveritySummary struct {
	CRITICAL int `json:"CRITICAL"`
	HIGH     int `json:"HIGH"`
	MEDIUM   int `json:"MEDIUM"`
	LOW      int `json:"LOW"`
}

// 스캔 결과의 개별 항목
type Result struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Type              string             `json:"Type"`
	MisconfSummary    MisconfSummary     `json:"MisconfSummary"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations"`
}

// 정책 위반 요약
type MisconfSummary struct {
	Successes int `json:"Successes"`
	Failures  int `json:"Failures"`
}

// 개별 정책 위반 정보
type Misconfiguration struct {
	ID          string      `json:"ID"`
	Title       string      `json:"Title"`
	Description string      `json:"Description"`
	Namespace   string      `json:"Namespace"`
	Resolution  string      `json:"Resolution"`
	Severity    string      `json:"Severity"`
	PrimaryURL  string      `json:"PrimaryURL"`
	Status      string      `json:"Status"`
	Violations  []Violation `json:"Violations,omitempty"`
}

// 정책 위반의 개별 발생 위치
type Violation struct {
	Resource  string `json:"Resource"`
	Provider  string `json:"Provider"`
	Service   string `json:"Service"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Message   string `json:"Message"`
}

// 파일별 스캔 결과
type FileScanResult struct {
	FileName         string            // 원본 파일명 (예: main.tf)
	TrivyPassed      bool              // Trivy 기본 정책 통과 여부
	CustomPassed     bool              // 커스텀 정책 통과 여부
	TrivyViolations  []PolicyViolation // Trivy 기본 정책 위반 목록
	CustomViolations []PolicyViolation // 커스텀 정책 위반 목록
}

// 정책 위반 정보
type PolicyViolation struct {
	Title    string
	Severity string
}
