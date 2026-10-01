package model

import "time"

// SecurityAnalysisRequest defines the payload containing the website URL to scan.
type SecurityAnalysisRequest struct {
	URL string `json:"url"`
}

// HeaderCheck represents the evaluation of a specific HTTP response header.
type HeaderCheck struct {
	Header         string `json:"header"`
	Present        bool   `json:"present"`
	Value          string `json:"value,omitempty"`
	Status         string `json:"status"` // "PASS", "WARN", "FAIL"
	Severity       string `json:"severity"` // "HIGH", "MEDIUM", "LOW", "INFO"
	Description    string `json:"description"`
	Recommendation string `json:"recommendation,omitempty"`
}

// SecurityAnalysisResult contains the overall security posture and detailed audit results.
type SecurityAnalysisResult struct {
	TargetURL    string        `json:"target_url"`
	ResolvedURL  string        `json:"resolved_url"`
	StatusCode   int           `json:"status_code"`
	HTTPS        bool          `json:"https_enforced"`
	Score        int           `json:"score"` // 0 to 100
	Grade        string        `json:"grade"` // A+, A, B, C, D, F
	HeaderChecks []HeaderCheck `json:"header_checks"`
	InfoLeaks    []HeaderCheck `json:"info_leaks"`
	ScannedAt    time.Time     `json:"scanned_at"`
}
