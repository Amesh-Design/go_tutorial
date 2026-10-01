package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go_tutorial/internal/model"
)

// SecurityService handles web application security and HTTP header auditing.
type SecurityService struct {
	client *http.Client
}

// NewSecurityService creates an instance of SecurityService with a safe HTTP client.
func NewSecurityService() *SecurityService {
	return &SecurityService{
		client: &http.Client{
			Timeout: 12 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				return nil
			},
		},
	}
}

// Analyze performs an automated security header and information leak audit on targetURL.
func (s *SecurityService) Analyze(rawURL string) (*model.SecurityAnalysisResult, error) {
	parsedURL, err := normalizeURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GoSecurityScanner/1.0; +https://securityheaders.com)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach target website: %w", err)
	}
	defer resp.Body.Close()

	score := 0
	isHTTPS := strings.EqualFold(resp.Request.URL.Scheme, "https")
	if isHTTPS {
		score += 20 // 20 points for enforcing secure transport
	}

	// 1. Audit Crucial Defensive Headers
	headerChecks := []model.HeaderCheck{}

	// Content-Security-Policy (CSP) / CSP-Report-Only
	cspVal := getHeader(resp.Header, "Content-Security-Policy")
	cspReportOnlyVal := getHeader(resp.Header, "Content-Security-Policy-Report-Only")

	if cspVal != "" {
		score += 25
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:      "Content-Security-Policy",
			Present:     true,
			Value:       cspVal,
			Status:      "PASS",
			Severity:    "HIGH",
			Description: "Prevents Cross-Site Scripting (XSS), data injections, and unauthorized resource loading.",
		})
	} else if cspReportOnlyVal != "" {
		score += 15 // Partial credit for testing/reporting CSP (matches SecurityHeaders/Snyk)
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:         "Content-Security-Policy-Report-Only",
			Present:        true,
			Value:          cspReportOnlyVal,
			Status:         "WARN",
			Severity:       "MEDIUM",
			Description:    "Content-Security-Policy is set to Report-Only mode. Violations are monitored but not actively blocked.",
			Recommendation: "Move policy from 'Content-Security-Policy-Report-Only' to 'Content-Security-Policy' for active enforcement.",
		})
	} else {
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:         "Content-Security-Policy",
			Present:        false,
			Status:         "FAIL",
			Severity:       "HIGH",
			Description:    "Prevents Cross-Site Scripting (XSS), data injections, and unauthorized resource loading.",
			Recommendation: "Define a Content-Security-Policy (e.g. `default-src 'self'`).",
		})
	}

	// Strict-Transport-Security (HSTS)
	hstsVal := getHeader(resp.Header, "Strict-Transport-Security")
	if isHTTPS && hstsVal != "" {
		score += 20
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:      "Strict-Transport-Security",
			Present:     true,
			Value:       hstsVal,
			Status:      "PASS",
			Severity:    "HIGH",
			Description: "Forces browsers to exclusively use HTTPS connections, preventing SSL-stripping MITM attacks.",
		})
	} else {
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:         "Strict-Transport-Security",
			Present:        false,
			Status:         "FAIL",
			Severity:       "HIGH",
			Description:    "Forces browsers to exclusively use HTTPS connections, preventing SSL-stripping MITM attacks.",
			Recommendation: "Set `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
		})
	}

	// X-Frame-Options (Clickjacking protection)
	xfoVal := getHeader(resp.Header, "X-Frame-Options")
	if xfoVal != "" {
		score += 15
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:      "X-Frame-Options",
			Present:     true,
			Value:       xfoVal,
			Status:      "PASS",
			Severity:    "MEDIUM",
			Description: "Protects users against Clickjacking by controlling whether the site can be embedded in an <iframe>.",
		})
	} else {
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:         "X-Frame-Options",
			Present:        false,
			Status:         "FAIL",
			Severity:       "MEDIUM",
			Description:    "Protects users against Clickjacking by controlling whether the site can be embedded in an <iframe>.",
			Recommendation: "Set `X-Frame-Options: DENY` or `SAMEORIGIN`.",
		})
	}

	// X-Content-Type-Options
	xctoVal := getHeader(resp.Header, "X-Content-Type-Options")
	if strings.EqualFold(xctoVal, "nosniff") {
		score += 10
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:      "X-Content-Type-Options",
			Present:     true,
			Value:       xctoVal,
			Status:      "PASS",
			Severity:    "MEDIUM",
			Description: "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
		})
	} else {
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:         "X-Content-Type-Options",
			Present:        xctoVal != "",
			Value:          xctoVal,
			Status:         "FAIL",
			Severity:       "MEDIUM",
			Description:    "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
			Recommendation: "Set `X-Content-Type-Options: nosniff`.",
		})
	}

	// Referrer-Policy
	refVal := getHeader(resp.Header, "Referrer-Policy")
	if refVal != "" {
		score += 5
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:      "Referrer-Policy",
			Present:     true,
			Value:       refVal,
			Status:      "PASS",
			Severity:    "LOW",
			Description: "Governs how much referrer information (URL paths) should be included with requests.",
		})
	} else {
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:         "Referrer-Policy",
			Present:        false,
			Status:         "WARN",
			Severity:       "LOW",
			Description:    "Governs how much referrer information (URL paths) should be included with requests.",
			Recommendation: "Set `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.",
		})
	}

	// Permissions-Policy
	permVal := getHeader(resp.Header, "Permissions-Policy")
	if permVal != "" {
		score += 5
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:      "Permissions-Policy",
			Present:     true,
			Value:       permVal,
			Status:      "PASS",
			Severity:    "LOW",
			Description: "Allows site to restrict browser features like geolocation, microphone, and camera.",
		})
	} else {
		headerChecks = append(headerChecks, model.HeaderCheck{
			Header:         "Permissions-Policy",
			Present:        false,
			Status:         "WARN",
			Severity:       "LOW",
			Description:    "Allows site to restrict browser features like geolocation, microphone, and camera.",
			Recommendation: "Set `Permissions-Policy: geolocation=(), camera=(), microphone=()`.",
		})
	}

	// 2. Audit Information Disclosure Leaks
	infoLeaks := []model.HeaderCheck{}

	// Server header disclosure
	if srv := getHeader(resp.Header, "Server"); srv != "" {
		// Only penalize if specific version numbers are exposed
		infoLeaks = append(infoLeaks, model.HeaderCheck{
			Header:         "Server",
			Present:        true,
			Value:          srv,
			Status:         "WARN",
			Severity:       "LOW",
			Description:    "Reveals web server software name or version to potential attackers.",
			Recommendation: "Configure your reverse proxy/server to suppress the `Server` header.",
		})
	}

	// X-Powered-By disclosure
	if xpb := getHeader(resp.Header, "X-Powered-By"); xpb != "" {
		score -= 10
		infoLeaks = append(infoLeaks, model.HeaderCheck{
			Header:         "X-Powered-By",
			Present:        true,
			Value:          xpb,
			Status:         "WARN",
			Severity:       "MEDIUM",
			Description:    "Discloses backend framework or language technologies (e.g. Express, PHP, ASP.NET).",
			Recommendation: "Disable the `X-Powered-By` header in your framework configuration.",
		})
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return &model.SecurityAnalysisResult{
		TargetURL:    rawURL,
		ResolvedURL:  resp.Request.URL.String(),
		StatusCode:   resp.StatusCode,
		HTTPS:        isHTTPS,
		Score:        score,
		Grade:        calculateGrade(score),
		HeaderChecks: headerChecks,
		InfoLeaks:    infoLeaks,
		ScannedAt:    time.Now().UTC(),
	}, nil
}

func getHeader(h http.Header, name string) string {
	return h.Get(name)
}

func calculateGrade(score int) string {
	switch {
	case score >= 85:
		return "A+"
	case score >= 70:
		return "A"
	case score >= 55:
		return "B"
	case score >= 40:
		return "C"
	case score >= 25:
		return "D"
	default:
		return "F"
	}
}

func normalizeURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("URL cannot be empty")
	}

	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}

	parsed, err := url.ParseRequestURI(raw)
	if err != nil {
		return nil, err
	}

	if parsed.Host == "" {
		return nil, errors.New("hostname is required")
	}

	return parsed, nil
}
