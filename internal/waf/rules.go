package waf

import (
	"fmt"
	"regexp"
)

const (
	maxBuiltInRules = 32
	maxPatternBytes = 512
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type rule struct {
	id          string
	category    string
	description string
	severity    Severity
	score       int
	locations   map[string]bool
	pattern     *regexp.Regexp
	limitations string
}

// RuleInfo exposes non-sensitive, stable metadata for documentation and tests.
type RuleInfo struct {
	ID, Category, Description string
	Severity                  Severity
	Score                     int
	Locations                 []string
	Limitations               string
}

var coreV1Rules = []rule{
	newRule("AG-1001", "sql-injection", "SQL control syntax combined with a tautology or UNION SELECT", SeverityHigh, 5,
		[]string{"query", "form", "json", "text"}, `(?i)(?:\bunion\s+(?:all\s+)?select\b|(?:['\"]\s*)?\b(?:or|and)\s+\d+\s*=\s*\d+\s*(?:--|#|/\*))`,
		"Signature-only detection misses many dialects and obfuscations; upstreams must use parameterized SQL."),
	newRule("AG-1002", "cross-site-scripting", "Executable script or event-handler markup with a strong execution signal", SeverityHigh, 5,
		[]string{"query", "form", "json", "text"}, `(?is)(?:<script\b[^>]*>.{0,256}\b(?:alert|eval|fetch)\s*\(|<img\b[^>]{0,256}\bonerror\s*=)`,
		"Context-free signatures cannot replace contextual output encoding and may miss browser-specific payloads."),
	newRule("AG-1003", "path-traversal", "Parent-directory traversal segment", SeverityHigh, 5,
		[]string{"path", "query", "form"}, `(?:^|[/\\])\.\.(?:[/\\]|$)`,
		"Does not understand an upstream filesystem or authorization model; upstreams must constrain filesystem access."),
	newRule("AG-1004", "command-injection", "Shell control operator followed by a common command", SeverityHigh, 5,
		[]string{"query", "form", "json", "text"}, `(?i)(?:;|&&|\|\|)\s*(?:bash|cat|cmd|curl|id|powershell|sh|wget|whoami)\b`,
		"Covers only selected shell-like sequences; applications must avoid shell evaluation and allowlist process arguments."),
	newRule("AG-1005", "ambiguous-encoding", "Dangerous percent escape remains after one decode", SeverityHigh, 5,
		[]string{"path", "query", "form", "json", "text"}, `(?i)%(?:00|25|2e|2f|5c)`,
		"Flags selected double-encoding signals rather than recursively decoding; other encodings may remain undetected."),
	newRule("AG-1006", "dangerous-header", "Method override requests a connection-oriented or tracing method", SeverityMedium, 3,
		[]string{"header"}, `(?i)^x-http-method-override:(?:connect|trace)$`,
		"Only selected header semantics not already rejected by Go's HTTP server are inspected."),
}

func init() {
	if len(coreV1Rules) > maxBuiltInRules {
		panic("core-v1 exceeds the built-in rule-count limit")
	}
}

func newRule(id, category, description string, severity Severity, score int, locations []string, pattern, limitations string) rule {
	if id == "" || category == "" || description == "" || limitations == "" || score < 1 || len(pattern) > maxPatternBytes {
		panic(fmt.Sprintf("invalid built-in WAF rule %q", id))
	}
	locationSet := make(map[string]bool, len(locations))
	for _, location := range locations {
		locationSet[location] = true
	}
	return rule{id: id, category: category, description: description, severity: severity, score: score,
		locations: locationSet, pattern: regexp.MustCompile(pattern), limitations: limitations}
}

func CoreV1Catalog() []RuleInfo {
	result := make([]RuleInfo, 0, len(coreV1Rules))
	for _, item := range coreV1Rules {
		locations := make([]string, 0, len(item.locations))
		for _, location := range []string{"method", "path", "query", "header", "json", "form", "text"} {
			if item.locations[location] {
				locations = append(locations, location)
			}
		}
		result = append(result, RuleInfo{item.id, item.category, item.description, item.severity, item.score, locations, item.limitations})
	}
	return result
}
