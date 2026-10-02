package waf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestCoreV1RulesPositiveAndBenignFixtures(t *testing.T) {
	policy := testPolicy(t, ModeEnforce, 5, Inspection{Query: true, Headers: true, MaxQueryBytes: 8192, MaxHeaderBytes: 16384})
	tests := []struct {
		name, target string
		header       http.Header
		wantID       string
	}{
		{"SQL injection", "/api?q=1%27+OR+1%3D1--", nil, "AG-1001"},
		{"SQL mixed case", "/api?q=1%27+oR+1%3D1--", nil, "AG-1001"},
		{"XSS", "/api?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", nil, "AG-1002"},
		{"path traversal single encoded", "/api/%2e%2e/secret", nil, "AG-1003"},
		{"traversal encoded separators", "/api?q=..%2F..%2Fetc%2Fpasswd", nil, "AG-1003"},
		{"command injection", "/api?q=ok%3Bcurl+attacker.example", nil, "AG-1004"},
		{"double encoding mixed case", "/api?q=%252E%252e%252Fetc", nil, "AG-1005"},
		{"dangerous header", "/api", http.Header{"X-Http-Method-Override": {"TRACE"}}, "AG-1006"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.target, nil)
			if tt.header != nil {
				req.Header = tt.header
			}
			result, err := NewEngine().Inspect(req, policy)
			if err != nil {
				t.Fatalf("Inspect() error = %v", err)
			}
			if !contains(result.MatchedRuleIDs, tt.wantID) {
				t.Fatalf("matched IDs = %v, want %s", result.MatchedRuleIDs, tt.wantID)
			}
		})
	}

	benign := []string{
		"/api?q=O%27Connor",
		"/api?q=This+article+discusses+SQL+SELECT+and+FROM+clauses",
		"/api?q=%3Cscript%3Econsole.log%28%27documentation%27%29%3C%2Fscript%3E",
		"/api?q=https%3A%2F%2Fexample.com%2Fsearch%3Fpage%3D2",
		"/api?q=use+a%3Bb+as+comparison+text",
	}
	for _, target := range benign {
		result, err := NewEngine().Inspect(httptest.NewRequest(http.MethodGet, target, nil), policy)
		if err != nil || len(result.MatchedRuleIDs) != 0 {
			t.Errorf("benign %q result = %#v, %v", target, result, err)
		}
	}
}

func TestCoreV1CatalogHasStableBoundedMetadata(t *testing.T) {
	catalog := CoreV1Catalog()
	if len(catalog) != 6 || len(catalog) > maxBuiltInRules {
		t.Fatalf("catalog size = %d", len(catalog))
	}
	seen := make(map[string]bool, len(catalog))
	for index, item := range catalog {
		wantID := fmt.Sprintf("AG-100%d", index+1)
		if item.ID != wantID || seen[item.ID] {
			t.Fatalf("rule %d ID = %q, want unique %q", index, item.ID, wantID)
		}
		seen[item.ID] = true
		if item.Category == "" || item.Description == "" || item.Severity == "" || item.Score <= 0 || len(item.Locations) == 0 || item.Limitations == "" {
			t.Fatalf("incomplete metadata for %s: %#v", item.ID, item)
		}
	}
}

func TestInspectionByteLimitsAllowExactBoundary(t *testing.T) {
	policy := testPolicy(t, ModeAudit, 5, Inspection{Query: true, Headers: true, MaxQueryBytes: 3, MaxHeaderBytes: 8})
	req := httptest.NewRequest(http.MethodGet, "/api?q=a", nil)
	req.Header.Set("X", "1234567")
	if _, err := NewEngine().Inspect(req, policy); err != nil {
		t.Fatalf("exact boundary rejected: %v", err)
	}
	req.URL.RawQuery = "q=ab"
	_, err := NewEngine().Inspect(req, policy)
	var clientError *ClientError
	if !errors.As(err, &clientError) || clientError.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-limit error = %v", err)
	}
}

func TestMethodAndPathHaveFixedInspectionBounds(t *testing.T) {
	policy := testPolicy(t, ModeAudit, 5, Inspection{})
	longMethod := httptest.NewRequest(http.MethodGet, "/api", nil)
	longMethod.Method = strings.Repeat("M", maxMethodBytes+1)
	_, err := NewEngine().Inspect(longMethod, policy)
	var clientError *ClientError
	if !errors.As(err, &clientError) || clientError.Status != http.StatusBadRequest {
		t.Fatalf("method error = %v", err)
	}
	longPath := httptest.NewRequest(http.MethodGet, "/api", nil)
	longPath.URL.Path = "/" + strings.Repeat("p", maxPathBytes)
	_, err = NewEngine().Inspect(longPath, policy)
	if !errors.As(err, &clientError) || clientError.Status != http.StatusRequestURITooLong {
		t.Fatalf("path error = %v", err)
	}
}

func TestNormalizationRejectsMalformedAmbiguousAndInvalidText(t *testing.T) {
	policy := testPolicy(t, ModeAudit, 5, Inspection{Query: true, MaxQueryBytes: 1024})
	tests := []struct{ name, rawQuery string }{
		{"malformed percent", "q=%zz"},
		{"invalid UTF-8", "q=%ff"},
		{"NUL", "q=%00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api", nil)
			req.URL.RawQuery = tt.rawQuery
			_, err := NewEngine().Inspect(req, policy)
			var clientError *ClientError
			if !errors.As(err, &clientError) || clientError.Status != http.StatusBadRequest {
				t.Fatalf("error = %v, want 400 ClientError", err)
			}
		})
	}
}

func TestPathEncodingAndRequestMetadataAreNotMutated(t *testing.T) {
	policy := testPolicy(t, ModeAudit, 5, Inspection{Query: true, Headers: true, MaxQueryBytes: 1024, MaxHeaderBytes: 1024})
	req := httptest.NewRequest(http.MethodGet, "/api/%252e%252e%252fsecret?q=hello+world", nil)
	req.Header.Add("X-Test", "first")
	req.Header.Add("X-Test", "second")
	originalPath, originalRawPath, originalQuery := req.URL.Path, req.URL.RawPath, req.URL.RawQuery
	originalHeaders := req.Header.Clone()
	result, err := NewEngine().Inspect(req, policy)
	if err != nil || !contains(result.MatchedRuleIDs, "AG-1005") {
		t.Fatalf("Inspect() = %#v, %v", result, err)
	}
	if req.URL.Path != originalPath || req.URL.RawPath != originalRawPath || req.URL.RawQuery != originalQuery || !reflect.DeepEqual(req.Header, originalHeaders) {
		t.Fatal("inspection mutated request metadata")
	}

	inconsistent := httptest.NewRequest(http.MethodGet, "/api", nil)
	inconsistent.URL.RawPath = "/different"
	_, err = NewEngine().Inspect(inconsistent, policy)
	var clientError *ClientError
	if !errors.As(err, &clientError) || clientError.Status != http.StatusBadRequest {
		t.Fatalf("inconsistent RawPath error = %v", err)
	}
}

func TestQueryPlusDuplicatesAndSplitFieldsAreDeterministic(t *testing.T) {
	policy := testPolicy(t, ModeAudit, 5, Inspection{Query: true, MaxQueryBytes: 2048})
	engine := NewEngine()
	duplicate := httptest.NewRequest(http.MethodGet, "/api?q=benign&q=1%27+OR+1%3D1--", nil)
	first, err := engine.Inspect(duplicate, policy)
	if err != nil || !contains(first.MatchedRuleIDs, "AG-1001") {
		t.Fatalf("duplicate result = %#v, %v", first, err)
	}
	second, err := engine.Inspect(duplicate, policy)
	if err != nil || !reflect.DeepEqual(first.MatchedRuleIDs, second.MatchedRuleIDs) {
		t.Fatalf("results are not deterministic: %#v %#v %v", first, second, err)
	}
	split := httptest.NewRequest(http.MethodGet, "/api?a=1%27+OR&b=1%3D1--", nil)
	result, err := engine.Inspect(split, policy)
	if err != nil || contains(result.MatchedRuleIDs, "AG-1001") {
		t.Fatalf("independent split fields unexpectedly combined: %#v, %v", result, err)
	}
}

func TestBodyInspectionRestoresExactBytesAndValidatesTypes(t *testing.T) {
	body := []byte(`{"name":"O'Connor","probe":"1' OR 1=1--"}`)
	policy := testPolicy(t, ModeAudit, 5, bodyInspection(1024))
	req := httptest.NewRequest(http.MethodPost, "/api", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	result, err := NewEngine().Inspect(req, policy)
	if err != nil || !contains(result.MatchedRuleIDs, "AG-1001") {
		t.Fatalf("Inspect() = %#v, %v", result, err)
	}
	forwarded, err := io.ReadAll(req.Body)
	if err != nil || !bytes.Equal(forwarded, body) {
		t.Fatalf("restored body = %q, %v; want exact %q", forwarded, err, body)
	}

	tests := []struct {
		name, contentType, contentEncoding, body string
		wantStatus                               int
	}{
		{"missing type", "", "", "payload", 415},
		{"multipart", "multipart/form-data; boundary=x", "", "--x--", 415},
		{"compressed", "application/json", "gzip", `{}`, 415},
		{"malformed JSON", "application/json", "", `{`, 400},
		{"multiple JSON", "application/json", "", `{} {}`, 400},
		{"invalid charset", "text/plain; charset=iso-8859-1", "", "text", 415},
		{"invalid UTF-8 JSON", "application/json", "", string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}), 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(tt.body))
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			if tt.contentEncoding != "" {
				req.Header.Set("Content-Encoding", tt.contentEncoding)
			}
			_, err := NewEngine().Inspect(req, policy)
			var clientError *ClientError
			if !errors.As(err, &clientError) || clientError.Status != tt.wantStatus {
				t.Fatalf("error = %v, want status %d", err, tt.wantStatus)
			}
		})
	}
}

func TestFormPlainTextAndChunkedBodies(t *testing.T) {
	policy := testPolicy(t, ModeAudit, 5, bodyInspection(1024))
	for _, tt := range []struct{ contentType, body, wantID string }{
		{"application/x-www-form-urlencoded", "name=ok&probe=1%27+OR+1%3D1--", "AG-1001"},
		{"text/plain; charset=utf-8", "ok;curl attacker.example", "AG-1004"},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(tt.body))
		req.ContentLength = -1
		req.Header.Set("Content-Type", tt.contentType)
		result, err := NewEngine().Inspect(req, policy)
		if err != nil || !contains(result.MatchedRuleIDs, tt.wantID) {
			t.Errorf("%s result = %#v, %v", tt.contentType, result, err)
		}
	}
}

func TestBodyLimitsDepthElementsAndOversize(t *testing.T) {
	limits := bodyInspection(16)
	limits.MaxJSONDepth = 2
	limits.MaxJSONElements = 3
	policy := testPolicy(t, ModeAudit, 5, limits)
	tests := []struct {
		name, body string
		status     int
	}{
		{"oversize", strings.Repeat("x", 17), 413},
		{"depth", `[[[]]]`, 400},
		{"elements", `[1,2,3,4]`, 413},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			_, err := NewEngine().Inspect(req, policy)
			var clientError *ClientError
			if !errors.As(err, &clientError) || clientError.Status != tt.status {
				t.Fatalf("error = %v, want %d", err, tt.status)
			}
		})
	}
}

func TestEngineConcurrentUse(t *testing.T) {
	engine := NewEngine()
	policy := testPolicy(t, ModeEnforce, 5, Inspection{Query: true, MaxQueryBytes: 1024})
	var group sync.WaitGroup
	for range 100 {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := engine.Inspect(httptest.NewRequest(http.MethodGet, "/api?q=1%27+OR+1%3D1--", nil), policy)
			if err != nil || result.Action != ActionBlock {
				t.Errorf("Inspect() = %#v, %v", result, err)
			}
		}()
	}
	group.Wait()
}

func FuzzNormalizeQuery(f *testing.F) {
	f.Add("q=hello+world")
	f.Add("q=%252e%252e%252f")
	policy := testPolicy(f, ModeAudit, 5, Inspection{Query: true, MaxQueryBytes: 1024})
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 1024 {
			t.Skip()
		}
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		req.URL.RawQuery = raw
		first, firstErr := NewEngine().Inspect(req, policy)
		second, secondErr := NewEngine().Inspect(req, policy)
		if (firstErr == nil) != (secondErr == nil) || first.AnomalyScore != second.AnomalyScore || !reflect.DeepEqual(first.MatchedRuleIDs, second.MatchedRuleIDs) {
			t.Fatalf("non-deterministic result")
		}
		if len(first.MatchedRuleIDs) > len(coreV1Rules) {
			t.Fatalf("unbounded rule IDs")
		}
	})
}

func FuzzInspectJSON(f *testing.F) {
	f.Add([]byte(`{"value":"hello"}`))
	f.Add([]byte(`[[[]]]`))
	policy := testPolicy(f, ModeAudit, 5, bodyInspection(1024))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1024 {
			t.Skip()
		}
		original := append([]byte(nil), body...)
		req := httptest.NewRequest(http.MethodPost, "/api", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		_, _ = NewEngine().Inspect(req, policy)
		if !bytes.Equal(body, original) {
			t.Fatal("input mutated")
		}
	})
}

func FuzzRuleEvaluation(f *testing.F) {
	f.Add("hello")
	f.Add("1' OR 1=1--")
	policy := testPolicy(f, ModeEnforce, 5, Inspection{Query: true, MaxQueryBytes: 1024})
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 512 {
			t.Skip()
		}
		req := httptest.NewRequest(http.MethodGet, "/api", nil)
		req.URL.RawQuery = "q=" + url.QueryEscape(input)
		first, firstErr := NewEngine().Inspect(req, policy)
		second, secondErr := NewEngine().Inspect(req, policy)
		if (firstErr == nil) != (secondErr == nil) || errorText(firstErr) != errorText(secondErr) || first.AnomalyScore != second.AnomalyScore || !reflect.DeepEqual(first.MatchedRuleIDs, second.MatchedRuleIDs) {
			t.Fatal("rule evaluation is not deterministic")
		}
	})
}

func BenchmarkWAF(b *testing.B) {
	cases := []struct {
		name, target string
		policy       Policy
		body         []byte
	}{
		{"disabled", "/api?q=hello", testPolicy(b, ModeDisabled, 0, Inspection{}), nil},
		{"audit_no_match", "/api?q=hello", testPolicy(b, ModeAudit, 5, Inspection{Query: true, MaxQueryBytes: 8192}), nil},
		{"enforce_no_match", "/api?q=hello", testPolicy(b, ModeEnforce, 5, Inspection{Query: true, MaxQueryBytes: 8192}), nil},
		{"matched", "/api?q=1%27+OR+1%3D1--", testPolicy(b, ModeEnforce, 5, Inspection{Query: true, MaxQueryBytes: 8192}), nil},
		{"max_body", "/api", testPolicy(b, ModeAudit, 5, bodyInspection(MaxBodyBytes)), bytes.Repeat([]byte("a"), MaxBodyBytes)},
	}
	for _, tt := range cases {
		b.Run(tt.name, func(b *testing.B) {
			engine := NewEngine()
			b.ReportAllocs()
			for range b.N {
				req := httptest.NewRequest(http.MethodPost, tt.target, bytes.NewReader(tt.body))
				if tt.body != nil {
					req.Header.Set("Content-Type", "text/plain")
				}
				_, _ = engine.Inspect(req, tt.policy)
			}
		})
	}
}

func testPolicy(tb testing.TB, mode Mode, threshold int, inspection Inspection) Policy {
	tb.Helper()
	rules := RuleSetCoreV1
	if mode == ModeDisabled {
		rules = ""
	}
	policy, err := NewPolicy(string(mode), rules, threshold, inspection)
	if err != nil {
		tb.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func bodyInspection(max int) Inspection {
	return Inspection{Body: true, MaxBodyBytes: max, MaxJSONDepth: 20, MaxJSONElements: 1000}
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
