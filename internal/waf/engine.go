package waf

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxInspectionValues = 10_000
	maxMethodBytes      = 32
	maxPathBytes        = 8 << 10
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionAudit Action = "audit"
	ActionBlock Action = "block"
)

type Result struct {
	AnomalyScore    int
	MatchedRuleIDs  []string
	HighestSeverity Severity
	Action          Action
	Duration        time.Duration
}

// ClientError represents deterministic invalid input or an inspection limit.
type ClientError struct {
	Status  int
	Code    string
	Message string
	Kind    string
}

func (e *ClientError) Error() string { return e.Kind }

var ErrInternal = errors.New("internal WAF inspection failure")

type value struct{ location, text string }
type representation struct{ values []value }

type Engine struct{}

func NewEngine() *Engine { return &Engine{} }

func (e *Engine) Inspect(r *http.Request, policy Policy) (result Result, err error) {
	started := time.Now()
	defer func() {
		result.Duration = time.Since(started)
		if recover() != nil {
			result = Result{Action: ActionAllow, Duration: time.Since(started)}
			err = ErrInternal
		}
	}()
	if err := policy.Validate(); err != nil {
		return result, fmt.Errorf("%w: invalid policy", ErrInternal)
	}
	if !policy.Enabled() {
		result.Action = ActionAllow
		return result, nil
	}
	representation, err := normalizeRequest(r, policy.Inspection())
	if err != nil {
		return result, err
	}
	for _, candidate := range coreV1Rules {
		matched := false
		for _, inspected := range representation.values {
			if candidate.locations[inspected.location] && couldMatch(candidate.id, inspected.text) && candidate.pattern.MatchString(inspected.text) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		result.AnomalyScore += candidate.score
		result.MatchedRuleIDs = append(result.MatchedRuleIDs, candidate.id)
		if severityRank(candidate.severity) > severityRank(result.HighestSeverity) {
			result.HighestSeverity = candidate.severity
		}
	}
	result.Action = ActionAllow
	if len(result.MatchedRuleIDs) > 0 {
		result.Action = ActionAudit
	}
	if policy.Enforces() && result.AnomalyScore >= policy.AnomalyThreshold() {
		result.Action = ActionBlock
	}
	return result, nil
}

func couldMatch(ruleID, text string) bool {
	switch ruleID {
	case "AG-1001":
		return containsASCIIFold(text, "union") || containsASCIIFold(text, "or") || containsASCIIFold(text, "and")
	case "AG-1002":
		return strings.Contains(text, "<")
	case "AG-1003":
		return strings.Contains(text, "..")
	case "AG-1004":
		return strings.ContainsAny(text, ";&|")
	case "AG-1005":
		return strings.Contains(text, "%")
	case "AG-1006":
		return containsASCIIFold(text, "x-http-method-override:")
	default:
		return false
	}
}

func containsASCIIFold(text, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for start := 0; start+len(needle) <= len(text); start++ {
		matched := true
		for index := range len(needle) {
			left, right := text[start+index], needle[index]
			if left >= 'A' && left <= 'Z' {
				left += 'a' - 'A'
			}
			if right >= 'A' && right <= 'Z' {
				right += 'a' - 'A'
			}
			if left != right {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func normalizeRequest(r *http.Request, limits Inspection) (representation, error) {
	rep := representation{values: make([]value, 0, 32)}
	if len(r.Method) > maxMethodBytes {
		return rep, badRequest("method_too_large", "request method exceeds inspection limit")
	}
	if len(r.URL.Path) > maxPathBytes {
		return rep, uriTooLong("path_too_large", "request path exceeds inspection limit")
	}
	if err := rep.add("method", r.Method); err != nil {
		return rep, err
	}
	if r.URL.RawPath != "" {
		decodedPath, err := url.PathUnescape(r.URL.RawPath)
		if err != nil || decodedPath != r.URL.Path {
			return rep, badRequest("invalid_path_encoding", "request path encoding is inconsistent")
		}
	}
	if err := addText(&rep, "path", r.URL.Path); err != nil {
		return rep, badRequest("invalid_path", "request path is not valid UTF-8 text")
	}
	if hasMalformedEscape(rawPath(r)) {
		return rep, badRequest("invalid_path_encoding", "request path contains malformed percent encoding")
	}
	if limits.Query {
		if len(r.URL.RawQuery) > limits.MaxQueryBytes {
			return rep, tooLarge("query_too_large", "request query exceeds inspection limit")
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			return rep, badRequest("invalid_query_encoding", "request query encoding is invalid")
		}
		for name, entries := range query {
			if err := addText(&rep, "query", name); err != nil {
				return rep, badRequest("invalid_query_text", "request query is not valid UTF-8 text")
			}
			for _, entry := range entries {
				if err := addText(&rep, "query", entry); err != nil {
					return rep, badRequest("invalid_query_text", "request query is not valid UTF-8 text")
				}
			}
		}
	}
	if limits.Headers {
		total := 0
		for name, entries := range r.Header {
			total += len(name)
			for _, entry := range entries {
				total += len(entry)
			}
			if total > limits.MaxHeaderBytes {
				return rep, tooLarge("headers_too_large", "request headers exceed inspection limit")
			}
			if err := validateText(name); err != nil {
				return rep, badRequest("invalid_header_text", "request headers are not valid text")
			}
			if sensitiveHeader(name) {
				continue
			}
			for _, entry := range entries {
				if err := validateText(entry); err != nil {
					return rep, badRequest("invalid_header_text", "request headers are not valid text")
				}
				if err := rep.add("header", strings.ToLower(name)+":"+entry); err != nil {
					return rep, err
				}
			}
		}
	}
	if limits.Body {
		if err := inspectBody(r, limits, &rep); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

func inspectBody(r *http.Request, limits Inspection, rep *representation) error {
	if r.ContentLength < -1 {
		return badRequest("invalid_content_length", "request content length is invalid")
	}
	if r.ContentLength > int64(limits.MaxBodyBytes) {
		return tooLarge("body_too_large", "request body exceeds inspection limit")
	}
	encoding := strings.TrimSpace(r.Header.Get("Content-Encoding"))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		return unsupported("unsupported_content_encoding", "compressed request bodies are not supported for inspection")
	}
	if r.Body == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limits.MaxBodyBytes)+1))
	if err != nil {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
		return fmt.Errorf("%w: read request body", ErrInternal)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) > limits.MaxBodyBytes {
		return tooLarge("body_too_large", "request body exceeds inspection limit")
	}
	if len(body) == 0 {
		return nil
	}
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		return unsupported("unsupported_media_type", "a supported Content-Type is required for body inspection")
	}
	if charset, ok := parameters["charset"]; ok && !strings.EqualFold(charset, "utf-8") && !strings.EqualFold(charset, "utf8") {
		return unsupported("unsupported_charset", "only UTF-8 request bodies are supported for inspection")
	}
	switch strings.ToLower(mediaType) {
	case "application/json":
		return inspectJSON(body, limits, rep)
	case "application/x-www-form-urlencoded":
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return badRequest("malformed_form", "request form encoding is invalid")
		}
		for name, entries := range form {
			if err := addText(rep, "form", name); err != nil {
				return badRequest("invalid_form_text", "request form is not valid UTF-8 text")
			}
			for _, entry := range entries {
				if err := addText(rep, "form", entry); err != nil {
					return badRequest("invalid_form_text", "request form is not valid UTF-8 text")
				}
			}
		}
		return nil
	case "text/plain":
		if err := addText(rep, "text", string(body)); err != nil {
			return badRequest("invalid_body_text", "request body is not valid UTF-8 text")
		}
		return nil
	default:
		return unsupported("unsupported_media_type", "request media type is not supported for body inspection")
	}
}

func inspectJSON(body []byte, limits Inspection, rep *representation) error {
	if !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return badRequest("invalid_json_text", "request JSON is not valid UTF-8 text")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	count := 0
	if err := parseJSONValue(decoder, 1, limits, &count, rep); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return badRequest("malformed_json", "request body must contain exactly one valid JSON value")
	}
	return nil
}

func parseJSONValue(decoder *json.Decoder, depth int, limits Inspection, count *int, rep *representation) error {
	if depth > limits.MaxJSONDepth {
		return badRequest("json_too_deep", "request JSON exceeds the configured depth limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return badRequest("malformed_json", "request body contains malformed JSON")
	}
	*count++
	if *count > limits.MaxJSONElements {
		return tooLarge("json_too_complex", "request JSON exceeds the configured element limit")
	}
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return badRequest("malformed_json", "request body contains malformed JSON")
				}
				*count++
				if *count > limits.MaxJSONElements {
					return tooLarge("json_too_complex", "request JSON exceeds the configured element limit")
				}
				if err := addText(rep, "json", key.(string)); err != nil {
					return badRequest("invalid_json_text", "request JSON is not valid UTF-8 text")
				}
				if err := parseJSONValue(decoder, depth+1, limits, count, rep); err != nil {
					return err
				}
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
				return badRequest("malformed_json", "request body contains malformed JSON")
			}
		case '[':
			for decoder.More() {
				if err := parseJSONValue(decoder, depth+1, limits, count, rep); err != nil {
					return err
				}
			}
			if closing, err := decoder.Token(); err != nil || closing != json.Delim(']') {
				return badRequest("malformed_json", "request body contains malformed JSON")
			}
		default:
			return badRequest("malformed_json", "request body contains malformed JSON")
		}
	case string:
		if err := addText(rep, "json", typed); err != nil {
			return badRequest("invalid_json_text", "request JSON is not valid UTF-8 text")
		}
	}
	return nil
}

func (r *representation) add(location, text string) error {
	if len(r.values) >= maxInspectionValues {
		return tooLarge("too_many_inspection_values", "request contains too many values to inspect")
	}
	r.values = append(r.values, value{location, text})
	return nil
}

func addText(rep *representation, location, text string) error {
	if err := validateText(text); err != nil {
		return err
	}
	return rep.add(location, text)
}

func validateText(text string) error {
	if !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 {
		return errors.New("invalid text")
	}
	return nil
}

func sensitiveHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "cookie", "proxy-authorization", "set-cookie", "x-api-key":
		return true
	default:
		return false
	}
}

func rawPath(r *http.Request) string {
	if r.URL.RawPath != "" {
		return r.URL.RawPath
	}
	return r.URL.EscapedPath()
}

func hasMalformedEscape(text string) bool {
	for index := 0; index < len(text); index++ {
		if text[index] != '%' {
			continue
		}
		if index+2 >= len(text) || !isHex(text[index+1]) || !isHex(text[index+2]) {
			return true
		}
		index += 2
	}
	return false
}

func isHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func severityRank(value Severity) int {
	switch value {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

func badRequest(kind, message string) *ClientError {
	return &ClientError{http.StatusBadRequest, "INVALID_REQUEST", message, kind}
}
func tooLarge(kind, message string) *ClientError {
	return &ClientError{http.StatusRequestEntityTooLarge, "REQUEST_TOO_LARGE", message, kind}
}
func unsupported(kind, message string) *ClientError {
	return &ClientError{http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE", message, kind}
}
func uriTooLong(kind, message string) *ClientError {
	return &ClientError{http.StatusRequestURITooLong, "URI_TOO_LONG", message, kind}
}
