package router

import (
	"fmt"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/auth"
)

// Route describes one validated gateway route and its upstream policy.
type Route struct {
	ID         string
	PathPrefix string
	Upstream   string
	Timeout    time.Duration
	Auth       auth.Policy
}

// Router matches request paths against an immutable, deterministic route set.
type Router struct {
	routes []Route
}

// New validates routing identity and path semantics, then sorts routes so the
// longest valid path prefix always wins regardless of file order.
func New(routes []Route) (*Router, error) {
	compiled := make([]Route, 0, len(routes))
	seenIDs := make(map[string]struct{}, len(routes))
	seenPrefixes := make(map[string]struct{}, len(routes))

	for _, route := range routes {
		if route.ID == "" || strings.TrimSpace(route.ID) != route.ID {
			return nil, fmt.Errorf("route ID must be non-empty without surrounding whitespace")
		}
		if _, exists := seenIDs[route.ID]; exists {
			return nil, fmt.Errorf("duplicate route ID %q", route.ID)
		}
		seenIDs[route.ID] = struct{}{}

		if err := validatePrefix(route.PathPrefix); err != nil {
			return nil, fmt.Errorf("route %q: %w", route.ID, err)
		}
		if _, exists := seenPrefixes[route.PathPrefix]; exists {
			return nil, fmt.Errorf("duplicate route path prefix %q", route.PathPrefix)
		}
		seenPrefixes[route.PathPrefix] = struct{}{}

		if route.Upstream == "" {
			return nil, fmt.Errorf("route %q upstream must not be empty", route.ID)
		}
		if route.Timeout <= 0 {
			return nil, fmt.Errorf("route %q timeout must be greater than zero", route.ID)
		}
		if err := route.Auth.Validate(); err != nil {
			return nil, fmt.Errorf("route %q authentication policy: %w", route.ID, err)
		}
		compiled = append(compiled, route)
	}

	sort.Slice(compiled, func(i, j int) bool {
		if len(compiled[i].PathPrefix) == len(compiled[j].PathPrefix) {
			return compiled[i].ID < compiled[j].ID
		}
		return len(compiled[i].PathPrefix) > len(compiled[j].PathPrefix)
	})

	return &Router{routes: compiled}, nil
}

// Match returns the most specific route whose prefix ends at a path-segment
// boundary. The root prefix is an explicit catch-all route.
func (r *Router) Match(requestPath string) (Route, bool) {
	if !isCanonicalRequestPath(requestPath) {
		return Route{}, false
	}
	for _, candidate := range r.routes {
		prefix := candidate.PathPrefix
		if prefix == "/" || requestPath == prefix ||
			(strings.HasPrefix(requestPath, prefix) && len(requestPath) > len(prefix) && requestPath[len(prefix)] == '/') {
			return candidate, true
		}
	}
	return Route{}, false
}

func isCanonicalRequestPath(requestPath string) bool {
	if requestPath == "" || !strings.HasPrefix(requestPath, "/") || strings.Contains(requestPath, "\\") {
		return false
	}
	canonical := path.Clean(requestPath)
	if strings.HasSuffix(requestPath, "/") && canonical != "/" {
		canonical += "/"
	}
	return canonical == requestPath
}

func validatePrefix(prefix string) error {
	if prefix == "" || strings.TrimSpace(prefix) != prefix {
		return fmt.Errorf("path prefix must be non-empty without surrounding whitespace")
	}
	if !strings.HasPrefix(prefix, "/") {
		return fmt.Errorf("path prefix %q must start with /", prefix)
	}
	if prefix != "/" && strings.HasSuffix(prefix, "/") {
		return fmt.Errorf("path prefix %q must not end with /", prefix)
	}
	if strings.ContainsAny(prefix, "*?#%\\") {
		return fmt.Errorf("path prefix %q contains unsupported characters", prefix)
	}
	if _, err := url.ParseRequestURI(prefix); err != nil {
		return fmt.Errorf("path prefix %q is not a valid URI path", prefix)
	}
	if cleaned := path.Clean(prefix); cleaned != prefix {
		return fmt.Errorf("path prefix %q is not canonical", prefix)
	}
	return nil
}
