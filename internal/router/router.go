package router

import (
	"fmt"
	"sort"
	"strings"
)

// Route describes a gateway route and its upstream destination.
type Route struct {
	ID       string
	Path     string
	Upstream string
}

type compiledRoute struct {
	route  Route
	prefix string
	exact  bool
}

// Router matches request paths against an immutable, deterministic route set.
type Router struct {
	routes []compiledRoute
}

// New validates and compiles routes. A path ending in * is a prefix route;
// every other path is an exact route.
func New(routes []Route) (*Router, error) {
	compiled := make([]compiledRoute, 0, len(routes))
	seenIDs := make(map[string]struct{}, len(routes))
	seenPaths := make(map[string]struct{}, len(routes))

	for _, route := range routes {
		if route.ID == "" {
			return nil, fmt.Errorf("route ID must not be empty")
		}
		if _, exists := seenIDs[route.ID]; exists {
			return nil, fmt.Errorf("duplicate route ID %q", route.ID)
		}
		seenIDs[route.ID] = struct{}{}

		if route.Upstream == "" {
			return nil, fmt.Errorf("route %q upstream must not be empty", route.ID)
		}
		if !strings.HasPrefix(route.Path, "/") {
			return nil, fmt.Errorf("route %q path must start with /", route.ID)
		}
		if strings.Count(route.Path, "*") > 1 || (strings.Contains(route.Path, "*") && !strings.HasSuffix(route.Path, "*")) {
			return nil, fmt.Errorf("route %q wildcard is only allowed at the end", route.ID)
		}
		if _, exists := seenPaths[route.Path]; exists {
			return nil, fmt.Errorf("duplicate route path %q", route.Path)
		}
		seenPaths[route.Path] = struct{}{}

		exact := !strings.HasSuffix(route.Path, "*")
		prefix := strings.TrimSuffix(route.Path, "*")
		if prefix == "" {
			return nil, fmt.Errorf("route %q path must not be empty", route.ID)
		}
		compiled = append(compiled, compiledRoute{route: route, prefix: prefix, exact: exact})
	}

	// Sorting once keeps matching cheap and makes the longest-prefix rule
	// independent of configuration order.
	sort.Slice(compiled, func(i, j int) bool {
		if len(compiled[i].prefix) == len(compiled[j].prefix) {
			return compiled[i].route.ID < compiled[j].route.ID
		}
		return len(compiled[i].prefix) > len(compiled[j].prefix)
	})

	return &Router{routes: compiled}, nil
}

// Match returns the most specific route for path.
func (r *Router) Match(path string) (Route, bool) {
	for _, candidate := range r.routes {
		if candidate.exact && path == candidate.prefix {
			return candidate.route, true
		}
		if !candidate.exact && strings.HasPrefix(path, candidate.prefix) {
			return candidate.route, true
		}
	}
	return Route{}, false
}
