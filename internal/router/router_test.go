package router

import (
	"testing"
	"time"
)

func TestRouterMatchUsesBoundariesAndLongestPrefix(t *testing.T) {
	routes, err := New([]Route{
		{ID: "catch-all", PathPrefix: "/", Upstream: "http://root.example", Timeout: time.Second},
		{ID: "api", PathPrefix: "/api", Upstream: "http://api.example", Timeout: time.Second},
		{ID: "users", PathPrefix: "/api/users", Upstream: "http://users.example", Timeout: time.Second},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name   string
		path   string
		wantID string
	}{
		{name: "prefix itself", path: "/api/users", wantID: "users"},
		{name: "prefix child", path: "/api/users/42", wantID: "users"},
		{name: "most specific wins", path: "/api/users/42/orders", wantID: "users"},
		{name: "similar segment does not match", path: "/api/users-v2", wantID: "api"},
		{name: "root is catch all", path: "/unmatched", wantID: "catch-all"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := routes.Match(tt.path)
			if !ok {
				t.Fatalf("Match(%q) did not match", tt.path)
			}
			if got.ID != tt.wantID {
				t.Fatalf("Match(%q).ID = %q, want %q", tt.path, got.ID, tt.wantID)
			}
		})
	}
}

func TestRouterUnknownPathReturnsNoMatch(t *testing.T) {
	routes, err := New([]Route{{
		ID: "users", PathPrefix: "/api/users", Upstream: "http://users.example", Timeout: time.Second,
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, requestPath := range []string{"/missing", "/api/users-v2", "/api/user"} {
		if _, ok := routes.Match(requestPath); ok {
			t.Errorf("Match(%q) matched unexpectedly", requestPath)
		}
	}
}

func TestRouterRejectsInvalidOrAmbiguousRoutes(t *testing.T) {
	tests := []struct {
		name   string
		routes []Route
	}{
		{
			name: "duplicate ID",
			routes: []Route{
				{ID: "api", PathPrefix: "/api", Upstream: "http://one.example", Timeout: time.Second},
				{ID: "api", PathPrefix: "/other", Upstream: "http://two.example", Timeout: time.Second},
			},
		},
		{
			name: "duplicate prefix",
			routes: []Route{
				{ID: "one", PathPrefix: "/api", Upstream: "http://one.example", Timeout: time.Second},
				{ID: "two", PathPrefix: "/api", Upstream: "http://two.example", Timeout: time.Second},
			},
		},
		{
			name:   "trailing slash",
			routes: []Route{{ID: "api", PathPrefix: "/api/", Upstream: "http://api.example", Timeout: time.Second}},
		},
		{
			name:   "noncanonical prefix",
			routes: []Route{{ID: "api", PathPrefix: "/api/../admin", Upstream: "http://api.example", Timeout: time.Second}},
		},
		{
			name:   "non-positive timeout",
			routes: []Route{{ID: "api", PathPrefix: "/api", Upstream: "http://api.example"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.routes); err == nil {
				t.Fatal("New() error = nil, want validation error")
			}
		})
	}
}
