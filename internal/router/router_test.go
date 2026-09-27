package router

import (
	"testing"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/auth"
)

func TestRouterMatchUsesBoundariesAndLongestPrefix(t *testing.T) {
	public := publicPolicy(t)
	routes, err := New([]Route{
		{ID: "catch-all", PathPrefix: "/", Upstream: "http://root.example", Timeout: time.Second, Auth: public},
		{ID: "api", PathPrefix: "/api", Upstream: "http://api.example", Timeout: time.Second, Auth: public},
		{ID: "users", PathPrefix: "/api/users", Upstream: "http://users.example", Timeout: time.Second, Auth: public},
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
		ID: "users", PathPrefix: "/api/users", Upstream: "http://users.example", Timeout: time.Second, Auth: publicPolicy(t),
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

func TestRouterRejectsNonCanonicalRequestPaths(t *testing.T) {
	routes, err := New([]Route{
		{ID: "public", PathPrefix: "/api", Upstream: "http://public.example", Timeout: time.Second, Auth: publicPolicy(t)},
		{ID: "admin", PathPrefix: "/api/admin", Upstream: "http://admin.example", Timeout: time.Second, Auth: publicPolicy(t)},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, requestPath := range []string{"/api//admin", "/api/./admin", "/api/users/../admin", `/api\admin`} {
		if route, ok := routes.Match(requestPath); ok {
			t.Errorf("Match(%q) = route %q, want no match", requestPath, route.ID)
		}
	}
	if route, ok := routes.Match("/api/admin/"); !ok || route.ID != "admin" {
		t.Fatalf("Match(canonical trailing slash) = (%q, %v), want admin", route.ID, ok)
	}
}

func TestRouterRejectsInvalidOrAmbiguousRoutes(t *testing.T) {
	public := publicPolicy(t)
	tests := []struct {
		name   string
		routes []Route
	}{
		{
			name: "duplicate ID",
			routes: []Route{
				{ID: "api", PathPrefix: "/api", Upstream: "http://one.example", Timeout: time.Second, Auth: public},
				{ID: "api", PathPrefix: "/other", Upstream: "http://two.example", Timeout: time.Second, Auth: public},
			},
		},
		{
			name: "duplicate prefix",
			routes: []Route{
				{ID: "one", PathPrefix: "/api", Upstream: "http://one.example", Timeout: time.Second, Auth: public},
				{ID: "two", PathPrefix: "/api", Upstream: "http://two.example", Timeout: time.Second, Auth: public},
			},
		},
		{
			name:   "trailing slash",
			routes: []Route{{ID: "api", PathPrefix: "/api/", Upstream: "http://api.example", Timeout: time.Second, Auth: public}},
		},
		{
			name:   "noncanonical prefix",
			routes: []Route{{ID: "api", PathPrefix: "/api/../admin", Upstream: "http://api.example", Timeout: time.Second, Auth: public}},
		},
		{
			name:   "non-positive timeout",
			routes: []Route{{ID: "api", PathPrefix: "/api", Upstream: "http://api.example", Auth: public}},
		},
		{
			name:   "missing authentication mode",
			routes: []Route{{ID: "api", PathPrefix: "/api", Upstream: "http://api.example", Timeout: time.Second}},
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

func publicPolicy(t *testing.T) auth.Policy {
	t.Helper()
	policy, err := auth.NewPolicy("public", nil)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}
