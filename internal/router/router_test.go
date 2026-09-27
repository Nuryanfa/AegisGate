package router

import "testing"

func TestRouterMatch(t *testing.T) {
	routes, err := New([]Route{
		{ID: "api", Path: "/api/*", Upstream: "http://api.example"},
		{ID: "users", Path: "/api/users/*", Upstream: "http://users.example"},
		{ID: "health", Path: "/upstream-health", Upstream: "http://api.example"},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name   string
		path   string
		wantID string
		ok     bool
	}{
		{name: "prefix route", path: "/api/orders/42", wantID: "api", ok: true},
		{name: "longest prefix wins", path: "/api/users/42", wantID: "users", ok: true},
		{name: "exact route", path: "/upstream-health", wantID: "health", ok: true},
		{name: "exact route rejects suffix", path: "/upstream-health/details", ok: false},
		{name: "unknown route", path: "/missing", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := routes.Match(tt.path)
			if ok != tt.ok {
				t.Fatalf("Match(%q) ok = %v, want %v", tt.path, ok, tt.ok)
			}
			if ok && got.ID != tt.wantID {
				t.Fatalf("Match(%q).ID = %q, want %q", tt.path, got.ID, tt.wantID)
			}
		})
	}
}

func TestRouterRejectsAmbiguousRoutes(t *testing.T) {
	_, err := New([]Route{
		{ID: "first", Path: "/api/*", Upstream: "http://first.example"},
		{ID: "second", Path: "/api/*", Upstream: "http://second.example"},
	})
	if err == nil {
		t.Fatal("New() error = nil, want duplicate path error")
	}
}
