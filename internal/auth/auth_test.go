package auth

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
)

const testCredential = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef"

func TestRegistryAuthorizesPublicAndScopedAPIKeyPolicies(t *testing.T) {
	key := mustKey(t, "client", testCredential, []string{"orders:read", "orders:write"})
	registry := mustRegistry(t, []Key{key})
	public := mustPolicy(t, "public", nil)
	protected := mustPolicy(t, "api_key", []string{"orders:read", "orders:write"})

	if _, err := registry.Authorize(public, make(http.Header)); err != nil {
		t.Fatalf("public authorization error = %v", err)
	}
	headers := make(http.Header)
	headers.Set(HeaderName, testCredential)
	identity, err := registry.Authorize(protected, headers)
	if err != nil {
		t.Fatalf("protected authorization error = %v", err)
	}
	if clientID, ok := identity.ClientID(); !ok || clientID != "client" {
		t.Fatalf("authenticated identity = (%q, %v), want client", clientID, ok)
	}
}

func TestRegistryRejectsInvalidCredentialTransport(t *testing.T) {
	registry := mustRegistry(t, []Key{mustKey(t, "client", testCredential, []string{"orders:read"})})
	policy := mustPolicy(t, "api_key", []string{"orders:read"})

	tests := []struct {
		name   string
		values []string
	}{
		{name: "missing"},
		{name: "empty", values: []string{""}},
		{name: "invalid", values: []string{"abcdefghijklmnopqrstuvwxyzABCDEFGH123456789"}},
		{name: "duplicate", values: []string{testCredential, testCredential}},
		{name: "oversized", values: []string{strings.Repeat("a", MaxCredentialLength+1)}},
		{name: "too short", values: []string{strings.Repeat("a", MinCredentialLength-1)}},
		{name: "malformed", values: []string{strings.Repeat("a", 42) + "+"}},
		{name: "comma joined", values: []string{testCredential + "," + testCredential}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			for _, value := range tt.values {
				headers.Add(HeaderName, value)
			}
			identity, err := registry.Authorize(policy, headers)
			if err != ErrUnauthenticated {
				t.Fatalf("Authorize() error = %v, want ErrUnauthenticated", err)
			}
			if clientID, ok := identity.ClientID(); ok || clientID != "" {
				t.Fatalf("rejected credential produced identity %q", clientID)
			}
		})
	}
}

func TestRegistryRejectsInsufficientScopes(t *testing.T) {
	registry := mustRegistry(t, []Key{mustKey(t, "client", testCredential, []string{"orders:read"})})
	policy := mustPolicy(t, "api_key", []string{"orders:read", "orders:write"})
	headers := make(http.Header)
	headers.Set(HeaderName, testCredential)

	if _, err := registry.Authorize(policy, headers); err != ErrForbidden {
		t.Fatalf("Authorize() error = %v, want ErrForbidden", err)
	}
}

func TestPolicyAndKeyValidation(t *testing.T) {
	if _, err := NewPolicy("", nil); err == nil {
		t.Fatal("NewPolicy() accepted an omitted mode")
	}
	if _, err := NewPolicy("unknown", nil); err == nil {
		t.Fatal("NewPolicy() accepted an unknown mode")
	}
	if _, err := NewPolicy("public", []string{"orders:read"}); err == nil {
		t.Fatal("NewPolicy() accepted scopes on a public route")
	}
	if _, err := NewPolicy("api_key", nil); err == nil {
		t.Fatal("NewPolicy() accepted a protected route without required scopes")
	}
	if _, err := NewPolicy("api_key", []string{"orders:read", "orders:read"}); err == nil {
		t.Fatal("NewPolicy() accepted duplicate required scopes")
	}
	if _, err := NewKey("bad id", strings.Repeat("0", 64), nil); err == nil {
		t.Fatal("NewKey() accepted an invalid ID")
	}
	if _, err := NewKey("client", "not-a-digest", nil); err == nil {
		t.Fatal("NewKey() accepted an invalid digest")
	}
	if _, err := NewKey("client", strings.Repeat("0", 64), []string{"bad scope"}); err == nil {
		t.Fatal("NewKey() accepted an invalid scope")
	}
	if _, err := NewKey("client", strings.Repeat("0", 64), nil); err == nil {
		t.Fatal("NewKey() accepted an empty scope set")
	}
}

func TestRegistryRejectsDuplicateIDsAndDigests(t *testing.T) {
	first := mustKey(t, "first", testCredential, []string{"orders:read"})
	duplicateID := mustKey(t, "first", strings.Repeat("a", 43), []string{"orders:read"})
	duplicateDigest := mustKey(t, "second", testCredential, []string{"orders:read"})

	if _, err := NewRegistry([]Key{first, duplicateID}); err == nil {
		t.Fatal("NewRegistry() accepted duplicate IDs")
	}
	if _, err := NewRegistry([]Key{first, duplicateDigest}); err == nil {
		t.Fatal("NewRegistry() accepted duplicate digests")
	}
}

func TestRegistrySupportsConcurrentAuthorization(t *testing.T) {
	registry := mustRegistry(t, []Key{mustKey(t, "client", testCredential, []string{"orders:read"})})
	policy := mustPolicy(t, "api_key", []string{"orders:read"})
	headers := make(http.Header)
	headers.Set(HeaderName, testCredential)

	const workers = 100
	errors := make(chan error, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			_, err := registry.Authorize(policy, headers)
			errors <- err
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Authorize() error = %v", err)
		}
	}
}

func mustKey(t *testing.T, id, plaintext string, scopes []string) Key {
	t.Helper()
	digest := sha256.Sum256([]byte(plaintext))
	key, err := NewKey(id, fmt.Sprintf("%x", digest), scopes)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	return key
}

func mustPolicy(t *testing.T, mode string, scopes []string) Policy {
	t.Helper()
	policy, err := NewPolicy(mode, scopes)
	if err != nil {
		t.Fatalf("NewPolicy() error = %v", err)
	}
	return policy
}

func mustRegistry(t *testing.T, keys []Key) *Registry {
	t.Helper()
	registry, err := NewRegistry(keys)
	if err != nil {
		t.Fatalf("NewRegistry() error = %v", err)
	}
	return registry
}
