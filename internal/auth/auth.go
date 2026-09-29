package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
)

const (
	HeaderName          = "X-API-Key"
	MinCredentialLength = 32
	MaxCredentialLength = 128
)

var (
	ErrUnauthenticated = errors.New("API client authentication failed")
	ErrForbidden       = errors.New("API client lacks required scopes")

	keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	scopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_-]{0,63}$`)
)

type Mode string

const (
	ModePublic Mode = "public"
	ModeAPIKey Mode = "api_key"
)

// Policy is an immutable route access policy created through NewPolicy.
type Policy struct {
	mode           Mode
	requiredScopes []string
}

// Key is an immutable API key verifier. It contains a digest, never plaintext.
type Key struct {
	id     string
	digest [sha256.Size]byte
	scopes []string
}

type registryKey struct {
	id     string
	digest [sha256.Size]byte
	scopes map[string]struct{}
}

// Registry is immutable after construction and safe for concurrent requests.
type Registry struct {
	keys []registryKey
}

// Identity is produced only after successful API-key authentication.
type Identity struct {
	clientID string
}

func (i Identity) ClientID() (string, bool) {
	return i.clientID, i.clientID != ""
}

func NewPolicy(rawMode string, requiredScopes []string) (Policy, error) {
	mode := Mode(rawMode)
	if mode != ModePublic && mode != ModeAPIKey {
		if rawMode == "" {
			return Policy{}, errors.New("access mode is required")
		}
		return Policy{}, fmt.Errorf("unknown access mode %q", rawMode)
	}

	scopes, err := validateScopes(requiredScopes)
	if err != nil {
		return Policy{}, fmt.Errorf("required scopes: %w", err)
	}
	if mode == ModePublic && len(scopes) != 0 {
		return Policy{}, errors.New("public access mode cannot require scopes")
	}
	if mode == ModeAPIKey && len(scopes) == 0 {
		return Policy{}, errors.New("API key access mode must require at least one scope")
	}
	return Policy{mode: mode, requiredScopes: scopes}, nil
}

func (p Policy) Validate() error {
	_, err := NewPolicy(string(p.mode), p.requiredScopes)
	return err
}

func (p Policy) RequiresAPIKey() bool {
	return p.mode == ModeAPIKey
}

func NewKey(id, digestHex string, scopes []string) (Key, error) {
	if !keyIDPattern.MatchString(id) {
		return Key{}, errors.New("API key ID must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")
	}
	if len(digestHex) != sha256.Size*2 {
		return Key{}, errors.New("API key SHA-256 digest must contain exactly 64 hexadecimal characters")
	}

	decoded, err := hex.DecodeString(digestHex)
	if err != nil {
		return Key{}, errors.New("API key SHA-256 digest must contain exactly 64 hexadecimal characters")
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)

	validatedScopes, err := validateScopes(scopes)
	if err != nil {
		return Key{}, fmt.Errorf("API key scopes: %w", err)
	}
	if len(validatedScopes) == 0 {
		return Key{}, errors.New("API key must declare at least one scope")
	}
	return Key{id: id, digest: digest, scopes: validatedScopes}, nil
}

func NewRegistry(keys []Key) (*Registry, error) {
	seenIDs := make(map[string]struct{}, len(keys))
	seenDigests := make(map[[sha256.Size]byte]struct{}, len(keys))
	registryKeys := make([]registryKey, 0, len(keys))

	for _, key := range keys {
		if !keyIDPattern.MatchString(key.id) {
			return nil, errors.New("API key registry contains an invalid ID")
		}
		if _, exists := seenIDs[key.id]; exists {
			return nil, fmt.Errorf("duplicate API key ID %q", key.id)
		}
		seenIDs[key.id] = struct{}{}
		if _, exists := seenDigests[key.digest]; exists {
			return nil, errors.New("duplicate API key SHA-256 digest")
		}
		seenDigests[key.digest] = struct{}{}

		scopes, err := validateScopes(key.scopes)
		if err != nil {
			return nil, fmt.Errorf("API key %q scopes: %w", key.id, err)
		}
		scopeSet := make(map[string]struct{}, len(scopes))
		for _, scope := range scopes {
			scopeSet[scope] = struct{}{}
		}
		registryKeys = append(registryKeys, registryKey{id: key.id, digest: key.digest, scopes: scopeSet})
	}

	return &Registry{keys: registryKeys}, nil
}

// Authorize authenticates one API client and enforces all route scopes.
func (r *Registry) Authorize(policy Policy, headers http.Header) (Identity, error) {
	if policy.mode == ModePublic {
		return Identity{}, nil
	}
	if policy.mode != ModeAPIKey {
		return Identity{}, ErrUnauthenticated
	}

	credential, err := credential(headers.Values(HeaderName))
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(credential))

	selected := 0
	found := 0
	for index := range r.keys {
		matches := subtle.ConstantTimeCompare(digest[:], r.keys[index].digest[:])
		selected = subtle.ConstantTimeSelect(matches, index, selected)
		found |= matches
	}
	if found != 1 {
		return Identity{}, ErrUnauthenticated
	}

	for _, required := range policy.requiredScopes {
		if _, ok := r.keys[selected].scopes[required]; !ok {
			return Identity{}, ErrForbidden
		}
	}
	return Identity{clientID: r.keys[selected].id}, nil
}

func credential(values []string) (string, error) {
	if len(values) != 1 {
		return "", ErrUnauthenticated
	}
	value := values[0]
	if len(value) < MinCredentialLength || len(value) > MaxCredentialLength {
		return "", ErrUnauthenticated
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' {
			continue
		}
		return "", ErrUnauthenticated
	}
	return value, nil
}

func validateScopes(scopes []string) ([]string, error) {
	validated := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if !scopePattern.MatchString(scope) {
			return nil, errors.New("scope must match [A-Za-z0-9][A-Za-z0-9:_-]{0,63}")
		}
		if _, exists := seen[scope]; exists {
			return nil, fmt.Errorf("duplicate scope %q", scope)
		}
		seen[scope] = struct{}{}
		validated = append(validated, scope)
	}
	return validated, nil
}
