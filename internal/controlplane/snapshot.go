package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/waf"
	"google.golang.org/protobuf/proto"
)

const ProtocolVersion = 1

func ToProto(d config.Dynamic) (*cpb.DynamicConfiguration, error) {
	if err := config.ValidateDynamic(d); err != nil {
		return nil, err
	}
	p := &cpb.DynamicConfiguration{}
	for _, key := range d.APIKeys {
		p.ApiClients = append(p.ApiClients, &cpb.ApiClient{Id: key.ID(), Sha256: key.DigestHex(), Scopes: key.Scopes()})
	}
	for _, route := range d.Routes {
		r := &cpb.Route{Id: route.ID, PathPrefix: route.PathPrefix, Upstream: route.Upstream, TimeoutNanos: int64(route.Timeout), Auth: &cpb.AuthenticationPolicy{Mode: string(route.Auth.Mode()), RequiredScopes: route.Auth.RequiredScopes()}}
		if route.RateLimit != nil {
			r.RateLimit = &cpb.RateLimitPolicy{Capacity: route.RateLimit.Capacity(), RefillPerSecond: route.RateLimit.RefillPerSecond(), OnRedisError: string(route.RateLimit.FailureMode())}
		}
		if route.WAF != nil {
			p := route.WAF
			i := p.Inspection()
			r.Waf = &cpb.WafPolicy{Mode: string(p.Mode()), RuleSet: p.RuleSet(), AnomalyThreshold: int32(p.AnomalyThreshold()), Inspection: &cpb.InspectionPolicy{Query: i.Query, Headers: i.Headers, Body: i.Body, MaxQueryBytes: int32(i.MaxQueryBytes), MaxHeaderBytes: int32(i.MaxHeaderBytes), MaxBodyBytes: int32(i.MaxBodyBytes), MaxJsonDepth: int32(i.MaxJSONDepth), MaxJsonElements: int32(i.MaxJSONElements)}}
		}
		p.Routes = append(p.Routes, r)
	}
	return p, nil
}

func FromProto(p *cpb.DynamicConfiguration) (config.Dynamic, error) {
	if p == nil || len(p.Routes) == 0 || len(p.Routes) > 64 || len(p.ApiClients) > 256 {
		return config.Dynamic{}, errors.New("snapshot entry count is invalid")
	}
	d := config.Dynamic{APIKeys: make([]auth.Key, 0, len(p.ApiClients)), Routes: make([]router.Route, 0, len(p.Routes))}
	for _, k := range p.ApiClients {
		if k == nil {
			return config.Dynamic{}, errors.New("snapshot contains nil API client")
		}
		key, err := auth.NewKey(k.Id, k.Sha256, k.Scopes)
		if err != nil {
			return config.Dynamic{}, fmt.Errorf("API client is invalid: %w", err)
		}
		d.APIKeys = append(d.APIKeys, key)
	}
	for _, r := range p.Routes {
		if r == nil || r.Auth == nil {
			return config.Dynamic{}, errors.New("snapshot route or authentication policy is missing")
		}
		authPolicy, err := auth.NewPolicy(r.Auth.Mode, r.Auth.RequiredScopes)
		if err != nil {
			return config.Dynamic{}, fmt.Errorf("authentication policy is invalid: %w", err)
		}
		route := router.Route{ID: r.Id, PathPrefix: r.PathPrefix, Upstream: r.Upstream, Timeout: time.Duration(r.TimeoutNanos), Auth: authPolicy}
		if r.RateLimit != nil {
			policy, err := ratelimit.NewPolicy(r.RateLimit.Capacity, r.RateLimit.RefillPerSecond, r.RateLimit.OnRedisError)
			if err != nil {
				return config.Dynamic{}, fmt.Errorf("rate-limit policy is invalid: %w", err)
			}
			route.RateLimit = &policy
		}
		if r.Waf != nil {
			if r.Waf.Inspection == nil {
				return config.Dynamic{}, errors.New("WAF inspection policy is missing")
			}
			i := r.Waf.Inspection
			policy, err := waf.NewPolicy(r.Waf.Mode, r.Waf.RuleSet, int(r.Waf.AnomalyThreshold), waf.Inspection{Query: i.Query, Headers: i.Headers, Body: i.Body, MaxQueryBytes: int(i.MaxQueryBytes), MaxHeaderBytes: int(i.MaxHeaderBytes), MaxBodyBytes: int(i.MaxBodyBytes), MaxJSONDepth: int(i.MaxJsonDepth), MaxJSONElements: int(i.MaxJsonElements)})
			if err != nil {
				return config.Dynamic{}, fmt.Errorf("WAF policy is invalid: %w", err)
			}
			route.WAF = &policy
		}
		d.Routes = append(d.Routes, route)
	}
	if err := config.ValidateDynamic(d); err != nil {
		return config.Dynamic{}, err
	}
	return d, nil
}

// Revision hashes semantic content, excluding stream sequence and generation time.
func Revision(p *cpb.DynamicConfiguration) (string, error) {
	d, err := FromProto(p)
	if err != nil {
		return "", err
	}
	canonical, err := ToProto(d)
	if err != nil {
		return "", err
	}
	sort.Slice(canonical.ApiClients, func(i, j int) bool { return canonical.ApiClients[i].Id < canonical.ApiClients[j].Id })
	for _, k := range canonical.ApiClients {
		sort.Strings(k.Scopes)
	}
	sort.Slice(canonical.Routes, func(i, j int) bool { return canonical.Routes[i].Id < canonical.Routes[j].Id })
	for _, r := range canonical.Routes {
		sort.Strings(r.Auth.RequiredScopes)
	}
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(canonical)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}
