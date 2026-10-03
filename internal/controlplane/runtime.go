package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/middleware"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"github.com/Nuryanfa/AegisGate/internal/proxy"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"go.opentelemetry.io/otel/trace"
)

type Runtime struct {
	Revision string
	Handler  *proxy.Handler
	Routes   []router.Route
}

type Compiler struct {
	WriteTimeout time.Duration
	Limiter      proxy.RateLimiter
	Inspector    proxy.RequestInspector
	Events       proxy.SecurityEventPublisher
	Metrics      *observability.Metrics
	Tracing      *observability.Tracing
	Logger       *slog.Logger
}

func (c Compiler) Compile(d config.Dynamic, revision string) (*Runtime, error) {
	if err := config.ValidateDynamic(d); err != nil {
		return nil, err
	}
	for _, route := range d.Routes {
		if route.Timeout >= c.WriteTimeout {
			return nil, errors.New("route timeout exceeds local write timeout")
		}
		if route.RateLimit != nil && c.Limiter == nil {
			return nil, errors.New("rate limiter unavailable")
		}
		if route.WAF != nil && route.WAF.Enabled() && (c.Inspector == nil || c.Events == nil) {
			return nil, errors.New("WAF inspector or event pipeline unavailable")
		}
	}
	registry, err := auth.NewRegistry(d.APIKeys)
	if err != nil {
		return nil, err
	}
	handler, err := proxy.NewWithObservability(d.Routes, registry, c.Limiter, c.Inspector, c.Events, c.Metrics, c.Tracing, c.Logger)
	if err != nil {
		return nil, err
	}
	return &Runtime{Revision: revision, Handler: handler, Routes: append([]router.Route(nil), d.Routes...)}, nil
}

// Store publishes complete immutable runtime values. Dispatch has one pointer load.
type Store struct {
	active                     atomic.Pointer[Runtime]
	mu                         sync.Mutex
	compiler                   Compiler
	startupPolicy, stalePolicy string
	staleAfter                 time.Duration
	started                    time.Time
	lastSuccess                atomic.Int64
	remote                     atomic.Bool
	connected                  atomic.Bool
	metrics                    *observability.ControlPlaneMetrics
}

func (s *Store) SetMetrics(metrics *observability.ControlPlaneMetrics) { s.metrics = metrics }

func NewStore(initial *Runtime, compiler Compiler, settings *config.ControlPlaneConfig) *Store {
	s := &Store{compiler: compiler, started: time.Now()}
	s.active.Store(initial)
	if settings != nil {
		s.startupPolicy = settings.StartupPolicy
		s.stalePolicy = settings.StalePolicy
		s.staleAfter = settings.StaleAfter
	}
	return s
}

func (s *Store) Active() *Runtime        { return s.active.Load() }
func (s *Store) SetConnected(value bool) { s.connected.Store(value) }
func (s *Store) Connected() bool         { return s.connected.Load() }
func (s *Store) RemoteApplied() bool     { return s.remote.Load() }
func (s *Store) Ready() bool {
	if s.startupPolicy == "require_remote" && !s.remote.Load() {
		return false
	}
	return !s.Stale()
}
func (s *Store) Stale() bool {
	if s.stalePolicy != "deny" || s.staleAfter <= 0 {
		if s.metrics != nil {
			s.metrics.Stale.Set(0)
		}
		return false
	}
	last := s.started
	if ts := s.lastSuccess.Load(); ts > 0 {
		last = time.Unix(0, ts)
	}
	stale := time.Since(last) > s.staleAfter
	if s.metrics != nil {
		if stale {
			s.metrics.Stale.Set(1)
		} else {
			s.metrics.Stale.Set(0)
		}
	}
	return stale
}

func (s *Store) Apply(d config.Dynamic, revision string) (bool, error) {
	return s.ApplyContext(context.Background(), d, revision)
}

func (s *Store) ApplyContext(ctx context.Context, d config.Dynamic, revision string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current := s.active.Load(); current != nil && current.Revision == revision {
		s.remote.Store(true)
		s.lastSuccess.Store(time.Now().UnixNano())
		return false, nil
	}
	var compileSpan trace.Span
	if s.compiler.Tracing != nil && s.compiler.Tracing.Enabled() {
		ctx, compileSpan = s.compiler.Tracing.StartCheck(ctx, "control_plane.runtime.compile")
	}
	candidate, err := s.compiler.Compile(d, revision)
	if compileSpan != nil {
		compileSpan.End()
	}
	if err != nil {
		return false, err
	}
	var applySpan trace.Span
	if s.compiler.Tracing != nil && s.compiler.Tracing.Enabled() {
		_, applySpan = s.compiler.Tracing.StartCheck(ctx, "control_plane.runtime.publish")
	}
	s.active.Store(candidate)
	if applySpan != nil {
		applySpan.End()
	}
	s.remote.Store(true)
	s.lastSuccess.Store(time.Now().UnixNano())
	return true, nil
}

func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	active := s.active.Load()
	if active == nil || (s.startupPolicy == "require_remote" && !s.remote.Load()) {
		writeUnavailable(w, r, "CONFIG_NOT_READY", "remote configuration not yet available")
		return
	}
	if s.Stale() {
		writeUnavailable(w, r, "CONFIG_STALE", "remote configuration is stale")
		return
	}
	active.Handler.ServeHTTP(w, r)
}

func writeUnavailable(w http.ResponseWriter, r *http.Request, code, message string) {
	observability.SetRequestOutcome(r.Context(), observability.OutcomeDependencyUnavailable)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message, "request_id": middleware.RequestIDFromContext(r.Context())}})
}
