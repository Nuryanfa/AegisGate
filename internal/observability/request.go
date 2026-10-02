package observability

import (
	"context"
	"net/http"
)

type requestStateKey struct{}
type RequestState struct {
	RouteID string
	Outcome string
}

func StateFromContext(ctx context.Context) *RequestState {
	state, _ := ctx.Value(requestStateKey{}).(*RequestState)
	return state
}
func SetRequestRoute(ctx context.Context, route, pattern string) {
	if state := StateFromContext(ctx); state != nil {
		state.RouteID = route
	}
	SetRoute(ctx, route, pattern)
}
func SetRequestOutcome(ctx context.Context, outcome string) {
	if state := StateFromContext(ctx); state != nil {
		state.Outcome = outcome
	}
}

// Middleware creates one bounded request state and, when enabled, one server span.
func Middleware(tracing *Tracing, metrics *Metrics, next http.Handler) http.Handler {
	if tracing == nil && metrics == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := &RequestState{Outcome: OutcomeSuccess}
		ctx := context.WithValue(r.Context(), requestStateKey{}, state)
		if metrics != nil {
			metrics.BeginRequest()
		}
		if tracing != nil && tracing.Enabled() {
			traced, span := tracing.StartServer(r.WithContext(ctx))
			defer span.End()
			ctx = traced
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
