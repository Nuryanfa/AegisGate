package securityevent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type recordingSink struct {
	mu        sync.Mutex
	records   []Record
	failures  atomic.Int32
	block     <-chan struct{}
	started   chan struct{}
	startOnce sync.Once
	active    atomic.Int32
	maxActive atomic.Int32
}

func (s *recordingSink) Write(ctx context.Context, record Record) error {
	active := s.active.Add(1)
	defer s.active.Add(-1)
	for {
		maximum := s.maxActive.Load()
		if active <= maximum || s.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	if s.started != nil {
		s.startOnce.Do(func() { close(s.started) })
	}
	if s.block != nil {
		select {
		case <-s.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.failures.Load() > 0 {
		s.failures.Add(-1)
		return errors.New("synthetic sink failure")
	}
	s.mu.Lock()
	s.records = append(s.records, record)
	s.mu.Unlock()
	return nil
}

func (s *recordingSink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.records) }

func TestPipelineCompleteDrainAndStatistics(t *testing.T) {
	sink := &recordingSink{}
	p := newTestPipeline(t, testOptions(), sink)
	for range 20 {
		if !p.Publish(detectorEvent("users", "audit", "AG-1001")) {
			t.Fatal("Publish() dropped unexpectedly")
		}
	}
	shutdownPipeline(t, p, time.Second)
	snapshot := p.Snapshot()
	if snapshot.AcceptedTotal != 20 || snapshot.ProcessedTotal != 20 || snapshot.DeliveredTotal != 20 || sink.count() != 20 {
		t.Fatalf("snapshot=%#v sink=%d", snapshot, sink.count())
	}
	if p.Publish(detectorEvent("users", "audit")) {
		t.Fatal("Publish() accepted after shutdown")
	}
	if p.Snapshot().DroppedIngressTotal != 1 {
		t.Fatalf("post-shutdown drop not counted: %#v", p.Snapshot())
	}
	shutdownPipeline(t, p, time.Second)
}

func TestPipelineConcurrentPublishAndShutdownRace(t *testing.T) {
	options := testOptions()
	options.QueueCapacity, options.DeliveryCapacity, options.Workers = 128, 128, 4
	p := newTestPipeline(t, options, &recordingSink{})
	const publishers, each = 16, 200
	var group sync.WaitGroup
	group.Add(publishers)
	for range publishers {
		go func() {
			defer group.Done()
			for range each {
				p.Publish(detectorEvent("users", "audit", "AG-1001"))
			}
		}()
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	}()
	group.Wait()
	<-shutdownDone
	s := p.Snapshot()
	if s.AcceptedTotal+s.DroppedIngressTotal != publishers*each {
		t.Fatalf("publish accounting = %#v", s)
	}
}

func TestPipelineDropNewestIsNonBlocking(t *testing.T) {
	release := make(chan struct{})
	sink := &recordingSink{block: release, started: make(chan struct{})}
	options := testOptions()
	options.QueueCapacity, options.DeliveryCapacity, options.Workers = 1, 1, 1
	options.SinkTimeout = time.Second
	p := newTestPipeline(t, options, sink)
	p.Publish(detectorEvent("users", "audit"))
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("sink did not start")
	}
	deadline := time.Now().Add(time.Second)
	dropped := false
	for !dropped && time.Now().Before(deadline) {
		started := time.Now()
		dropped = !p.Publish(detectorEvent("users", "audit"))
		if time.Since(started) > 50*time.Millisecond {
			t.Fatal("Publish() blocked on queue capacity")
		}
	}
	if !dropped || p.Snapshot().DroppedIngressTotal == 0 {
		t.Fatalf("queue never saturated: %#v", p.Snapshot())
	}
	close(release)
	shutdownPipeline(t, p, time.Second)
}

func TestPipelineDeliverySaturationBackpressuresIngress(t *testing.T) {
	release := make(chan struct{})
	sink := &recordingSink{block: release, started: make(chan struct{})}
	options := testOptions()
	options.QueueCapacity, options.DeliveryCapacity, options.Workers = 1, 1, 1
	options.SinkTimeout = time.Second
	p := newTestPipeline(t, options, sink)
	event := detectorEvent("users", "audit")

	if !p.Publish(event) {
		t.Fatal("first event was not accepted")
	}
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("sink did not start")
	}
	if !p.Publish(event) {
		t.Fatal("second event was not accepted")
	}
	waitForSnapshot(t, p, func(snapshot Snapshot) bool { return snapshot.DeliveryQueueDepth == 1 })
	if !p.Publish(event) {
		t.Fatal("third event was not accepted")
	}
	waitForSnapshot(t, p, func(snapshot Snapshot) bool { return snapshot.ProcessedTotal >= 3 })
	if !p.Publish(event) {
		t.Fatal("fourth event was not accepted into ingress")
	}
	if p.Publish(event) {
		t.Fatal("drop-newest policy accepted an event after both stages saturated")
	}
	if snapshot := p.Snapshot(); snapshot.DeliveryQueueDepth != 1 || snapshot.IngressQueueDepth != 1 || snapshot.DroppedIngressTotal != 1 {
		t.Fatalf("unexpected saturation snapshot: %#v", snapshot)
	}

	close(release)
	shutdownPipeline(t, p, time.Second)
}

func TestPipelineSinkErrorTimeoutAndContinuation(t *testing.T) {
	sink := &recordingSink{}
	sink.failures.Store(1)
	p := newTestPipeline(t, testOptions(), sink)
	p.Publish(detectorEvent("users", "audit"))
	p.Publish(detectorEvent("users", "audit"))
	shutdownPipeline(t, p, time.Second)
	if s := p.Snapshot(); s.SinkErrorsTotal != 1 || s.DeliveredTotal != 1 {
		t.Fatalf("sink continuation stats = %#v", s)
	}

	never := make(chan struct{})
	blocking := &recordingSink{block: never, started: make(chan struct{})}
	options := testOptions()
	options.SinkTimeout = 20 * time.Millisecond
	timed := newTestPipeline(t, options, blocking)
	timed.Publish(detectorEvent("users", "audit"))
	shutdownPipeline(t, timed, time.Second)
	if timed.Snapshot().SinkErrorsTotal != 1 {
		t.Fatalf("sink timeout not counted: %#v", timed.Snapshot())
	}
}

func TestPipelineUsesFixedWorkerPool(t *testing.T) {
	release := make(chan struct{})
	sink := &recordingSink{block: release, started: make(chan struct{})}
	options := testOptions()
	options.Workers, options.QueueCapacity, options.DeliveryCapacity = 3, 20, 20
	p := newTestPipeline(t, options, sink)
	for range 10 {
		p.Publish(detectorEvent("users", "audit"))
	}
	deadline := time.Now().Add(time.Second)
	for sink.maxActive.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := sink.maxActive.Load(); got != 3 {
		t.Fatalf("maximum concurrent sink writes = %d, want fixed 3", got)
	}
	close(release)
	shutdownPipeline(t, p, time.Second)
}

func TestPipelineShutdownTimeoutCancelsSinkAndIsIdempotent(t *testing.T) {
	never := make(chan struct{})
	sink := &recordingSink{block: never, started: make(chan struct{})}
	options := testOptions()
	options.SinkTimeout = time.Second
	p := newTestPipeline(t, options, sink)
	p.Publish(detectorEvent("users", "audit"))
	select {
	case <-sink.started:
	case <-time.After(time.Second):
		t.Fatal("sink did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := p.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() error = %v", err)
	}
	shutdownPipeline(t, p, time.Second)

	empty := newTestPipeline(t, testOptions(), &recordingSink{})
	shutdownPipeline(t, empty, time.Second)
}

func testOptions() Options {
	return Options{QueueCapacity: 32, DeliveryCapacity: 32, Workers: 1,
		SinkTimeout: 100 * time.Millisecond, ShutdownTimeout: time.Second, SummaryInterval: time.Hour,
		Detection: DetectionOptions{Enabled: false}}
}

func newTestPipeline(t *testing.T, options Options, sink Sink) *Pipeline {
	t.Helper()
	p, err := NewPipeline(options, sink, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatalf("NewPipeline() error = %v", err)
	}
	return p
}

func shutdownPipeline(t *testing.T, p *Pipeline, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

func waitForSnapshot(t *testing.T, p *Pipeline, predicate func(Snapshot) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if predicate(p.Snapshot()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("pipeline state did not converge: %#v", p.Snapshot())
}

func BenchmarkPublish(b *testing.B) {
	event := detectorEvent("users", "audit", "AG-1001")
	b.Run("accepted", func(b *testing.B) {
		p := &Pipeline{ingress: make(chan Event, 1), accepting: true}
		b.ReportAllocs()
		for range b.N {
			if !p.Publish(event) {
				b.Fatal("unexpected drop")
			}
			<-p.ingress
		}
	})
	b.Run("full_queue_drop", func(b *testing.B) {
		p := &Pipeline{ingress: make(chan Event, 1), accepting: true}
		p.ingress <- event
		b.ReportAllocs()
		for range b.N {
			if p.Publish(event) {
				b.Fatal("unexpected accept")
			}
		}
	})
}

func BenchmarkDetector(b *testing.B) {
	event := detectorEvent("users", "audit", "AG-1001")
	b.Run("below_threshold", func(b *testing.B) {
		clock := &incrementingClock{now: time.Unix(1, 0)}
		d := newDetector(DetectionOptions{Enabled: true, Window: time.Hour, RuleMatchThreshold: int(^uint(0) >> 1), BlockThreshold: 2, Cooldown: time.Nanosecond, MaxKeys: 10}, clock)
		b.ReportAllocs()
		for range b.N {
			d.process(event)
		}
	})
	b.Run("generates_alert", func(b *testing.B) {
		clock := &incrementingClock{now: time.Unix(1, 0)}
		d := newDetector(DetectionOptions{Enabled: true, Window: time.Hour, RuleMatchThreshold: 1, BlockThreshold: 1, Cooldown: time.Nanosecond, MaxKeys: 10}, clock)
		b.ReportAllocs()
		for range b.N {
			d.process(event)
		}
	})
}

type incrementingClock struct{ now time.Time }

func (c *incrementingClock) Now() time.Time { c.now = c.now.Add(time.Nanosecond); return c.now }
