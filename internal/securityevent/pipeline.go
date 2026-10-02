package securityevent

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Snapshot struct {
	AcceptedTotal             uint64
	DroppedIngressTotal       uint64
	ProcessedTotal            uint64
	AlertsGeneratedTotal      uint64
	SinkErrorsTotal           uint64
	DeliveredTotal            uint64
	DroppedDeliveryTotal      uint64
	DetectionKeysDroppedTotal uint64
	IngressQueueDepth         int
	DeliveryQueueDepth        int
	ActiveDetectionKeys       int
}

type counters struct {
	accepted, droppedIngress, processed, alertsGenerated         atomic.Uint64
	sinkErrors, delivered, droppedDelivery, detectionKeysDropped atomic.Uint64
	activeKeys                                                   atomic.Int64
}

type Pipeline struct {
	options     Options
	sink        Sink
	logger      *slog.Logger
	ingress     chan Event
	delivery    chan Record
	detector    *detector
	runCtx      context.Context
	cancel      context.CancelFunc
	publishMu   sync.RWMutex
	accepting   bool
	stopOnce    sync.Once
	summaryStop chan struct{}
	runWG       sync.WaitGroup
	done        chan struct{}
	counters    counters
}

// Cancellation gives context-aware sinks a brief, bounded chance to exit
// after the shutdown deadline before the caller returns.
const shutdownCancellationGrace = 250 * time.Millisecond

func NewPipeline(options Options, sink Sink, logger *slog.Logger, clock Clock) (*Pipeline, error) {
	if err := options.Validate(); err != nil {
		return nil, err
	}
	if sink == nil {
		return nil, errors.New("security-event pipeline requires a sink")
	}
	if logger == nil {
		return nil, errors.New("security-event pipeline requires a diagnostic logger")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pipeline{options: options, sink: sink, logger: logger,
		ingress: make(chan Event, options.QueueCapacity), delivery: make(chan Record, options.DeliveryCapacity),
		detector: newDetector(options.Detection, clock), runCtx: ctx, cancel: cancel,
		accepting: true, summaryStop: make(chan struct{}), done: make(chan struct{})}
	p.runWG.Add(2 + options.Workers)
	go p.runDetector()
	for range options.Workers {
		go p.runWorker()
	}
	go p.runSummary()
	go func() {
		p.runWG.Wait()
		if remaining := len(p.delivery); remaining > 0 {
			p.counters.droppedDelivery.Add(uint64(remaining))
		}
		p.logSummary("security-event pipeline stopped")
		close(p.done)
	}()
	return p, nil
}

func (p *Pipeline) Publish(event Event) bool {
	p.publishMu.RLock()
	defer p.publishMu.RUnlock()
	if !p.accepting {
		p.counters.droppedIngress.Add(1)
		return false
	}
	select {
	case p.ingress <- event:
		p.counters.accepted.Add(1)
		return true
	default:
		p.counters.droppedIngress.Add(1)
		return false
	}
}

func (p *Pipeline) Shutdown(ctx context.Context) error {
	p.stopOnce.Do(func() {
		p.publishMu.Lock()
		p.accepting = false
		close(p.ingress)
		p.publishMu.Unlock()
		close(p.summaryStop)
	})
	select {
	case <-p.done:
		p.cancel()
		return nil
	case <-ctx.Done():
		p.cancel()
	}
	grace := time.NewTimer(shutdownCancellationGrace)
	defer grace.Stop()
	select {
	case <-p.done:
	case <-grace.C:
		select {
		case <-p.done:
		default:
			p.logger.Warn("security-event pipeline shutdown cancellation requested")
		}
	}
	return ctx.Err()
}

func (p *Pipeline) Snapshot() Snapshot {
	return Snapshot{
		AcceptedTotal: p.counters.accepted.Load(), DroppedIngressTotal: p.counters.droppedIngress.Load(),
		ProcessedTotal: p.counters.processed.Load(), AlertsGeneratedTotal: p.counters.alertsGenerated.Load(),
		SinkErrorsTotal: p.counters.sinkErrors.Load(), DeliveredTotal: p.counters.delivered.Load(),
		DroppedDeliveryTotal: p.counters.droppedDelivery.Load(), DetectionKeysDroppedTotal: p.counters.detectionKeysDropped.Load(),
		IngressQueueDepth: len(p.ingress), DeliveryQueueDepth: len(p.delivery), ActiveDetectionKeys: int(p.counters.activeKeys.Load()),
	}
}

func (p *Pipeline) runDetector() {
	defer p.runWG.Done()
	defer close(p.delivery)
	cleanupEvery := time.Second
	if p.options.Detection.Enabled && p.options.Detection.Window < cleanupEvery {
		cleanupEvery = p.options.Detection.Window
	}
	ticker := time.NewTicker(cleanupEvery)
	defer ticker.Stop()
	for {
		select {
		case event, ok := <-p.ingress:
			if !ok {
				return
			}
			p.counters.processed.Add(1)
			alerts := p.detector.process(event)
			p.updateDetectorCounters()
			p.counters.alertsGenerated.Add(uint64(len(alerts)))
			if !p.sendRecord(eventRecord(event)) {
				p.abandonIngress()
				return
			}
			for _, alert := range alerts {
				if !p.sendRecord(alertRecord(alert)) {
					p.abandonIngress()
					return
				}
			}
		case <-ticker.C:
			if p.options.Detection.Enabled {
				p.detector.cleanup(p.detector.clock.Now().UTC())
				p.updateDetectorCounters()
			}
		case <-p.runCtx.Done():
			p.abandonIngress()
			return
		}
	}
}

func (p *Pipeline) updateDetectorCounters() {
	p.counters.activeKeys.Store(int64(p.detector.activeKeys()))
	p.counters.detectionKeysDropped.Store(p.detector.keyDrops)
}

func (p *Pipeline) sendRecord(record Record) bool {
	select {
	case p.delivery <- record:
		return true
	case <-p.runCtx.Done():
		p.counters.droppedDelivery.Add(1)
		return false
	}
}

func (p *Pipeline) abandonIngress() {
	for range p.ingress {
		p.counters.droppedDelivery.Add(1)
	}
}

func (p *Pipeline) runWorker() {
	defer p.runWG.Done()
	for {
		select {
		case <-p.runCtx.Done():
			return
		default:
		}
		select {
		case <-p.runCtx.Done():
			return
		case record, ok := <-p.delivery:
			if !ok {
				return
			}
			ctx, cancel := context.WithTimeout(p.runCtx, p.options.SinkTimeout)
			err := p.sink.Write(ctx, record)
			cancel()
			if err != nil {
				count := p.counters.sinkErrors.Add(1)
				if count == 1 || count&(count-1) == 0 {
					p.logger.Warn("security-event sink failures observed", "sink_errors_total", count)
				}
				continue
			}
			p.counters.delivered.Add(1)
		}
	}
}

func (p *Pipeline) runSummary() {
	defer p.runWG.Done()
	ticker := time.NewTicker(p.options.SummaryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.logSummary("security-event pipeline summary")
		case <-p.summaryStop:
			return
		case <-p.runCtx.Done():
			return
		}
	}
}

func (p *Pipeline) logSummary(message string) {
	s := p.Snapshot()
	p.logger.Info(message,
		"accepted_total", s.AcceptedTotal, "dropped_ingress_total", s.DroppedIngressTotal,
		"processed_total", s.ProcessedTotal, "alerts_generated_total", s.AlertsGeneratedTotal,
		"sink_errors_total", s.SinkErrorsTotal, "delivered_total", s.DeliveredTotal,
		"dropped_delivery_total", s.DroppedDeliveryTotal, "detection_keys_dropped_total", s.DetectionKeysDroppedTotal,
		"ingress_queue_depth", s.IngressQueueDepth, "delivery_queue_depth", s.DeliveryQueueDepth,
		"active_detection_keys", s.ActiveDetectionKeys)
}
