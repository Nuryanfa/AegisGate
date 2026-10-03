package controlplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	settings config.ControlPlaneConfig
	store    *Store
	logger   *slog.Logger
	metrics  *observability.ControlPlaneMetrics
	tracing  *observability.Tracing
	dialer   func(context.Context, string) (*grpc.ClientConn, error)
}

func (c *Client) SetMetrics(metrics *observability.ControlPlaneMetrics) { c.metrics = metrics }
func (c *Client) SetTracing(tracing *observability.Tracing)             { c.tracing = tracing }

func NewClient(settings config.ControlPlaneConfig, store *Store, logger *slog.Logger) (*Client, error) {
	var transport grpc.DialOption
	if settings.TLS.Enabled {
		creds, err := ClientCredentials(settings.TLS)
		if err != nil {
			return nil, err
		}
		transport = grpc.WithTransportCredentials(creds)
	} else {
		transport = grpc.WithTransportCredentials(insecure.NewCredentials())
	}
	dialer := func(ctx context.Context, address string) (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, address, transport, grpc.WithBlock(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(settings.MaxReceiveBytes), grpc.MaxCallSendMsgSize(4096)))
	}
	return &Client{settings: settings, store: store, logger: logger, dialer: dialer}, nil
}

func (c *Client) Run(ctx context.Context) {
	backoff := c.settings.ReconnectMinBackoff
	initialDeadline := time.Now().Add(c.settings.InitialSyncTimeout)
	initialWarned := false
	for ctx.Err() == nil {
		if c.metrics != nil {
			c.metrics.Reconnects.Inc()
		}
		connected, err := c.connectOnce(ctx)
		c.store.SetConnected(false)
		if c.metrics != nil {
			c.metrics.Connected.Set(0)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.logger.Warn("control-plane connection unavailable", "reason", "dependency")
		}
		if !initialWarned && !c.store.RemoteApplied() && time.Now().After(initialDeadline) {
			initialWarned = true
			c.logger.Warn("initial control-plane synchronization timeout", "reason", "dependency")
		}
		if connected {
			backoff = c.settings.ReconnectMinBackoff
		}
		jitter := time.Duration(rand.Int64N(int64(backoff/4) + 1))
		timer := time.NewTimer(backoff + jitter)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < c.settings.ReconnectMaxBackoff/2 {
			backoff *= 2
		} else {
			backoff = c.settings.ReconnectMaxBackoff
		}
	}
}

func (c *Client) connectOnce(parent context.Context) (bool, error) {
	if c.tracing != nil && c.tracing.Enabled() {
		var span trace.Span
		parent, span = c.tracing.StartCheck(parent, "control_plane.stream")
		defer span.End()
	}
	dialCtx, cancelDial := context.WithTimeout(parent, c.settings.DialTimeout)
	conn, err := c.dialer(dialCtx, c.settings.Address)
	cancelDial()
	if err != nil {
		return false, err
	}
	defer conn.Close()
	streamCtx, cancelStream := context.WithCancel(parent)
	defer cancelStream()
	stream, err := cpb.NewConfigurationServiceClient(conn).Sync(streamCtx)
	if err != nil {
		return false, err
	}
	current := c.store.Active()
	revision := ""
	if current != nil {
		revision = current.Revision
	}
	if err := stream.Send(&cpb.SyncRequest{Payload: &cpb.SyncRequest_Registration{Registration: &cpb.Registration{InstanceId: c.settings.InstanceID, ProtocolVersion: ProtocolVersion, AppliedRevision: revision}}}); err != nil {
		return false, err
	}
	responses := make(chan *cpb.SyncRequest, c.settings.AckQueueCapacity)
	senderDone := make(chan struct{})
	go func() {
		defer close(senderDone)
		for {
			select {
			case <-streamCtx.Done():
				return
			case msg := <-responses:
				if err := stream.Send(msg); err != nil {
					cancelStream()
					return
				}
			}
		}
	}()
	defer func() { cancelStream(); <-senderDone }()
	c.store.SetConnected(true)
	if c.metrics != nil {
		c.metrics.Connected.Set(1)
	}
	var lastSequence uint64
	for {
		message, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return true, nil
			}
			return true, err
		}
		snapshot := message.GetSnapshot()
		if snapshot == nil {
			if message.GetHeartbeat() != nil {
				continue
			}
			return true, errors.New("unsupported server message")
		}
		started := time.Now()
		if c.metrics != nil {
			c.metrics.Received.Inc()
		}
		if snapshot.Sequence <= lastSequence {
			c.metrics.ObserveApply("rejected", "protocol", time.Since(started))
			if !c.queue(streamCtx, responses, nack(snapshot, "protocol")) {
				return true, streamCtx.Err()
			}
			continue
		}
		lastSequence = snapshot.Sequence
		var validationSpan trace.Span
		if c.tracing != nil && c.tracing.Enabled() {
			_, validationSpan = c.tracing.StartCheck(streamCtx, "control_plane.snapshot.validate")
		}
		computed, err := Revision(snapshot.Configuration)
		if validationSpan != nil {
			validationSpan.End()
		}
		if err != nil || computed != snapshot.Revision {
			c.metrics.ObserveApply("rejected", "validation", time.Since(started))
			if !c.queue(streamCtx, responses, nack(snapshot, "validation")) {
				return true, streamCtx.Err()
			}
			continue
		}
		dynamic, err := FromProto(snapshot.Configuration)
		if err != nil {
			c.metrics.ObserveApply("rejected", "validation", time.Since(started))
			if !c.queue(streamCtx, responses, nack(snapshot, "validation")) {
				return true, streamCtx.Err()
			}
			continue
		}
		changed, err := c.store.ApplyContext(streamCtx, dynamic, snapshot.Revision)
		if err != nil {
			c.metrics.ObserveApply("rejected", "dependency", time.Since(started))
			if !c.queue(streamCtx, responses, nack(snapshot, "dependency")) {
				return true, streamCtx.Err()
			}
			c.logger.Warn("snapshot rejected", "reason", "dependency")
			continue
		}
		if !c.queue(streamCtx, responses, &cpb.SyncRequest{Payload: &cpb.SyncRequest_Ack{Ack: &cpb.Acknowledgement{Sequence: snapshot.Sequence, Revision: snapshot.Revision}}}) {
			return true, streamCtx.Err()
		}
		if changed {
			c.metrics.ObserveApply("success", "none", time.Since(started))
		} else {
			c.metrics.ObserveApply("unchanged", "none", time.Since(started))
		}
		if c.metrics != nil {
			c.metrics.LastSuccess.SetToCurrentTime()
		}
		if changed {
			c.logger.Info("snapshot applied", "revision", snapshot.Revision, "sequence", snapshot.Sequence)
		}
	}
}

func (c *Client) queue(ctx context.Context, channel chan<- *cpb.SyncRequest, message *cpb.SyncRequest) bool {
	select {
	case channel <- message:
		return true
	case <-ctx.Done():
		return false
	}
}

func nack(snapshot *cpb.ConfigurationSnapshot, reason string) *cpb.SyncRequest {
	revision := snapshot.Revision
	if !safeRevision.MatchString(revision) {
		revision = ""
	}
	return &cpb.SyncRequest{Payload: &cpb.SyncRequest_Nack{Nack: &cpb.Rejection{Sequence: snapshot.Sequence, Revision: revision, ReasonCode: reason, Message: "snapshot rejected"}}}
}
