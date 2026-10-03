package controlplane

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"regexp"
	"sync"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var safeInstanceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
var safeRevision = regexp.MustCompile(`^[a-f0-9]{64}$`)

type publication struct {
	revision  string
	content   *cpb.DynamicConfiguration
	generated time.Time
}
type subscriber struct{ latest chan publication }

// Server is one in-memory authority. Publication never waits for a network client.
type Server struct {
	cpb.UnimplementedConfigurationServiceServer
	mu              sync.Mutex
	current         publication
	clients         map[*subscriber]struct{}
	maxClients      int
	logger          *slog.Logger
	metrics         *observability.ControlPlaneMetrics
	tracing         *observability.Tracing
	maxMessageBytes int
}

func (s *Server) SetMetrics(metrics *observability.ControlPlaneMetrics) { s.metrics = metrics }
func (s *Server) SetTracing(tracing *observability.Tracing)             { s.tracing = tracing }
func (s *Server) SetMessageLimit(limit int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit < 1024 || limit > 2<<20 || proto.Size(s.current.content)+256 > limit {
		return errors.New("initial snapshot exceeds gRPC message limit")
	}
	s.maxMessageBytes = limit
	return nil
}

func NewServer(initial config.Dynamic, maxClients int, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if maxClients < 1 || maxClients > 1024 {
		return nil, errors.New("maxClients must be 1-1024")
	}
	p, err := ToProto(initial)
	if err != nil {
		return nil, err
	}
	rev, err := Revision(p)
	if err != nil {
		return nil, err
	}
	return &Server{current: publication{revision: rev, content: p, generated: time.Now().UTC()}, clients: make(map[*subscriber]struct{}), maxClients: maxClients, logger: logger}, nil
}

func (s *Server) Revision() string { s.mu.Lock(); defer s.mu.Unlock(); return s.current.revision }
func (s *Server) ClientCount() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.clients) }

func (s *Server) Publish(d config.Dynamic) (bool, error) {
	p, err := ToProto(d)
	if err != nil {
		return false, err
	}
	rev, err := Revision(p)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxMessageBytes > 0 && proto.Size(p)+256 > s.maxMessageBytes {
		return false, errors.New("snapshot exceeds gRPC message limit")
	}
	if rev == s.current.revision {
		return false, nil
	}
	s.current = publication{revision: rev, content: p, generated: time.Now().UTC()}
	if s.metrics != nil {
		s.metrics.Published.Inc()
	}
	for client := range s.clients {
		select {
		case client.latest <- s.current:
		default:
			select {
			case <-client.latest:
			default:
			}
			select {
			case client.latest <- s.current:
			default:
			}
		}
	}
	return true, nil
}

// Reload parses and validates before publishing, retaining the current snapshot on error.
func (s *Server) Reload(path string) (bool, error) {
	if s.tracing != nil && s.tracing.Enabled() {
		var span trace.Span
		_, span = s.tracing.StartCheck(context.Background(), "control_plane.reload")
		defer span.End()
	}
	d, err := config.ReadDynamic(path)
	if err != nil {
		return false, err
	}
	return s.Publish(d)
}

func (s *Server) Sync(stream cpb.ConfigurationService_SyncServer) error {
	first, err := stream.Recv()
	if err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			return err
		}
		return status.Error(codes.InvalidArgument, "registration required")
	}
	registration := first.GetRegistration()
	if registration == nil || !safeInstanceID.MatchString(registration.InstanceId) || (registration.AppliedRevision != "" && !safeRevision.MatchString(registration.AppliedRevision)) {
		return status.Error(codes.InvalidArgument, "valid registration required")
	}
	if registration.ProtocolVersion != ProtocolVersion {
		return status.Error(codes.FailedPrecondition, "unsupported protocol version")
	}
	client := &subscriber{latest: make(chan publication, 1)}
	s.mu.Lock()
	if len(s.clients) >= s.maxClients {
		s.mu.Unlock()
		return status.Error(codes.ResourceExhausted, "control-plane client capacity reached")
	}
	s.clients[client] = struct{}{}
	if s.metrics != nil {
		s.metrics.Clients.Set(float64(len(s.clients)))
	}
	client.latest <- s.current
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.clients, client)
		if s.metrics != nil {
			s.metrics.Clients.Set(float64(len(s.clients)))
		}
		s.mu.Unlock()
	}()
	received := make(chan *cpb.SyncRequest, 1)
	recvErr := make(chan error, 1)
	go func() {
		for {
			message, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case received <- message:
			case <-stream.Context().Done():
				return
			}
		}
	}()
	var sequence uint64
	sent := make(map[uint64]string)
	heartbeat := time.NewTicker(config.ControlPlaneHeartbeatInterval)
	defer heartbeat.Stop()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case update := <-client.latest:
			sequence++
			sent[sequence] = update.revision
			if sequence > 64 {
				delete(sent, sequence-64)
			}
			message := &cpb.SyncResponse{Payload: &cpb.SyncResponse_Snapshot{Snapshot: &cpb.ConfigurationSnapshot{Sequence: sequence, Revision: update.revision, GeneratedAt: timestamppb.New(update.generated), Configuration: update.content}}}
			if err := stream.Send(message); err != nil {
				return err
			}
		case msg := <-received:
			if ack := msg.GetAck(); ack != nil {
				if ack.Sequence == 0 || sent[ack.Sequence] != ack.Revision {
					return status.Error(codes.InvalidArgument, "ACK does not match latest snapshot")
				}
				s.logger.Info("snapshot acknowledged", "instance_id", registration.InstanceId, "sequence", ack.Sequence, "revision", ack.Revision)
				if s.metrics != nil {
					s.metrics.ACKs.Inc()
				}
			} else if nack := msg.GetNack(); nack != nil {
				if nack.Sequence == 0 || sent[nack.Sequence] != nack.Revision || len(nack.Message) > 128 {
					return status.Error(codes.InvalidArgument, "NACK is invalid")
				}
				s.logger.Warn("snapshot rejected", "instance_id", registration.InstanceId, "sequence", nack.Sequence, "revision", nack.Revision, "reason", boundedReason(nack.ReasonCode))
				if s.metrics != nil {
					s.metrics.NACKs.Inc()
				}
			} else if msg.GetHeartbeat() == nil {
				return status.Error(codes.InvalidArgument, "unsupported client message")
			}
		case <-heartbeat.C:
			if err := stream.Send(&cpb.SyncResponse{Payload: &cpb.SyncResponse_Heartbeat{Heartbeat: &cpb.Heartbeat{}}}); err != nil {
				return err
			}
		}
	}
}

func boundedReason(reason string) string {
	switch reason {
	case "validation", "dependency", "stale", "protocol", "capacity":
		return reason
	}
	return "validation"
}

func (s *Server) WaitForClients(ctx context.Context, n int) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if s.ClientCount() >= n {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
