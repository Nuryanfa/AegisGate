package controlplane

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/test/bufconn"
)

// rpcEndSignal closes only after the wrapped instrumentation has processed End.
type rpcEndSignal struct {
	stats.Handler
	done chan struct{}
	once sync.Once
}

func (s *rpcEndSignal) HandleRPC(ctx context.Context, event stats.RPCStats) {
	s.Handler.HandleRPC(ctx, event)
	if _, ok := event.(*stats.End); ok {
		s.once.Do(func() { close(s.done) })
	}
}

func TestGRPCTraceContextPropagationAndPrivacy(t *testing.T) {
	options := observability.Options{ServiceName: "control-plane-test", Tracing: observability.TracingOptions{Enabled: true, SampleRatio: 1, ExportTimeout: time.Second, BatchTimeout: time.Millisecond, MaxQueueSize: 64, MaxExportBatchSize: 32}}
	clientExporter := tracetest.NewInMemoryExporter()
	serverExporter := tracetest.NewInMemoryExporter()
	clientTracing, err := observability.NewTracing(context.Background(), options, "test", clientExporter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := clientTracing.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown client tracing: %v", err)
		}
	})
	serverTracing, err := observability.NewTracing(context.Background(), options, "test", serverExporter)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := serverTracing.Shutdown(shutdownCtx); err != nil {
			t.Errorf("shutdown server tracing: %v", err)
		}
	})
	service, err := NewServer(testDynamic("http://do-not-record.example:8081"), 1, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	serverStats := &rpcEndSignal{Handler: serverTracing.GRPCServerHandler(), done: make(chan struct{})}
	clientStats := &rpcEndSignal{Handler: clientTracing.GRPCClientHandler(), done: make(chan struct{})}
	server := grpc.NewServer(grpc.StatsHandler(serverStats))
	cpb.RegisterConfigurationServiceServer(server, service)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	serveCompleted := false
	t.Cleanup(func() {
		server.Stop()
		listener.Close()
		if !serveCompleted {
			select {
			case <-serveDone:
			case <-time.After(2 * time.Second):
				t.Error("gRPC Serve did not finish during cleanup")
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	ctx, root := clientTracing.StartCheck(ctx, "test.control-plane.root")
	t.Cleanup(func() { root.End() })
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(clientStats), grpc.WithBlock())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	stream, err := cpb.NewConfigurationServiceClient(conn).Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&cpb.SyncRequest{Payload: &cpb.SyncRequest_Registration{Registration: &cpb.Registration{InstanceId: "gateway-test", ProtocolVersion: ProtocolVersion}}}); err != nil {
		t.Fatal(err)
	}
	if message, err := stream.Recv(); err != nil || message.GetSnapshot() == nil {
		t.Fatalf("snapshot: %v %v", message, err)
	}
	cancel()
	if err := conn.Close(); err != nil {
		t.Fatalf("close client connection: %v", err)
	}
	gracefulDone := make(chan struct{})
	go func() { server.GracefulStop(); close(gracefulDone) }()
	select {
	case <-gracefulDone:
	case <-time.After(2 * time.Second):
		server.Stop()
		select {
		case <-gracefulDone:
		case <-time.After(2 * time.Second):
			t.Error("gRPC GracefulStop remained blocked after forced stop")
		}
		t.Fatal("gRPC server did not gracefully stop after stream cancellation")
	}
	select {
	case err := <-serveDone:
		serveCompleted = true
		if err != nil {
			t.Fatalf("gRPC server exited with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("gRPC Serve did not return after graceful shutdown")
	}
	for _, endpoint := range []struct {
		name string
		done <-chan struct{}
	}{{"client", clientStats.done}, {"server", serverStats.done}} {
		select {
		case <-endpoint.done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s RPC instrumentation did not finish", endpoint.name)
		}
	}
	root.End()
	flushCtx, cancelFlush := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFlush()
	if err := clientTracing.ForceFlush(flushCtx); err != nil {
		t.Fatal(err)
	}
	if err := serverTracing.ForceFlush(flushCtx); err != nil {
		t.Fatal(err)
	}
	var clientRPC, serverRPC *tracetest.SpanStub
	clientCount, serverCount := 0, 0
	for _, span := range clientExporter.GetSpans() {
		if span.SpanKind == trace.SpanKindClient {
			clientCount++
			copy := span
			clientRPC = &copy
		}
	}
	for _, span := range serverExporter.GetSpans() {
		if span.SpanKind == trace.SpanKindServer {
			serverCount++
			copy := span
			serverRPC = &copy
		}
		for _, attribute := range span.Attributes {
			value := fmt.Sprint(attribute.Value)
			if strings.Contains(value, "do-not-record.example") || strings.Contains(value, service.Revision()) {
				t.Fatalf("snapshot data leaked into span attribute %s", attribute.Key)
			}
		}
	}
	if clientCount != 1 || serverCount != 1 || clientRPC == nil || serverRPC == nil {
		t.Fatalf("RPC spans client=%d server=%d", clientCount, serverCount)
	}
	if clientRPC.SpanContext.TraceID() != serverRPC.SpanContext.TraceID() || serverRPC.Parent.SpanID() != clientRPC.SpanContext.SpanID() || !serverRPC.Parent.IsRemote() {
		t.Fatal("server RPC span is not a remote child of the client RPC span")
	}
}

func TestDisabledGRPCTracingHasNoHandlers(t *testing.T) {
	tracing, err := observability.NewTracing(context.Background(), observability.Options{}, "dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tracing.Enabled() || tracing.GRPCClientHandler() != nil || tracing.GRPCServerHandler() != nil {
		t.Fatal("disabled tracing installed transport instrumentation")
	}
}
