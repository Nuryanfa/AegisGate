package controlplane

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/observability"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCTraceContextPropagationAndPrivacy(t *testing.T) {
	options := observability.Options{ServiceName: "control-plane-test", Tracing: observability.TracingOptions{Enabled: true, SampleRatio: 1, ExportTimeout: time.Second, BatchTimeout: time.Millisecond, MaxQueueSize: 64, MaxExportBatchSize: 32}}
	clientExporter := tracetest.NewInMemoryExporter()
	serverExporter := tracetest.NewInMemoryExporter()
	clientTracing, err := observability.NewTracing(context.Background(), options, "test", clientExporter)
	if err != nil {
		t.Fatal(err)
	}
	serverTracing, err := observability.NewTracing(context.Background(), options, "test", serverExporter)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewServer(testDynamic("http://do-not-record.example:8081"), 1, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.StatsHandler(serverTracing.GRPCServerHandler()))
	cpb.RegisterConfigurationServiceServer(server, service)
	go server.Serve(listener)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	ctx, root := clientTracing.StartCheck(ctx, "test.control-plane.root")
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithStatsHandler(clientTracing.GRPCClientHandler()), grpc.WithBlock())
	if err != nil {
		t.Fatal(err)
	}
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
	conn.Close()
	server.Stop()
	root.End()
	if err := clientTracing.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := serverTracing.ForceFlush(context.Background()); err != nil {
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
	if err := clientTracing.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := serverTracing.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
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
