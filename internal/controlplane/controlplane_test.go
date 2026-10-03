package controlplane

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/auth"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"github.com/Nuryanfa/AegisGate/internal/ratelimit"
	"github.com/Nuryanfa/AegisGate/internal/router"
	"github.com/Nuryanfa/AegisGate/internal/waf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func testDynamic(upstream string) config.Dynamic {
	policy, _ := auth.NewPolicy("public", nil)
	return config.Dynamic{Routes: []router.Route{{ID: "users", PathPrefix: "/api/users", Upstream: upstream, Timeout: time.Second, Auth: policy}}}
}
func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRevisionIsCanonicalAndRoundTrips(t *testing.T) {
	first := testDynamic("http://localhost:8081")
	key, _ := auth.NewKey("client", "0000000000000000000000000000000000000000000000000000000000000000", []string{"b", "a"})
	first.APIKeys = []auth.Key{key}
	wire, err := ToProto(first)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := Revision(wire)
	if err != nil {
		t.Fatal(err)
	}
	wire.ApiClients[0].Scopes = []string{"a", "b"}
	second, err := Revision(wire)
	if err != nil {
		t.Fatal(err)
	}
	if revision != second {
		t.Fatalf("ordering changed revision: %s != %s", revision, second)
	}
	decoded, err := FromProto(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Routes) != 1 || decoded.Routes[0].Upstream != first.Routes[0].Upstream {
		t.Fatal("round trip changed route")
	}
	wire.Routes[0].Upstream = "http://localhost:8082"
	third, err := Revision(wire)
	if err != nil {
		t.Fatal(err)
	}
	if third == revision {
		t.Fatal("content change did not change revision")
	}
	wire.Routes[0].Auth = nil
	if _, err := FromProto(wire); err == nil {
		t.Fatal("missing auth accepted")
	}
}

func TestServerStreamsLatestSnapshotToMultipleClients(t *testing.T) {
	initial := testDynamic("http://localhost:8081")
	server, err := NewServer(initial, 2, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer(grpc.MaxRecvMsgSize(4096))
	cpb.RegisterConfigurationServiceServer(grpcServer, server)
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()
	connect := func(instance string) (cpb.ConfigurationService_SyncClient, *grpc.ClientConn) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		if err != nil {
			t.Fatal(err)
		}
		stream, err := cpb.NewConfigurationServiceClient(conn).Sync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Send(&cpb.SyncRequest{Payload: &cpb.SyncRequest_Registration{Registration: &cpb.Registration{InstanceId: instance, ProtocolVersion: ProtocolVersion}}}); err != nil {
			t.Fatal(err)
		}
		return stream, conn
	}
	a, connA := connect("gateway-a")
	defer connA.Close()
	b, connB := connect("gateway-b")
	defer connB.Close()
	for _, stream := range []cpb.ConfigurationService_SyncClient{a, b} {
		message, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if message.GetSnapshot().Revision != server.Revision() {
			t.Fatal("wrong initial snapshot")
		}
	}
	if changed, err := server.Publish(initial); err != nil || changed {
		t.Fatalf("identical publish: %v %v", changed, err)
	}
	updated := testDynamic("http://localhost:8082")
	if changed, err := server.Publish(updated); err != nil || !changed {
		t.Fatalf("changed publish: %v %v", changed, err)
	}
	for _, stream := range []cpb.ConfigurationService_SyncClient{a, b} {
		message, err := stream.Recv()
		if err != nil {
			t.Fatal(err)
		}
		if message.GetSnapshot().Sequence != 2 || message.GetSnapshot().Revision != server.Revision() {
			t.Fatal("wrong update")
		}
	}
	c, connC := connect("gateway-c")
	defer connC.Close()
	if _, err := c.Recv(); err == nil {
		t.Fatal("capacity exceeded but stream remained open")
	}
}

func TestAtomicStoreKeepsInflightHandler(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.Write([]byte("old")) }))
	defer old.Close()
	newer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("new")) }))
	defer newer.Close()
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(testDynamic(old.URL), "old")
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial, compiler, nil)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		response := httptest.NewRecorder()
		store.ServeHTTP(response, httptest.NewRequest("GET", "/api/users", nil))
		if response.Body.String() != "old" {
			t.Errorf("inflight=%q", response.Body.String())
		}
	}()
	<-entered
	if _, err := store.Apply(testDynamic(newer.URL), "new"); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	store.ServeHTTP(response, httptest.NewRequest("GET", "/api/users", nil))
	if response.Body.String() != "new" {
		t.Fatalf("new request=%q", response.Body.String())
	}
	close(release)
	wg.Wait()
	if _, err := store.Apply(testDynamic("ftp://invalid"), "bad"); err == nil {
		t.Fatal("invalid update accepted")
	}
	if store.Active().Revision != "new" {
		t.Fatal("invalid update replaced runtime")
	}
}

func TestClientAppliesRemoteSnapshotAndStops(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer upstream.Close()
	dynamic := testDynamic(upstream.URL)
	server, err := NewServer(dynamic, 1, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	cpb.RegisterConfigurationServiceServer(grpcServer, server)
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(testDynamic("http://localhost:1"), strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	settings := config.ControlPlaneConfig{Address: "bufnet:1", InstanceID: "gateway-a", StartupPolicy: "require_remote", StalePolicy: "serve", DialTimeout: time.Second, InitialSyncTimeout: time.Second, ReconnectMinBackoff: 10 * time.Millisecond, ReconnectMaxBackoff: 100 * time.Millisecond, MaxReceiveBytes: 1 << 20, AckQueueCapacity: 2, ShutdownTimeout: time.Second}
	store := NewStore(initial, compiler, &settings)
	if store.Ready() {
		t.Fatal("remote-required store started ready")
	}
	client, err := NewClient(settings, store, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	client.dialer = func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { client.Run(ctx); close(done) }()
	deadline := time.After(2 * time.Second)
	for !store.Ready() {
		select {
		case <-deadline:
			t.Fatal("remote snapshot not applied")
		case <-time.After(5 * time.Millisecond):
		}
	}
	if store.Active().Revision != server.Revision() {
		t.Fatal("revision mismatch")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client goroutine did not stop")
	}
}

func TestDependencyCompatibilityAndStalePolicies(t *testing.T) {
	d := testDynamic("http://localhost:8081")
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(d, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	rate, err := ratelimit.NewPolicy(5, 1, "deny")
	if err != nil {
		t.Fatal(err)
	}
	d.Routes[0].RateLimit = &rate
	if _, err := compiler.Compile(d, "rate"); err == nil {
		t.Fatal("missing Redis limiter accepted")
	}
	d.Routes[0].RateLimit = nil
	wafPolicy, err := waf.NewPolicy("audit", "core-v1", 5, waf.Inspection{Query: true, MaxQueryBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	d.Routes[0].WAF = &wafPolicy
	if _, err := compiler.Compile(d, "waf"); err == nil {
		t.Fatal("missing WAF event pipeline accepted")
	}
	d.Routes[0].WAF = nil
	d.Routes[0].Timeout = 2 * time.Second
	if _, err := compiler.Compile(d, "timeout"); err == nil {
		t.Fatal("route timeout >= write timeout accepted")
	}
	for _, policy := range []string{"serve", "deny"} {
		t.Run(policy, func(t *testing.T) {
			settings := &config.ControlPlaneConfig{StartupPolicy: "use_bootstrap", StalePolicy: policy, StaleAfter: 5 * time.Millisecond}
			store := NewStore(initial, compiler, settings)
			if !store.Ready() {
				t.Fatal("bootstrap not ready")
			}
			time.Sleep(10 * time.Millisecond)
			if store.Ready() != (policy == "serve") {
				t.Fatalf("readiness for %s incorrect", policy)
			}
			if policy == "deny" {
				response := httptest.NewRecorder()
				store.ServeHTTP(response, httptest.NewRequest("GET", "/api/users", nil))
				if response.Code != 503 || !strings.Contains(response.Body.String(), "CONFIG_STALE") {
					t.Fatalf("stale response: %d %s", response.Code, response.Body.String())
				}
			}
		})
	}
}

func TestReloadKeepsLastKnownGoodAndMessageLimit(t *testing.T) {
	server, err := NewServer(testDynamic("http://localhost:8081"), 2, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := server.SetMessageLimit(1024); err != nil {
		t.Fatal(err)
	}
	initial := server.Revision()
	path := filepath.Join(t.TempDir(), "snapshot.yaml")
	if err := os.WriteFile(path, []byte("routes: [broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Reload(path); err == nil {
		t.Fatal("invalid reload accepted")
	}
	if server.Revision() != initial {
		t.Fatal("invalid reload changed revision")
	}
	valid := []byte("routes:\n  - id: users\n    path_prefix: /api/users\n    upstream: http://localhost:8082\n    timeout: 1s\n    auth:\n      mode: public\n")
	if err := os.WriteFile(path, valid, 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := server.Reload(path)
	if err != nil || !changed {
		t.Fatalf("valid reload: %v %v", changed, err)
	}
	if server.Revision() == initial {
		t.Fatal("revision did not change")
	}
	if changed, err := server.Reload(path); err != nil || changed {
		t.Fatalf("identical reload: %v %v", changed, err)
	}
	tooLarge := testDynamic("http://localhost:8083/" + strings.Repeat("a", 1500))
	if _, err := server.Publish(tooLarge); err == nil {
		t.Fatal("oversized publication accepted")
	}
}

func TestServerConfigRejectsInsecureProductionAndUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-plane.yaml")
	base := "environment: production\naddress: 127.0.0.1:8443\nsnapshot_file: snapshot.yaml\nmax_clients: 2\nmax_message_bytes: 2097152\nshutdown_timeout: 5s\ntls:\n  enabled: false\n"
	if err := os.WriteFile(path, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("insecure production accepted")
	}
	if err := os.WriteFile(path, []byte(strings.Replace(base, "production", "development", 1)+"surprise: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestLatestSnapshotWinsWithoutBlockingPublisher(t *testing.T) {
	server, err := NewServer(testDynamic("http://localhost:8081"), 1, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	slow := &subscriber{latest: make(chan publication, 1)}
	server.clients[slow] = struct{}{}
	started := time.Now()
	for i := 0; i < 100; i++ {
		candidate := testDynamic(fmt.Sprintf("http://localhost:%d", 9000+i))
		if _, err := server.Publish(candidate); err != nil {
			t.Fatal(err)
		}
	}
	if time.Since(started) > time.Second {
		t.Fatal("slow client blocked publication")
	}
	if len(slow.latest) != 1 {
		t.Fatalf("pending snapshots=%d, want 1", len(slow.latest))
	}
	latest := <-slow.latest
	if latest.revision != server.Revision() {
		t.Fatal("client did not retain latest revision")
	}
}

func TestConcurrentRequestsDuringRepeatedAtomicSwaps(t *testing.T) {
	upstreamA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("a")) }))
	defer upstreamA.Close()
	upstreamB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("b")) }))
	defer upstreamB.Close()
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(testDynamic(upstreamA.URL), "a")
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(initial, compiler, nil)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				response := httptest.NewRecorder()
				store.ServeHTTP(response, httptest.NewRequest("GET", "/api/users", nil))
				body := response.Body.String()
				if response.Code != 200 || (body != "a" && body != "b") {
					t.Errorf("partial runtime: %d %q", response.Code, body)
					return
				}
			}
		}()
	}
	for i := 0; i < 100; i++ {
		url := upstreamA.URL
		if i%2 == 1 {
			url = upstreamB.URL
		}
		if _, err := store.Apply(testDynamic(url), fmt.Sprintf("revision-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

type reorderedService struct {
	cpb.UnimplementedConfigurationServiceServer
	first, second *cpb.ConfigurationSnapshot
	nack          chan *cpb.Rejection
}

func (s *reorderedService) Sync(stream cpb.ConfigurationService_SyncServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	for _, snapshot := range []*cpb.ConfigurationSnapshot{s.first, s.second} {
		if err := stream.Send(&cpb.SyncResponse{Payload: &cpb.SyncResponse_Snapshot{Snapshot: snapshot}}); err != nil {
			return err
		}
	}
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if nack := message.GetNack(); nack != nil {
			s.nack <- nack
			return nil
		}
	}
}

func TestReorderedSequenceCannotReplaceRuntime(t *testing.T) {
	first := testDynamic("http://localhost:8081")
	second := testDynamic("http://localhost:8082")
	firstProto, _ := ToProto(first)
	firstRevision, _ := Revision(firstProto)
	secondProto, _ := ToProto(second)
	secondRevision, _ := Revision(secondProto)
	service := &reorderedService{first: &cpb.ConfigurationSnapshot{Sequence: 2, Revision: firstRevision, Configuration: firstProto}, second: &cpb.ConfigurationSnapshot{Sequence: 1, Revision: secondRevision, Configuration: secondProto}, nack: make(chan *cpb.Rejection, 1)}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	cpb.RegisterConfigurationServiceServer(grpcServer, service)
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(testDynamic("http://localhost:1"), strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	settings := config.ControlPlaneConfig{Address: "bufnet:1", InstanceID: "gateway-a", StartupPolicy: "require_remote", StalePolicy: "serve", DialTimeout: time.Second, InitialSyncTimeout: time.Second, ReconnectMinBackoff: time.Second, ReconnectMaxBackoff: time.Second, MaxReceiveBytes: 1 << 20, AckQueueCapacity: 2}
	store := NewStore(initial, compiler, &settings)
	client, err := NewClient(settings, store, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	client.dialer = func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { client.Run(ctx); close(done) }()
	select {
	case nack := <-service.nack:
		if nack.ReasonCode != "protocol" || nack.Sequence != 1 {
			t.Fatalf("unexpected NACK: %#v", nack)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reordered snapshot was not rejected")
	}
	if store.Active().Revision != firstRevision {
		t.Fatal("reordered snapshot replaced current runtime")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client did not stop")
	}
}

type restartingService struct {
	cpb.UnimplementedConfigurationServiceServer
	first, second *cpb.ConfigurationSnapshot
	connections   atomic.Int32
	secondAck     chan struct{}
}

func (s *restartingService) Sync(stream cpb.ConfigurationService_SyncServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	n := s.connections.Add(1)
	snapshot := s.first
	if n > 1 {
		snapshot = s.second
	}
	if err := stream.Send(&cpb.SyncResponse{Payload: &cpb.SyncResponse_Snapshot{Snapshot: snapshot}}); err != nil {
		return err
	}
	for {
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if ack := message.GetAck(); ack != nil {
			if n == 2 {
				close(s.secondAck)
			}
			return nil
		}
	}
}

func TestReconnectAcceptsNewStreamSequenceReset(t *testing.T) {
	first := testDynamic("http://localhost:8081")
	second := testDynamic("http://localhost:8082")
	a, _ := ToProto(first)
	ar, _ := Revision(a)
	b, _ := ToProto(second)
	br, _ := Revision(b)
	service := &restartingService{first: &cpb.ConfigurationSnapshot{Sequence: 10, Revision: ar, Configuration: a}, second: &cpb.ConfigurationSnapshot{Sequence: 1, Revision: br, Configuration: b}, secondAck: make(chan struct{})}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	cpb.RegisterConfigurationServiceServer(grpcServer, service)
	go grpcServer.Serve(listener)
	defer grpcServer.Stop()
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(testDynamic("http://localhost:1"), strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	settings := config.ControlPlaneConfig{Address: "bufnet:1", InstanceID: "gateway-a", StartupPolicy: "require_remote", StalePolicy: "serve", DialTimeout: time.Second, InitialSyncTimeout: time.Second, ReconnectMinBackoff: 5 * time.Millisecond, ReconnectMaxBackoff: 20 * time.Millisecond, MaxReceiveBytes: 1 << 20, AckQueueCapacity: 2}
	store := NewStore(initial, compiler, &settings)
	client, err := NewClient(settings, store, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	client.dialer = func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { client.Run(ctx); close(done) }()
	select {
	case <-service.secondAck:
	case <-time.After(2 * time.Second):
		t.Fatal("reconnect did not ACK new stream")
	}
	if store.Active().Revision != br {
		t.Fatal("new stream sequence 1 was rejected")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client did not stop")
	}
}
