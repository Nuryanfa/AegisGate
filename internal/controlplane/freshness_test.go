package controlplane

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

func TestFreshnessUsesContactNotSnapshotAge(t *testing.T) {
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(testDynamic("http://localhost:8081"), "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range []string{"serve", "deny"} {
		t.Run(policy, func(t *testing.T) {
			settings := &config.ControlPlaneConfig{StartupPolicy: "use_bootstrap", StalePolicy: policy, StaleAfter: time.Minute}
			store := NewStore(initial, compiler, settings)
			var now atomic.Int64
			start := time.Now()
			now.Store(start.UnixNano())
			store.started = start
			store.now = func() time.Time { return time.Unix(0, now.Load()) }
			if _, err := store.Apply(testDynamic("http://localhost:8081"), "remote"); err != nil {
				t.Fatal(err)
			}
			snapshotTime := store.lastSuccess.Load()
			original := store.Active()
			store.SetConnected(true)
			for i := 1; i <= 5; i++ {
				now.Store(start.Add(time.Duration(i) * 30 * time.Second).UnixNano())
				store.RecordContact() // authenticated heartbeat
				if !store.Ready() || store.Active() != original || store.lastSuccess.Load() != snapshotTime {
					t.Fatal("healthy heartbeat changed runtime, snapshot time, or readiness")
				}
			}
			store.SetConnected(false)
			now.Store(start.Add(3*time.Minute + 29*time.Second).UnixNano())
			if !store.Ready() {
				t.Fatal("stale deadline elapsed too early")
			}
			now.Store(start.Add(3*time.Minute + 31*time.Second).UnixNano())
			if store.Ready() != (policy == "serve") {
				t.Fatal("stale policy ignored")
			}
			if policy == "deny" {
				response := httptest.NewRecorder()
				store.ServeHTTP(response, httptest.NewRequest("GET", "/api/users", nil))
				if response.Code != 503 || !strings.Contains(response.Body.String(), "CONFIG_STALE") {
					t.Fatalf("stale response: %d %s", response.Code, response.Body.String())
				}
			}
			store.SetConnected(true)
			store.RecordContact() // valid message on a reconnected stream
			if !store.Ready() || store.lastSuccess.Load() != snapshotTime {
				t.Fatal("reconnect did not clear stale state independently of snapshot time")
			}
		})
	}
}

type heartbeatService struct {
	cpb.UnimplementedConfigurationServiceServer
	snapshot *cpb.ConfigurationSnapshot
	advance  chan struct{}
	acked    chan uint64
}

func (s *heartbeatService) Sync(stream cpb.ConfigurationService_SyncServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := stream.Send(&cpb.SyncResponse{Payload: &cpb.SyncResponse_Snapshot{Snapshot: s.snapshot}}); err != nil {
		return err
	}
	if _, err := stream.Recv(); err != nil { // initial ACK
		return err
	}
	for sequence := uint64(2); sequence <= 3; sequence++ {
		select {
		case <-s.advance:
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
		if sequence == 2 {
			if err := stream.Send(&cpb.SyncResponse{Payload: &cpb.SyncResponse_Heartbeat{Heartbeat: &cpb.Heartbeat{}}}); err != nil {
				return err
			}
			continue
		}
		copy := proto.Clone(s.snapshot).(*cpb.ConfigurationSnapshot)
		copy.Sequence = sequence
		if err := stream.Send(&cpb.SyncResponse{Payload: &cpb.SyncResponse_Snapshot{Snapshot: copy}}); err != nil {
			return err
		}
		message, err := stream.Recv()
		if err != nil {
			return err
		}
		if message.GetAck() != nil {
			s.acked <- message.GetAck().Sequence
		}
	}
	<-stream.Context().Done()
	return nil
}

func TestHeartbeatAndUnchangedRevisionRefreshContactWithoutObservability(t *testing.T) {
	dynamic := testDynamic("http://localhost:8081")
	wire, _ := ToProto(dynamic)
	revision, _ := Revision(wire)
	service := &heartbeatService{snapshot: &cpb.ConfigurationSnapshot{Sequence: 1, Revision: revision, Configuration: wire}, advance: make(chan struct{}), acked: make(chan uint64, 1)}
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	cpb.RegisterConfigurationServiceServer(server, service)
	go server.Serve(listener)
	defer server.Stop()
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(dynamic, revision)
	if err != nil {
		t.Fatal(err)
	}
	settings := config.ControlPlaneConfig{Address: "bufnet:1", InstanceID: "gateway-a", StartupPolicy: "require_remote", StalePolicy: "deny", StaleAfter: time.Minute, DialTimeout: time.Second, InitialSyncTimeout: time.Second, ReconnectMinBackoff: time.Second, ReconnectMaxBackoff: time.Second, MaxReceiveBytes: 1 << 20, AckQueueCapacity: 2}
	store := NewStore(initial, compiler, &settings)
	var now atomic.Int64
	start := time.Now()
	now.Store(start.UnixNano())
	store.started = start
	store.now = func() time.Time { return time.Unix(0, now.Load()) }
	client, err := NewClient(settings, store, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	client.dialer = func(ctx context.Context, _ string) (*grpc.ClientConn, error) {
		return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { client.Run(ctx); close(done) }()
	deadline := time.After(2 * time.Second)
	for !store.Ready() {
		select {
		case <-deadline:
			t.Fatal("initial unchanged revision not accepted")
		case <-time.After(time.Millisecond):
		}
	}
	original := store.Active()
	snapshotTime := store.lastSuccess.Load()
	now.Store(start.Add(90 * time.Second).UnixNano())
	service.advance <- struct{}{}
	deadline = time.After(2 * time.Second)
	for store.lastContact.Load() < now.Load() {
		select {
		case <-deadline:
			t.Fatal("heartbeat did not refresh contact")
		case <-time.After(time.Millisecond):
		}
	}
	if !store.Ready() || store.Active() != original || store.lastSuccess.Load() != snapshotTime {
		t.Fatal("heartbeat did not preserve runtime and snapshot time")
	}
	now.Store(start.Add(3 * time.Minute).UnixNano())
	service.advance <- struct{}{}
	select {
	case sequence := <-service.acked:
		if sequence != 3 || store.Active() != original || store.lastContact.Load() != now.Load() {
			t.Fatal("unchanged snapshot ACK did not refresh contact")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("unchanged snapshot not ACKed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not stop")
	}
}
