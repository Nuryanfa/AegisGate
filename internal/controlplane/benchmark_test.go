package controlplane

import (
	"fmt"
	"testing"
	"time"

	cpb "github.com/Nuryanfa/AegisGate/api/controlplane/v1"
	"github.com/Nuryanfa/AegisGate/internal/config"
	"google.golang.org/protobuf/proto"
)

func benchmarkFixture(b *testing.B) (config.Dynamic, *Store, *cpb.DynamicConfiguration) {
	d := testDynamic("http://localhost:8081")
	compiler := Compiler{WriteTimeout: 2 * time.Second, Logger: testLogger()}
	initial, err := compiler.Compile(d, "bootstrap")
	if err != nil {
		b.Fatal(err)
	}
	p, err := ToProto(d)
	if err != nil {
		b.Fatal(err)
	}
	return d, NewStore(initial, compiler, nil), p
}

func BenchmarkAtomicRuntimeLoad(b *testing.B) {
	_, store, _ := benchmarkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if store.Active() == nil {
			b.Fatal("nil runtime")
		}
	}
}
func BenchmarkRuntimeCompilation(b *testing.B) {
	d, store, _ := benchmarkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.compiler.Compile(d, "candidate"); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkSnapshotApply(b *testing.B) {
	d, store, _ := benchmarkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.Apply(d, fmt.Sprintf("revision-%d", i)); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkCanonicalRevision(b *testing.B) {
	_, _, p := benchmarkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Revision(p); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkProtobufRoundTrip(b *testing.B) {
	_, _, p := benchmarkFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		raw, err := proto.Marshal(p)
		if err != nil {
			b.Fatal(err)
		}
		var decoded cpb.DynamicConfiguration
		if err := proto.Unmarshal(raw, &decoded); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkSnapshotFanout(b *testing.B) {
	d, _, _ := benchmarkFixture(b)
	server, err := NewServer(d, 64, testLogger())
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		client := &subscriber{latest: make(chan publication, 1)}
		server.clients[client] = struct{}{}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		candidate := testDynamic(fmt.Sprintf("http://localhost:%d", 8081+i%1000))
		if _, err := server.Publish(candidate); err != nil {
			b.Fatal(err)
		}
	}
}
