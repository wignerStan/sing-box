//go:build linux && !android && with_dae

package dae

import (
	"context"
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/ebpfinbound"
)

type testGeneration struct{ port uint16 }

func (*testGeneration) TCP4() net.Listener { return nil }
func (*testGeneration) TCP6() net.Listener { return nil }
func (*testGeneration) UDP() *net.UDPConn  { return nil }
func (g *testGeneration) Port() uint16     { return g.port }
func (*testGeneration) Close() error       { return nil }

type testRuntime struct {
	commits []ebpfinbound.Generation
}

func (*testRuntime) OpenGeneration(context.Context, uint16) (ebpfinbound.Generation, error) {
	return nil, nil
}
func (*testRuntime) CloneGeneration(context.Context, ebpfinbound.Generation) (ebpfinbound.Generation, error) {
	return nil, nil
}
func (r *testRuntime) CommitGeneration(_ context.Context, generation ebpfinbound.Generation) error {
	r.commits = append(r.commits, generation)
	return nil
}
func (*testRuntime) LookupMetadata(context.Context, ebpfinbound.Flow) (ebpfinbound.Metadata, bool, error) {
	return ebpfinbound.Metadata{}, false, nil
}
func (*testRuntime) OutputMark() uint32 { return ebpfinbound.DefaultOutputMark }
func (*testRuntime) Close() error       { return nil }

func TestNormalizeCaptureConfig(t *testing.T) {
	config := normalizeCaptureConfig(ebpfinbound.CaptureConfig{
		WANInterfaces: []string{"eth1", "", " eth0 ", "eth1"},
	})
	if len(config.WANInterfaces) != 2 || config.WANInterfaces[0] != "eth0" || config.WANInterfaces[1] != "eth1" {
		t.Fatalf("WANInterfaces = %v", config.WANInterfaces)
	}
	if config.TProxyPort != ebpfinbound.DefaultTProxyPort {
		t.Fatalf("TProxyPort = %d", config.TProxyPort)
	}
	if config.OutputMark != ebpfinbound.DefaultOutputMark {
		t.Fatalf("OutputMark = %#x", config.OutputMark)
	}
}

func TestRuntimeCoordinatorRepublishesSurvivingGeneration(t *testing.T) {
	runtime := &testRuntime{}
	firstGeneration := &testGeneration{port: 1}
	secondGeneration := &testGeneration{port: 1}
	first := &runtimeMember{generation: firstGeneration}
	second := &runtimeMember{generation: secondGeneration}
	coordinator := &runtimeCoordinator{lease: &runtimeLease{
		runtime: runtime,
		active:  second,
		members: map[*runtimeMember]struct{}{
			first:  {},
			second: {},
		},
	}}

	if err, closeRuntime := coordinator.release(second); err != nil || closeRuntime != nil {
		t.Fatalf("release active generation = (%v, %T)", err, closeRuntime)
	}
	if len(runtime.commits) != 1 || runtime.commits[0] != firstGeneration {
		t.Fatalf("commits = %v", runtime.commits)
	}
	if coordinator.lease.active != first {
		t.Fatal("surviving generation was not made active")
	}
	if err, closeRuntime := coordinator.release(first); err != nil || closeRuntime != runtime {
		t.Fatalf("release final generation = (%v, %T)", err, closeRuntime)
	}
	if coordinator.lease != nil {
		t.Fatal("runtime lease was not cleared")
	}
}
