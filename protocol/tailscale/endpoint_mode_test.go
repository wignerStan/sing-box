//go:build with_gvisor

package tailscale

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/tailscale/tsnet"
)

func TestSystemInterfaceEndpointDoesNotImplementPort(t *testing.T) {
	var endpoint adapter.Endpoint = &Endpoint{systemInterface: true}
	if _, loaded := endpoint.(tun.Port); loaded {
		t.Fatal("system-interface endpoint unexpectedly implements tun.Port")
	}
}

func TestUserspaceEndpointImplementsPort(t *testing.T) {
	var endpoint adapter.Endpoint = &userspaceEndpoint{Endpoint: &Endpoint{}}
	if _, loaded := endpoint.(tun.Port); !loaded {
		t.Fatal("userspace endpoint does not implement tun.Port")
	}
}

func TestUnwrapEndpoint(t *testing.T) {
	base := &Endpoint{}
	for _, endpoint := range []adapter.Endpoint{base, &userspaceEndpoint{Endpoint: base}} {
		unwrapped, loaded := unwrapEndpoint(endpoint)
		if !loaded || unwrapped != base {
			t.Fatalf("unwrapEndpoint(%T) = (%p, %v)", endpoint, unwrapped, loaded)
		}
	}
}

func TestUserspaceEndpointProvidesPacketHandler(t *testing.T) {
	base := &Endpoint{}
	userspace := &userspaceEndpoint{Endpoint: base}
	base.userspaceHandler = userspace
	if base.userspaceHandler != userspace {
		t.Fatal("userspace packet handler was not retained by the base endpoint")
	}
}

func TestSystemInterfaceSelectsPureSystemDataPlane(t *testing.T) {
	endpoint := &Endpoint{
		systemInterface: true,
		server:          &tsnet.Server{},
	}
	endpoint.configureDataPlane()
	if endpoint.server.DataPlaneMode != tsnet.DataPlaneSystem {
		t.Fatalf("DataPlaneMode = %v, want %v", endpoint.server.DataPlaneMode, tsnet.DataPlaneSystem)
	}
}
