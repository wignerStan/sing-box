//go:build with_gvisor

package tailscale

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/tailscale/tsnet"
)

// userspaceEndpoint adds the packet-level tun.Port capability used by
// sing-box flow routing. A system-interface endpoint intentionally does not
// implement tun.Port: packets must traverse the real OS TUN exactly once.
type userspaceEndpoint struct {
	*Endpoint
}

// endpointCoreProvider is sealed to this package. It lets package-local
// integrations reach the shared endpoint owner without teaching each caller
// about every mode-specific wrapper.
type endpointCoreProvider interface {
	endpointCore() *Endpoint
}

func (t *Endpoint) endpointCore() *Endpoint {
	return t
}

func endpointCoreOf(raw adapter.Endpoint) (*Endpoint, bool) {
	provider, loaded := raw.(endpointCoreProvider)
	if !loaded {
		return nil, false
	}
	return provider.endpointCore(), true
}

func (t *Endpoint) configureDataPlane() {
	if t.systemInterface {
		t.server.DataPlaneMode = tsnet.DataPlaneSystem
	}
}
