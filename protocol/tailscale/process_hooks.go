//go:build with_gvisor

package tailscale

import (
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/net/netns"
)

var tailscaleProcessHookRegistry struct {
	sync.Mutex
	lease *processHookLease
}

// processHookLease gives one endpoint explicit ownership of Tailscale's
// process-global network hooks. Releasing a stale or foreign lease cannot
// clear hooks installed by the current owner.
type processHookLease struct {
	owner          *Endpoint
	released       bool
	interfaceProps bool
}

func acquireProcessHookLease(owner *Endpoint) (*processHookLease, error) {
	if owner == nil {
		return nil, E.New("missing Tailscale process-hook owner")
	}
	tailscaleProcessHookRegistry.Lock()
	defer tailscaleProcessHookRegistry.Unlock()
	if current := tailscaleProcessHookRegistry.lease; current != nil && !current.released {
		return nil, E.New("only one Tailscale endpoint can be active per sing-box process while Tailscale socket hooks are process-global")
	}
	lease := &processHookLease{owner: owner}
	tailscaleProcessHookRegistry.lease = lease
	return lease, nil
}

// setSystemInterface associates the real OS TUN with the same exclusive lease
// as the socket hooks. A stale lease cannot replace a newer endpoint's identity.
func (l *processHookLease) setSystemInterface(name string, index int) error {
	tailscaleProcessHookRegistry.Lock()
	defer tailscaleProcessHookRegistry.Unlock()
	if l == nil || l.released || tailscaleProcessHookRegistry.lease != l {
		return E.New("inactive Tailscale process-hook lease")
	}
	if name == "" || index <= 0 {
		return E.New("invalid Tailscale system-interface identity")
	}
	netmon.SetTailscaleInterfaceProps(name, index)
	l.interfaceProps = true
	return nil
}

func (l *processHookLease) Release() {
	if l == nil {
		return
	}
	tailscaleProcessHookRegistry.Lock()
	defer tailscaleProcessHookRegistry.Unlock()
	if l.released {
		return
	}
	l.released = true
	if tailscaleProcessHookRegistry.lease != l {
		return
	}
	if l.interfaceProps {
		netmon.SetTailscaleInterfaceProps("", 0)
	}
	netmon.RegisterInterfaceGetter(nil)
	netns.SetControlFunc(nil)
	netns.SetListenPacketFunc(nil)
	tailscaleProcessHookRegistry.lease = nil
}

func (t *Endpoint) acquireProcessHooks() error {
	if t.processHooks != nil {
		return nil
	}
	lease, err := acquireProcessHookLease(t)
	if err != nil {
		return err
	}
	t.processHooks = lease
	return nil
}

func (t *Endpoint) releaseProcessHooks() {
	lease := t.processHooks
	t.processHooks = nil
	lease.Release()
}
