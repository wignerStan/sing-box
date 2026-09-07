package tun

import (
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	stun "github.com/sagernet/sing-tun"
)

type closeTestNetworkManager struct {
	adapter.NetworkManager
	mark            uint32
	unregisterCount int
}

type closeTestAutoRedirect struct {
	err error
}

func (*closeTestAutoRedirect) Start() error                 { return nil }
func (r *closeTestAutoRedirect) Close() error               { return r.err }
func (*closeTestAutoRedirect) UpdateRouteAddressSet() error { return nil }

func (m *closeTestNetworkManager) UnregisterAutoRedirectOutputMark(mark uint32) error {
	if mark == 0 || m.mark != mark {
		return errors.New("output mark ownership mismatch")
	}
	m.mark = 0
	m.unregisterCount++
	return nil
}

func TestCloseReleasesAutoRedirectOutputMarkOnce(t *testing.T) {
	manager := &closeTestNetworkManager{mark: 0x100}
	inbound := &Inbound{
		networkManager:             manager,
		tunOptions:                 stun.Options{AutoRedirectOutputMark: 0x100},
		autoRedirectMarkRegistered: true,
	}
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
	if manager.mark != 0 || manager.unregisterCount != 1 {
		t.Fatalf("output mark lease was not released once: mark=%#x unregister=%d", manager.mark, manager.unregisterCount)
	}
}

func TestCloseRetainsAutoRedirectOutputMarkOnCleanupFailure(t *testing.T) {
	manager := &closeTestNetworkManager{mark: 0x100}
	inbound := &Inbound{
		networkManager:             manager,
		tunOptions:                 stun.Options{AutoRedirectOutputMark: 0x100},
		autoRedirect:               &closeTestAutoRedirect{err: errors.New("redirect cleanup failed")},
		autoRedirectMarkRegistered: true,
	}
	if err := inbound.Close(); err == nil {
		t.Fatal("close unexpectedly succeeded")
	}
	if manager.mark != 0x100 || manager.unregisterCount != 0 {
		t.Fatalf("output mark was released after failed cleanup: mark=%#x unregister=%d", manager.mark, manager.unregisterCount)
	}
}
