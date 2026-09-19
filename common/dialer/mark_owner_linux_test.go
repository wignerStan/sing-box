//go:build linux

package dialer_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"golang.org/x/sys/unix"
)

func TestExplicitMarksRemainAllowedWithoutDeclaredOwner(t *testing.T) {
	for _, source := range []string{"routing_mark", "route.default_mark"} {
		manager := &configuredMarkNetworkManager{NetworkManager: new(route.NetworkManager)}
		options := option.DialerOptions{}
		if source == "routing_mark" {
			options.RoutingMark = 0x100
		} else {
			manager.options.RoutingMark = 0x100
		}
		ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
		if _, err := dialer.NewDefault(ctx, options); err != nil {
			t.Fatalf("%s without capture owner: %v", source, err)
		}
	}
}

func TestRuntimeLeaseStillRejectsExplicitMarks(t *testing.T) {
	for _, source := range []string{"routing_mark", "route.default_mark"} {
		manager := &configuredMarkNetworkManager{NetworkManager: new(route.NetworkManager)}
		options := option.DialerOptions{}
		if source == "routing_mark" {
			options.RoutingMark = 0x100
		} else {
			manager.options.RoutingMark = 0x100
		}
		ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
		d, err := dialer.NewDefault(ctx, options)
		if err != nil {
			t.Fatal(err)
		}
		if err = manager.RegisterAutoRedirectOutputMark(0x100); err != nil {
			t.Fatal(err)
		}
		conn, err := d.DialContext(ctx, "udp4", M.ParseSocksaddr("127.0.0.1:9"))
		if conn != nil {
			conn.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "conflict") {
			t.Fatalf("%s runtime conflict = %v", source, err)
		}
	}
}

func TestOutputMarkLeaseMarksTCPUDPAndPacketSockets(t *testing.T) {
	manager := new(route.NetworkManager)
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
	ctx = dialer.ContextWithExclusiveOutputMark(ctx, "dae")
	// Dialers are constructed before the capture runtime owns its mark.
	d, err := dialer.NewDefault(ctx, option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.RegisterAutoRedirectOutputMark(0x100); err != nil {
		t.Fatal(err)
	}
	defer manager.UnregisterAutoRedirectOutputMark(0x100)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, e := listener.Accept()
		if e == nil {
			c.Close()
		}
	}()
	for _, network := range []string{"tcp4", "udp4"} {
		t.Run(network, func(t *testing.T) {
			conn, err := d.DialContext(ctx, network, M.SocksaddrFromNet(listener.Addr()))
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
				t.Skip("requires SO_MARK capability")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			assertSocketMark(t, conn, 0x100)
		})
	}
	t.Run("packet", func(t *testing.T) {
		conn, err := d.ListenPacket(ctx, M.ParseSocksaddr("127.0.0.1:9"))
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Skip("requires SO_MARK capability")
		}
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		assertSocketMark(t, conn, 0x100)
	})
}

func assertSocketMark(t *testing.T, conn any, want int) {
	t.Helper()
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	var optionErr error
	err = raw.Control(func(fd uintptr) { got, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK) })
	if err != nil || optionErr != nil {
		t.Fatalf("getsockopt: %v, %v", err, optionErr)
	}
	if got != want {
		t.Fatalf("socket mark = %#x, want %#x", got, want)
	}
}
