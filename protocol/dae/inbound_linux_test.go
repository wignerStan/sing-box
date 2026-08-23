//go:build linux && !android

package dae

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/daeipc"
)

func TestAdoptListeners(t *testing.T) {
	tcp4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp4.Close()
	port := uint16(tcp4.Addr().(*net.TCPAddr).Port)
	tcp6, err := net.Listen("tcp6", net.JoinHostPort("::1", portString(port)))
	if err != nil {
		t.Skipf("IPv6 listener unavailable: %v", err)
	}
	defer tcp6.Close()
	udp, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: int(port)})
	if err != nil {
		t.Skipf("IPv6 UDP listener unavailable: %v", err)
	}
	defer udp.Close()

	tcp4File, err := tcp4.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	tcp6File, err := tcp6.(*net.TCPListener).File()
	if err != nil {
		t.Fatal(err)
	}
	udpFile, err := udp.File()
	if err != nil {
		t.Fatal(err)
	}
	files := []*os.File{tcp4File, tcp6File, udpFile}

	instance := &Inbound{
		ctx:        context.Background(),
		outputMark: defaultOutputMark,
	}
	session := &controlSession{inbound: instance}
	message := daeipc.NewMessage(daeipc.TypeRegister)
	message.Generation = 1
	message.TProxyPort = port
	message.OutputMark = defaultOutputMark
	message.Listeners = []string{daeipc.ListenerTCP4, daeipc.ListenerTCP6, daeipc.ListenerUDP6}

	set, err := session.adoptListeners(message, files)
	if err != nil {
		t.Fatal(err)
	}
	if set.tcp4 == nil || set.tcp6 == nil || set.udp == nil {
		t.Fatal("incomplete adopted listener set")
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestControlSessionLookup(t *testing.T) {
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()

	instance := &Inbound{
		ctx:      context.Background(),
		sessions: make(map[*controlSession]struct{}),
	}
	session := newControlSession(instance, client)
	session.generation = 9
	instance.sessions[session] = struct{}{}
	go session.readLoop()

	errorChannel := make(chan error, 1)
	go func() {
		request, files, err := daeipc.Read(server)
		closeFiles(files)
		if err != nil {
			errorChannel <- err
			return
		}
		response := daeipc.NewMessage(daeipc.TypeLookupResponse)
		response.RequestID = request.RequestID
		response.Generation = request.Generation
		response.Found = true
		response.PID = 123
		errorChannel <- daeipc.Write(server, response)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := session.lookup(ctx, daeipc.NetworkTCP, mustAddrPort(t, "127.0.0.1:1234"), mustAddrPort(t, "1.1.1.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errorChannel; err != nil {
		t.Fatal(err)
	}
	if !response.Found || response.PID != 123 {
		t.Fatalf("unexpected response: %#v", response)
	}
	session.close(net.ErrClosed)
}

func unixPacketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Skipf("unixpacket unavailable: %v", err)
	}
	defer listener.Close()

	clientChannel := make(chan *net.UnixConn, 1)
	errorChannel := make(chan error, 1)
	go func() {
		client, dialErr := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
		if dialErr != nil {
			errorChannel <- dialErr
			return
		}
		clientChannel <- client
	}()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case client := <-clientChannel:
		return server, client
	case err := <-errorChannel:
		server.Close()
		t.Fatal(err)
		return nil, nil
	case <-time.After(5 * time.Second):
		server.Close()
		t.Fatal("timed out creating unixpacket pair")
		return nil, nil
	}
}

func mustAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func portString(port uint16) string {
	return strconv.FormatUint(uint64(port), 10)
}

func TestRemoveStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dae.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := removeStaleSocket(path); err == nil {
		_ = listener.Close()
		t.Fatal("active dae socket was treated as stale")
	}
	if _, err := os.Lstat(path); err != nil {
		_ = listener.Close()
		t.Fatalf("active socket path was removed: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeStaleSocket(path); err != nil {
		t.Fatalf("remove stale socket: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket still exists: %v", err)
	}
}
