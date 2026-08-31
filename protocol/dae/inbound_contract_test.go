//go:build linux && !android

package dae

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/daeipc"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"
)

type daeTestNetworkManager struct {
	adapter.NetworkManager
	finder      control.InterfaceFinder
	mark        uint32
	registerErr error
	access      sync.Mutex
}

func (m *daeTestNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return m.finder
}

func (m *daeTestNetworkManager) RegisterAutoRedirectOutputMark(mark uint32) error {
	m.access.Lock()
	defer m.access.Unlock()
	if m.registerErr != nil {
		return m.registerErr
	}
	if m.mark != 0 {
		return fmt.Errorf("output mark already registered: %#x", m.mark)
	}
	m.mark = mark
	return nil
}

func (m *daeTestNetworkManager) AutoRedirectOutputMark() uint32 {
	m.access.Lock()
	defer m.access.Unlock()
	return m.mark
}

func (m *daeTestNetworkManager) AutoRedirectOutputMarkFunc() control.Func {
	return nil
}

func TestNewInboundValidationAndMarkRegistration(t *testing.T) {
	validPath := filepath.Join(t.TempDir(), "dae.sock")
	invalid := []struct {
		name    string
		options option.DAEInboundOptions
		wantErr string
	}{
		{name: "missing path", options: option.DAEInboundOptions{}, wantErr: "missing socket_path"},
		{name: "relative path", options: option.DAEInboundOptions{SocketPath: "dae.sock"}, wantErr: "absolute"},
		{name: "invalid mode bits", options: option.DAEInboundOptions{SocketPath: validPath, SocketMode: 0x1000}, wantErr: "invalid socket_mode"},
		{name: "world writable", options: option.DAEInboundOptions{SocketPath: validPath, SocketMode: 0o666}, wantErr: "world-writable"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewInbound(context.Background(), nil, nil, "dae", test.options)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("NewInbound() = %v, want error containing %q", err, test.wantErr)
			}
		})
	}

	// A valid configuration without a registered network manager fails cleanly.
	if _, err := NewInbound(context.Background(), nil, nil, "dae", option.DAEInboundOptions{SocketPath: validPath}); err == nil || !strings.Contains(err.Error(), "missing network manager") {
		t.Fatalf("missing network manager error = %v", err)
	}
	if _, err := NewInbound(nil, nil, nil, "dae", option.DAEInboundOptions{SocketPath: validPath}); err == nil || !strings.Contains(err.Error(), "missing network manager") {
		t.Fatalf("nil context error = %v", err)
	}

	networkManager := &daeTestNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	instance, err := NewInbound(ctx, nil, nil, "dae", option.DAEInboundOptions{
		SocketPath: validPath,
		OutputMark: option.FwMark(0x73ae),
	})
	if err != nil {
		t.Fatal(err)
	}
	inbound, ok := instance.(*Inbound)
	if !ok {
		t.Fatalf("inbound type = %T", instance)
	}
	if got := networkManager.AutoRedirectOutputMark(); got != 0x73ae {
		t.Fatalf("registered output mark = %#x, want %#x", got, 0x73ae)
	}
	if inbound.socketMode != defaultSocketMode || inbound.metadataTimeout != defaultMetadataTimeout {
		t.Fatalf("defaults not applied: mode=%#o timeout=%s", inbound.socketMode, inbound.metadataTimeout)
	}
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
	if err := inbound.Close(); err != nil {
		t.Fatal("Close is not idempotent:", err)
	}

	if _, err := NewInbound(ctx, nil, nil, "dae-again", option.DAEInboundOptions{SocketPath: filepath.Join(t.TempDir(), "again.sock")}); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("duplicate output mark error = %v", err)
	}
}

func TestInboundStartCloseLifecycle(t *testing.T) {
	networkManager := &daeTestNetworkManager{}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), networkManager)
	socketPath := filepath.Join(t.TempDir(), "nested", "dae.sock")
	instance, err := NewInbound(ctx, nil, log.NewNOPFactory().Logger(), "dae", option.DAEInboundOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatal(err)
	}
	inbound := instance.(*Inbound)
	if err := inbound.Start(adapter.StartStateStart); err != nil {
		t.Fatal(err)
	}
	if err := inbound.Start(adapter.StartStateStart); err != nil {
		t.Fatalf("second Start() = %v", err)
	}
	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != defaultSocketMode.Perm() {
		t.Fatalf("socket mode = %#o, want %#o", info.Mode().Perm(), defaultSocketMode.Perm())
	}
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("control socket remains after Close: %v", err)
	}
	if err := inbound.Start(adapter.StartStateStart); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Start after Close = %v, want net.ErrClosed", err)
	}
}

func TestAdoptListenersRejectsMalformedRegistrations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*daeipc.Message, *[]*os.File, *daeListenerFixture)
		want   string
	}{
		{name: "missing generation", mutate: func(message *daeipc.Message, _ *[]*os.File, _ *daeListenerFixture) { message.Generation = 0 }, want: "missing dae generation"},
		{name: "mark mismatch", mutate: func(message *daeipc.Message, _ *[]*os.File, _ *daeListenerFixture) { message.OutputMark++ }, want: "output mark mismatch"},
		{name: "missing port", mutate: func(message *daeipc.Message, _ *[]*os.File, _ *daeListenerFixture) { message.TProxyPort = 0 }, want: "invalid dae tproxy port"},
		{name: "descriptor count", mutate: func(message *daeipc.Message, files *[]*os.File, _ *daeListenerFixture) {
			message.Listeners = message.Listeners[:2]
			*files = (*files)[:2]
		}, want: "requires TCP4, TCP6, and UDP listeners"},
		{name: "duplicate tcp4", mutate: func(message *daeipc.Message, files *[]*os.File, fixture *daeListenerFixture) {
			message.Listeners = []string{daeipc.ListenerTCP4, daeipc.ListenerTCP4, daeipc.ListenerTCP6, daeipc.ListenerUDP4}
			*files = append([]*os.File{fixture.files[0], fixture.files[0]}, fixture.files[1:]...)
		}, want: "duplicate TCP4"},
		{name: "unsupported kind", mutate: func(message *daeipc.Message, _ *[]*os.File, _ *daeListenerFixture) { message.Listeners[0] = "sctp4" }, want: "unsupported dae listener kind"},
		{name: "tcp family mismatch", mutate: func(message *daeipc.Message, _ *[]*os.File, _ *daeListenerFixture) {
			message.Listeners[0] = daeipc.ListenerTCP6
		}, want: "wrong address family"},
		{name: "udp family mismatch", mutate: func(message *daeipc.Message, _ *[]*os.File, _ *daeListenerFixture) {
			message.Listeners[2] = daeipc.ListenerUDP6
		}, want: "wrong address family"},
		{name: "missing required listener", mutate: func(message *daeipc.Message, files *[]*os.File, _ *daeListenerFixture) {
			message.Listeners = []string{daeipc.ListenerTCP4, daeipc.ListenerTCP6}
			*files = (*files)[:2]
		}, want: "requires TCP4, TCP6, and UDP listeners"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDAEListenerFixture(t)
			defer fixture.close()
			files := append([]*os.File(nil), fixture.files...)
			message := daeipc.NewMessage(daeipc.TypeRegister)
			message.Generation = 1
			message.TProxyPort = fixture.port
			message.OutputMark = defaultOutputMark
			message.Listeners = []string{daeipc.ListenerTCP4, daeipc.ListenerTCP6, daeipc.ListenerUDP4}
			test.mutate(&message, &files, fixture)
			session := &controlSession{inbound: &Inbound{ctx: context.Background(), outputMark: defaultOutputMark}}
			set, err := session.adoptListeners(message, files)
			if set != nil {
				_ = set.Close()
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("adoptListeners() = %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestDAEListenerFamilyMatches(t *testing.T) {
	ipv4 := &net.TCPAddr{IP: net.IPv4zero, Port: 1}
	ipv6 := &net.TCPAddr{IP: net.IPv6unspecified, Port: 1}
	udp4 := &net.UDPAddr{IP: net.IPv4zero, Port: 1}
	udp6 := &net.UDPAddr{IP: net.IPv6unspecified, Port: 1}
	tests := []struct {
		kind string
		addr net.Addr
		want bool
	}{
		{daeipc.ListenerTCP4, ipv4, true},
		{daeipc.ListenerTCP4, ipv6, false},
		{daeipc.ListenerTCP6, ipv6, true},
		{daeipc.ListenerTCP6, ipv4, false},
		{daeipc.ListenerUDP4, udp4, true},
		{daeipc.ListenerUDP4, udp6, false},
		{daeipc.ListenerUDP6, udp6, true},
		{daeipc.ListenerUDP6, udp4, false},
	}
	for _, test := range tests {
		if got := daeListenerFamilyMatches(test.kind, test.addr); got != test.want {
			t.Errorf("daeListenerFamilyMatches(%q, %T) = %t, want %t", test.kind, test.addr, got, test.want)
		}
	}
}

func TestControlSessionLookupCancellationAndClose(t *testing.T) {
	if _, err := (&controlSession{}).lookup(nil, daeipc.NetworkTCP, mustAddrPort(t, "127.0.0.1:1234"), mustAddrPort(t, "1.1.1.1:443")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("lookup on an uninitialized session = %v, want net.ErrClosed", err)
	}
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()
	inbound := &Inbound{ctx: context.Background(), sessions: make(map[*controlSession]struct{})}
	session := newControlSession(inbound, client)
	session.generation = 5
	inbound.sessions[session] = struct{}{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := session.lookup(ctx, daeipc.NetworkTCP, mustAddrPort(t, "127.0.0.1:1234"), mustAddrPort(t, "1.1.1.1:443"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled lookup = %v, want context.Canceled", err)
	}
	session.pendingAccess.Lock()
	pendingCount := len(session.pending)
	session.pendingAccess.Unlock()
	if pendingCount != 0 {
		t.Fatalf("cancelled lookup left %d pending requests", pendingCount)
	}

	go session.readLoop()
	result := make(chan error, 1)
	go func() {
		_, err := session.lookup(nil, daeipc.NetworkTCP, mustAddrPort(t, "127.0.0.1:1235"), mustAddrPort(t, "1.1.1.1:443"))
		result <- err
	}()
	request, files, err := daeipc.Read(server)
	closeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	if request.Type != daeipc.TypeLookup {
		t.Fatalf("request type = %q", request.Type)
	}
	session.close(errors.New("test close"))
	select {
	case err := <-result:
		if err == nil || (!strings.Contains(err.Error(), "test close") && !strings.Contains(err.Error(), "closed network connection")) {
			t.Fatalf("pending lookup error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pending lookup was not woken by session close")
	}
	// close is deliberately idempotent.
	session.close(errors.New("second close"))
}

func TestControlSessionReadLoopRejectsGenerationAndDescriptors(t *testing.T) {
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()
	inbound := &Inbound{ctx: context.Background(), sessions: make(map[*controlSession]struct{})}
	session := newControlSession(inbound, client)
	session.generation = 3
	inbound.sessions[session] = struct{}{}
	go session.readLoop()

	result := make(chan error, 1)
	go func() {
		_, err := session.lookup(context.Background(), daeipc.NetworkTCP, mustAddrPort(t, "127.0.0.1:1234"), mustAddrPort(t, "1.1.1.1:443"))
		result <- err
	}()
	request, files, err := daeipc.Read(server)
	closeFiles(files)
	if err != nil {
		t.Fatal(err)
	}
	response := daeipc.NewMessage(daeipc.TypeLookupResponse)
	response.RequestID = request.RequestID
	response.Generation = session.generation + 1
	if err := daeipc.Write(server, response); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !strings.Contains(err.Error(), "generation mismatch") {
			t.Fatalf("generation mismatch result = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lookup did not receive generation mismatch")
	}
	session.close(net.ErrClosed)

	server2, client2 := unixPacketPair(t)
	defer server2.Close()
	defer client2.Close()
	inbound2 := &Inbound{ctx: context.Background(), sessions: make(map[*controlSession]struct{})}
	session2 := newControlSession(inbound2, client2)
	inbound2.sessions[session2] = struct{}{}
	go session2.readLoop()
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	if err := daeipc.Write(server2, daeipc.NewMessage(daeipc.TypePong), file); err != nil {
		file.Close()
		t.Fatal(err)
	}
	file.Close()
	select {
	case <-session2.closed:
	case <-time.After(time.Second):
		t.Fatal("unexpected descriptor did not close session")
	}
}

func TestListenerSetReplacementAndClose(t *testing.T) {
	inbound := &Inbound{
		ctx:      context.Background(),
		logger:   log.NewNOPFactory().Logger(),
		sessions: make(map[*controlSession]struct{}),
	}
	first := newTestListenerSet(t, inbound, 0)
	second := newTestListenerSet(t, inbound, 1)
	firstSession := first.session
	secondSession := second.session
	if err := inbound.activateListenerSet(first); err != nil {
		t.Fatal(err)
	}
	if inbound.activeSession() != firstSession {
		t.Fatal("first listener generation was not activated")
	}
	if err := inbound.activateListenerSet(second); err != nil {
		t.Fatal(err)
	}
	if inbound.activeSession() != secondSession {
		t.Fatal("second listener generation was not activated")
	}
	select {
	case <-first.ctx.Done():
	default:
		t.Fatal("old listener generation was not closed")
	}
	if err := inbound.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPacketWriterCloseIsIdempotent(t *testing.T) {
	writer := &packetWriter{}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

type daeListenerFixture struct {
	tcp4  net.Listener
	tcp6  net.Listener
	udp   *net.UDPConn
	files []*os.File
	port  uint16
}

func newDAEListenerFixture(t *testing.T) *daeListenerFixture {
	t.Helper()
	tcp4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(tcp4.Addr().(*net.TCPAddr).Port)
	tcp6, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(int(port))))
	if err != nil {
		_ = tcp4.Close()
		t.Skipf("IPv6 listener unavailable: %v", err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		_ = tcp4.Close()
		_ = tcp6.Close()
		t.Fatal(err)
	}
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
	return &daeListenerFixture{
		tcp4:  tcp4,
		tcp6:  tcp6,
		udp:   udp,
		files: []*os.File{tcp4File, tcp6File, udpFile},
		port:  port,
	}
}

func (f *daeListenerFixture) close() {
	for _, file := range f.files {
		if file != nil {
			_ = file.Close()
		}
	}
	if f.tcp4 != nil {
		_ = f.tcp4.Close()
	}
	if f.tcp6 != nil {
		_ = f.tcp6.Close()
	}
	if f.udp != nil {
		_ = f.udp.Close()
	}
}

func newTestListenerSet(t *testing.T, inbound *Inbound, generation uint64) *listenerSet {
	t.Helper()
	tcp4, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		_ = tcp4.Close()
		t.Skipf("IPv6 listener unavailable: %v", err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		_ = tcp4.Close()
		_ = tcp6.Close()
		t.Fatal(err)
	}
	session := &controlSession{inbound: inbound, generation: generation}
	return newListenerSet(inbound.ctx, inbound, session, tcp4, tcp6, udp)
}
