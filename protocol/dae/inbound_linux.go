//go:build linux && !android

package dae

import (
	"context"
	stderrors "errors"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/daeipc"
	"github.com/sagernet/sing-box/common/redir"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.org/x/sys/unix"
)

const (
	defaultSocketMode      = os.FileMode(0o600)
	defaultOutputMark      = uint32(0x100)
	defaultMetadataTimeout = time.Second
	registrationTimeout    = 10 * time.Second
	udpReadBufferSize      = 64 << 10
	udpOOBBufferSize       = 512
)

var (
	_ adapter.Inbound          = (*Inbound)(nil)
	_ N.UDPConnectionHandlerEx = (*Inbound)(nil)
)

type Inbound struct {
	inbound.Adapter
	ctx             context.Context
	cancel          context.CancelFunc
	router          adapter.Router
	logger          log.ContextLogger
	socketPath      string
	socketMode      os.FileMode
	producerUID     uint32
	outputMark      uint32
	metadataTimeout time.Duration
	udpNat          *tun.UDPNat

	access          sync.Mutex
	controlListener *net.UnixListener
	sessions        map[*controlSession]struct{}
	active          *listenerSet
	starting        bool
	started         bool
	closed          bool
	userNameCache   sync.Map // map[int32]string
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DAEInboundOptions) (adapter.Inbound, error) {
	if options.SocketPath == "" {
		return nil, E.New("missing socket_path")
	}
	if !filepath.IsAbs(options.SocketPath) {
		return nil, E.New("socket_path must be absolute")
	}

	socketMode := os.FileMode(options.SocketMode)
	if socketMode == 0 {
		socketMode = defaultSocketMode
	}
	if socketMode&^os.FileMode(0o777) != 0 {
		return nil, E.New("invalid socket_mode: ", options.SocketMode)
	}
	if socketMode&0o002 != 0 {
		return nil, E.New("socket_mode must not be world-writable")
	}

	producerUID := uint32(os.Geteuid())
	if options.ProducerUID != nil {
		producerUID = *options.ProducerUID
	}
	outputMark := uint32(options.OutputMark)
	if outputMark == 0 {
		outputMark = defaultOutputMark
	}
	metadataTimeout := time.Duration(options.MetadataTimeout)
	if metadataTimeout <= 0 {
		metadataTimeout = defaultMetadataTimeout
	}
	udpTimeout := time.Duration(options.UDPTimeout)
	if udpTimeout <= 0 {
		udpTimeout = C.UDPTimeout
	}

	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	if err := networkManager.RegisterAutoRedirectOutputMark(outputMark); err != nil {
		return nil, E.Cause(err, "register dae output mark")
	}

	inboundCtx, cancel := context.WithCancel(ctx)
	instance := &Inbound{
		Adapter:         inbound.NewAdapter(C.TypeDAE, tag),
		ctx:             inboundCtx,
		cancel:          cancel,
		router:          router,
		logger:          logger,
		socketPath:      options.SocketPath,
		socketMode:      socketMode,
		producerUID:     producerUID,
		outputMark:      outputMark,
		metadataTimeout: metadataTimeout,
		sessions:        make(map[*controlSession]struct{}),
	}
	instance.udpNat = tun.NewUDPNat(tun.UDPNatOptions{
		Handler:         instance,
		Prepare:         instance.preparePacketConnection,
		Timeout:         udpTimeout,
		Mapping:         tun.NATMapping(options.UDPMapping),
		Filtering:       tun.NATFiltering(options.UDPFiltering),
		MaxSize:         options.UDPNATMax,
		InterfaceFinder: networkManager.InterfaceFinder(),
	})
	return instance, nil
}

func (i *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}

	i.access.Lock()
	if i.closed {
		i.access.Unlock()
		return net.ErrClosed
	}
	if i.started {
		i.access.Unlock()
		return nil
	}
	if i.starting {
		i.access.Unlock()
		return E.New("dae inbound is already starting")
	}
	i.starting = true
	i.access.Unlock()

	started := false
	defer func() {
		if started {
			return
		}
		i.access.Lock()
		i.starting = false
		i.access.Unlock()
	}()

	if err := os.MkdirAll(filepath.Dir(i.socketPath), 0o755); err != nil {
		return E.Cause(err, "create dae socket directory")
	}
	if err := removeStaleSocket(i.socketPath); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: i.socketPath, Net: "unixpacket"})
	if err != nil {
		return E.Cause(err, "listen dae control socket")
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(i.socketPath, i.socketMode); err != nil {
		_ = listener.Close()
		return E.Cause(err, "set dae control socket mode")
	}
	if err := i.udpNat.Start(); err != nil {
		_ = listener.Close()
		return err
	}

	i.access.Lock()
	if i.closed {
		i.access.Unlock()
		_ = listener.Close()
		_ = i.udpNat.Close()
		return net.ErrClosed
	}
	i.controlListener = listener
	i.starting = false
	i.started = true
	i.access.Unlock()
	started = true

	i.logger.Info("dae datapath control socket listening at ", i.socketPath)
	go i.acceptControlLoop(listener)
	return nil
}

func (i *Inbound) Close() error {
	i.access.Lock()
	if i.closed {
		i.access.Unlock()
		return nil
	}
	i.closed = true
	i.cancel()
	listener := i.controlListener
	i.controlListener = nil
	active := i.active
	i.active = nil
	sessions := make([]*controlSession, 0, len(i.sessions))
	for session := range i.sessions {
		sessions = append(sessions, session)
	}
	i.sessions = nil
	i.access.Unlock()

	var err error
	if listener != nil {
		err = E.Errors(err, listener.Close())
	}
	if active != nil {
		err = E.Errors(err, active.Close())
	}
	for _, session := range sessions {
		session.close(net.ErrClosed)
	}
	err = E.Errors(err, i.udpNat.Close())
	return err
}

func (i *Inbound) InterfaceUpdated(context.Context) {
	i.udpNat.Purge()
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return E.Cause(err, "inspect dae control socket")
	}
	if info.Mode()&os.ModeSocket == 0 {
		return E.New("refusing to replace non-socket path: ", path)
	}

	probe, dialErr := net.DialTimeout("unixpacket", path, 250*time.Millisecond)
	if dialErr == nil {
		_ = probe.Close()
		return E.New("dae control socket is already in use: ", path)
	}
	if !stderrors.Is(dialErr, unix.ECONNREFUSED) && !stderrors.Is(dialErr, unix.ENOENT) {
		return E.Cause(dialErr, "probe existing dae control socket")
	}
	if err := os.Remove(path); err != nil {
		return E.Cause(err, "remove stale dae control socket")
	}
	return nil
}

func (i *Inbound) acceptControlLoop(listener *net.UnixListener) {
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if i.ctx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				i.logger.Error("accept dae control connection: ", err)
			}
			return
		}
		credentials, err := daeipc.PeerCredentials(conn)
		if err != nil {
			i.logger.Error("authenticate dae control connection: ", err)
			_ = conn.Close()
			continue
		}
		if credentials.Uid != i.producerUID {
			i.logger.Warn("reject dae control connection from uid ", credentials.Uid, ", expected ", i.producerUID)
			_ = conn.Close()
			continue
		}

		session := newControlSession(i, conn)
		i.access.Lock()
		if i.closed {
			i.access.Unlock()
			_ = conn.Close()
			return
		}
		i.sessions[session] = struct{}{}
		i.access.Unlock()
		go session.register()
	}
}

func (i *Inbound) activateListenerSet(set *listenerSet) error {
	if set == nil || set.session == nil {
		return E.New("invalid dae listener set")
	}
	if err := set.Start(); err != nil {
		return err
	}

	i.access.Lock()
	if i.closed {
		i.access.Unlock()
		_ = set.Close()
		return net.ErrClosed
	}
	old := i.active
	i.active = set
	i.access.Unlock()

	if old != nil {
		_ = old.Close()
	}
	i.logger.Info("activated dae listener generation ", set.session.generation)
	return nil
}

func (i *Inbound) sessionClosed(session *controlSession) {
	i.access.Lock()
	if i.sessions != nil {
		delete(i.sessions, session)
	}
	var active *listenerSet
	if i.active != nil && i.active.session == session {
		active = i.active
		i.active = nil
	}
	i.access.Unlock()
	if active != nil {
		_ = active.Close()
	}
}

func (i *Inbound) activeSession() *controlSession {
	i.access.Lock()
	defer i.access.Unlock()
	if i.active == nil {
		return nil
	}
	return i.active.session
}

func (i *Inbound) handleTCP(session *controlSession, conn net.Conn) {
	ctx := log.ContextWithNewID(i.ctx)
	source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	destination := M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata, err := i.lookupMetadata(ctx, session, daeipc.NetworkTCP, source, destination)
	if err != nil {
		i.logger.ErrorContext(ctx, "lookup dae TCP metadata: ", err)
		_ = conn.Close()
		return
	}
	metadata.Network = N.NetworkTCP
	i.logger.InfoContext(ctx, "inbound connection from ", source)
	i.logger.InfoContext(ctx, "inbound connection to ", destination)
	i.router.RouteConnectionEx(ctx, conn, metadata, nil)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, userData any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	session, ok := userData.(*controlSession)
	if !ok || session == nil {
		return false, nil, nil, nil
	}
	ctx := log.ContextWithNewID(i.ctx)
	metadata, err := i.lookupMetadata(ctx, session, daeipc.NetworkUDP, source, destination)
	if err != nil {
		i.logger.ErrorContext(ctx, "lookup dae UDP metadata: ", err)
		return false, nil, nil, nil
	}
	metadata.Network = N.NetworkUDP
	ctx = adapter.WithContext(ctx, &metadata)
	writer := &packetWriter{
		ctx:         ctx,
		outputMark:  i.outputMark,
		source:      source.AddrPort(),
		destination: destination,
	}
	return true, ctx, writer, func(error) {
		_ = writer.Close()
	}
}

func (i *Inbound) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	if existing := adapter.ContextFrom(ctx); existing != nil {
		metadata = *existing
	} else {
		metadata.Inbound = i.Tag()
		metadata.InboundType = i.Type()
		metadata.Network = N.NetworkUDP
		metadata.Source = source
		metadata.Destination = destination
	}
	i.logger.InfoContext(ctx, "inbound packet connection from ", source)
	i.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) lookupMetadata(ctx context.Context, session *controlSession, network string, source M.Socksaddr, destination M.Socksaddr) (adapter.InboundContext, error) {
	metadata := adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Source:      source,
		Destination: destination,
	}
	if !source.IsIP() || !destination.IsIP() {
		return metadata, E.New("dae metadata lookup requires IP source and destination")
	}

	lookupCtx, cancel := context.WithTimeout(ctx, i.metadataTimeout)
	defer cancel()
	response, err := session.lookup(lookupCtx, network, source.AddrPort(), destination.AddrPort())
	if err != nil {
		// During dae hot reload, a connection accepted by the retiring listener
		// generation can outlive its metadata channel. The BPF maps are shared
		// across generations, so retry against the active generation before
		// failing the flow.
		if replacement := i.activeSession(); replacement != nil && replacement != session {
			response, err = replacement.lookup(lookupCtx, network, source.AddrPort(), destination.AddrPort())
		}
		if err != nil {
			return metadata, err
		}
	}
	if response.Error != "" {
		return metadata, E.New(response.Error)
	}
	if !response.Found {
		return metadata, nil
	}
	if response.SourceMAC != "" {
		mac, err := net.ParseMAC(response.SourceMAC)
		if err != nil {
			return metadata, E.Cause(err, "parse dae source MAC")
		}
		metadata.SourceMACAddress = mac
	}
	metadata.DSCP = response.DSCP
	if response.PID != 0 || response.ProcessName != "" || response.ProcessPath != "" || response.HasUserID {
		owner := &adapter.ConnectionOwner{
			ProcessID:   response.PID,
			ProcessName: response.ProcessName,
			ProcessPath: response.ProcessPath,
			UserId:      -1,
		}
		if response.HasUserID {
			owner.UserId = response.UserID
			owner.UserName = i.lookupUserName(response.UserID)
		}
		metadata.ProcessInfo = owner
	}
	return metadata, nil
}

func (i *Inbound) lookupUserName(userID int32) string {
	if cached, loaded := i.userNameCache.Load(userID); loaded {
		return cached.(string)
	}
	entry, err := user.LookupId(strconv.FormatInt(int64(userID), 10))
	if err != nil {
		i.userNameCache.Store(userID, "")
		return ""
	}
	i.userNameCache.Store(userID, entry.Username)
	return entry.Username
}

type listenerSet struct {
	inbound   *Inbound
	session   *controlSession
	ctx       context.Context
	cancel    context.CancelFunc
	tcp4      net.Listener
	tcp6      net.Listener
	udp       *net.UDPConn
	closeOnce sync.Once
	waiter    sync.WaitGroup
}

func newListenerSet(parent context.Context, inbound *Inbound, session *controlSession, tcp4 net.Listener, tcp6 net.Listener, udp *net.UDPConn) *listenerSet {
	ctx, cancel := context.WithCancel(parent)
	return &listenerSet{
		inbound: inbound,
		session: session,
		ctx:     ctx,
		cancel:  cancel,
		tcp4:    tcp4,
		tcp6:    tcp6,
		udp:     udp,
	}
}

func (s *listenerSet) Start() error {
	if s.tcp4 == nil || s.tcp6 == nil || s.udp == nil {
		return E.New("incomplete dae listener set")
	}
	s.waiter.Add(3)
	go s.acceptLoop(s.tcp4)
	go s.acceptLoop(s.tcp6)
	go s.udpLoop()
	return nil
}

func (s *listenerSet) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.cancel()
		closeErr = E.Errors(s.tcp4.Close(), s.tcp6.Close(), s.udp.Close())
		s.waiter.Wait()
	})
	return closeErr
}

func (s *listenerSet) acceptLoop(listener net.Listener) {
	defer s.waiter.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.ctx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				s.inbound.logger.Error("accept dae TCP connection: ", err)
			}
			return
		}
		go s.inbound.handleTCP(s.session, conn)
	}
}

func (s *listenerSet) udpLoop() {
	defer s.waiter.Done()
	payload := make([]byte, udpReadBufferSize)
	oob := make([]byte, udpOOBBufferSize)
	for {
		n, oobN, flags, source, err := s.udp.ReadMsgUDPAddrPort(payload, oob)
		if err != nil {
			if s.ctx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				s.inbound.logger.Error("read dae UDP packet: ", err)
			}
			return
		}
		if flags&unix.MSG_TRUNC != 0 {
			s.inbound.logger.Warn("drop truncated dae UDP packet from ", source)
			continue
		}
		destination, err := redir.GetOriginalDestinationFromOOB(oob[:oobN])
		if err != nil {
			s.inbound.logger.Warn("read dae UDP original destination: ", err)
			continue
		}
		if n == len(payload) {
			s.inbound.logger.Warn("drop oversized dae UDP packet from ", source)
			continue
		}
		s.inbound.udpNat.NewPacket(
			[][]byte{payload[:n]},
			M.SocksaddrFromNetIP(source).Unwrap(),
			M.SocksaddrFromNetIP(destination).Unwrap(),
			s.session,
		)
	}
}

type controlSession struct {
	inbound    *Inbound
	conn       *net.UnixConn
	generation uint64

	writeAccess   sync.Mutex
	pendingAccess sync.Mutex
	pending       map[uint64]chan lookupResult
	requestID     atomic.Uint64
	closeOnce     sync.Once
	closed        chan struct{}
}

type lookupResult struct {
	message daeipc.Message
	err     error
}

func newControlSession(inbound *Inbound, conn *net.UnixConn) *controlSession {
	return &controlSession{
		inbound: inbound,
		conn:    conn,
		pending: make(map[uint64]chan lookupResult),
		closed:  make(chan struct{}),
	}
}

func (s *controlSession) register() {
	if err := s.conn.SetDeadline(time.Now().Add(registrationTimeout)); err != nil {
		s.close(E.Cause(err, "set dae registration deadline"))
		return
	}
	message, files, err := daeipc.Read(s.conn)
	if clearErr := s.conn.SetDeadline(time.Time{}); clearErr != nil && err == nil {
		err = clearErr
	}
	if err != nil {
		s.close(E.Cause(err, "read dae registration"))
		return
	}
	if message.Type != daeipc.TypeRegister {
		closeFiles(files)
		s.close(E.New("expected dae registration, got ", message.Type))
		return
	}
	s.generation = message.Generation

	set, err := s.adoptListeners(message, files)
	ack := daeipc.NewMessage(daeipc.TypeRegisterAck)
	ack.Generation = message.Generation
	if err != nil {
		ack.Error = err.Error()
		_ = s.write(ack)
		s.close(err)
		return
	}
	if err := s.write(ack); err != nil {
		_ = set.Close()
		s.close(err)
		return
	}

	go s.readLoop()
	if err := s.inbound.activateListenerSet(set); err != nil {
		s.close(err)
		return
	}
}

func (s *controlSession) adoptListeners(message daeipc.Message, files []*os.File) (*listenerSet, error) {
	defer closeFiles(files)
	if message.Generation == 0 {
		return nil, E.New("missing dae generation")
	}
	if message.OutputMark != s.inbound.outputMark {
		return nil, E.New("dae output mark mismatch: received ", message.OutputMark, ", configured ", s.inbound.outputMark)
	}
	if message.TProxyPort == 0 {
		return nil, E.New("invalid dae tproxy port")
	}
	if len(message.Listeners) != len(files) {
		return nil, E.New("dae listener descriptor count mismatch")
	}

	var (
		tcp4 net.Listener
		tcp6 net.Listener
		udp  *net.UDPConn
	)
	closeAdopted := func() {
		common.Close(tcp4, tcp6, udp)
	}
	for index, kind := range message.Listeners {
		file := files[index]
		switch kind {
		case daeipc.ListenerTCP4:
			if tcp4 != nil {
				closeAdopted()
				return nil, E.New("duplicate TCP4 listener")
			}
			listener, err := net.FileListener(file)
			if err != nil {
				closeAdopted()
				return nil, E.Cause(err, "adopt dae TCP4 listener")
			}
			tcp4 = listener
		case daeipc.ListenerTCP6:
			if tcp6 != nil {
				closeAdopted()
				return nil, E.New("duplicate TCP6 listener")
			}
			listener, err := net.FileListener(file)
			if err != nil {
				closeAdopted()
				return nil, E.Cause(err, "adopt dae TCP6 listener")
			}
			tcp6 = listener
		case daeipc.ListenerUDP4, daeipc.ListenerUDP6:
			if udp != nil {
				closeAdopted()
				return nil, E.New("duplicate UDP listener")
			}
			packetConn, err := net.FilePacketConn(file)
			if err != nil {
				closeAdopted()
				return nil, E.Cause(err, "adopt dae UDP listener")
			}
			udpConn, ok := packetConn.(*net.UDPConn)
			if !ok {
				_ = packetConn.Close()
				closeAdopted()
				return nil, E.New("unexpected dae UDP listener type")
			}
			udp = udpConn
		default:
			closeAdopted()
			return nil, E.New("unsupported dae listener kind: ", kind)
		}
	}
	if tcp4 == nil || tcp6 == nil || udp == nil {
		closeAdopted()
		return nil, E.New("dae registration requires TCP4, TCP6, and UDP listeners")
	}
	for _, address := range []net.Addr{tcp4.Addr(), tcp6.Addr(), udp.LocalAddr()} {
		if M.SocksaddrFromNet(address).Port != message.TProxyPort {
			closeAdopted()
			return nil, E.New("dae listener port mismatch")
		}
	}
	return newListenerSet(s.inbound.ctx, s.inbound, s, tcp4, tcp6, udp), nil
}

func (s *controlSession) write(message daeipc.Message) error {
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	return daeipc.Write(s.conn, message)
}

func (s *controlSession) readLoop() {
	for {
		message, files, err := daeipc.Read(s.conn)
		closeFiles(files)
		if err != nil {
			s.close(err)
			return
		}
		if len(files) != 0 {
			s.close(E.New("unexpected file descriptors in dae response"))
			return
		}
		switch message.Type {
		case daeipc.TypeLookupResponse:
			s.pendingAccess.Lock()
			responseChannel := s.pending[message.RequestID]
			delete(s.pending, message.RequestID)
			s.pendingAccess.Unlock()
			if responseChannel != nil {
				responseChannel <- lookupResult{message: message}
			}
		case daeipc.TypePong:
		default:
			s.close(E.New("unsupported dae response type: ", message.Type))
			return
		}
	}
}

func (s *controlSession) lookup(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (daeipc.Message, error) {
	requestID := s.requestID.Add(1)
	if requestID == 0 {
		requestID = s.requestID.Add(1)
	}
	responseChannel := make(chan lookupResult, 1)
	s.pendingAccess.Lock()
	s.pending[requestID] = responseChannel
	s.pendingAccess.Unlock()

	request := daeipc.NewMessage(daeipc.TypeLookup)
	request.RequestID = requestID
	request.Generation = s.generation
	request.Network = network
	request.Source = source.String()
	request.Destination = destination.String()
	if err := s.write(request); err != nil {
		s.removePending(requestID)
		return daeipc.Message{}, err
	}

	select {
	case result := <-responseChannel:
		if result.err != nil {
			return daeipc.Message{}, result.err
		}
		if result.message.Generation != 0 && result.message.Generation != s.generation {
			return daeipc.Message{}, E.New("dae metadata generation mismatch")
		}
		return result.message, nil
	case <-ctx.Done():
		s.removePending(requestID)
		return daeipc.Message{}, ctx.Err()
	case <-s.closed:
		s.removePending(requestID)
		return daeipc.Message{}, net.ErrClosed
	}
}

func (s *controlSession) removePending(requestID uint64) {
	s.pendingAccess.Lock()
	delete(s.pending, requestID)
	s.pendingAccess.Unlock()
}

func (s *controlSession) close(reason error) {
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
		close(s.closed)
		s.pendingAccess.Lock()
		pending := s.pending
		s.pending = make(map[uint64]chan lookupResult)
		s.pendingAccess.Unlock()
		for _, responseChannel := range pending {
			responseChannel <- lookupResult{err: reason}
		}
		s.inbound.sessionClosed(s)
	})
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}

type packetWriter struct {
	ctx         context.Context
	outputMark  uint32
	source      netip.AddrPort
	destination M.Socksaddr

	access sync.Mutex
	conn   *net.UDPConn
}

func (w *packetWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	w.access.Lock()
	defer w.access.Unlock()

	conn := w.conn
	if w.destination == destination && conn != nil {
		_, err := conn.WriteToUDPAddrPort(buffer.Bytes(), w.source)
		if err == nil {
			return nil
		}
		_ = conn.Close()
		w.conn = nil
	}

	var listenConfig net.ListenConfig
	listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	listenConfig.Control = control.Append(listenConfig.Control, control.RoutingMark(w.outputMark))
	listenConfig.Control = control.Append(listenConfig.Control, redir.TProxyWriteBack())
	packetConn, err := listenConfig.ListenPacket(w.ctx, "udp", destination.String())
	if err != nil {
		return err
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return E.New("unexpected UDP packet connection type")
	}
	if w.destination == destination {
		w.conn = udpConn
	} else {
		defer udpConn.Close()
	}
	return common.Error(udpConn.WriteToUDPAddrPort(buffer.Bytes(), w.source))
}

func (w *packetWriter) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.conn == nil {
		return nil
	}
	err := w.conn.Close()
	w.conn = nil
	return err
}
