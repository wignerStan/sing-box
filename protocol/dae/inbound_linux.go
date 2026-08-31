//go:build linux && !android

package dae

import (
	"context"
	stderrors "errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/daeipc"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
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
	if ctx == nil {
		ctx = context.Background()
	}
	if logger == nil {
		logger = log.NewNOPFactory().Logger()
	}
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
	if i.cancel != nil {
		i.cancel()
	}
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
	if i.udpNat != nil {
		err = E.Errors(err, i.udpNat.Close())
	}
	return err
}

func (i *Inbound) InterfaceUpdated(context.Context) {
	if i != nil && i.udpNat != nil {
		i.udpNat.Purge()
	}
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
