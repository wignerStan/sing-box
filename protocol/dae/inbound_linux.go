//go:build linux && !android && with_dae

package dae

import (
	"bytes"
	"context"
	stderrors "errors"
	"net"
	"net/netip"
	"os"
	"os/user"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/pkg/ebpfinbound"
	daeembedded "github.com/daeuniverse/dae/pkg/ebpfinbound/embedded"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
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
	udpReadBufferSize = 64 << 10
	udpOOBBufferSize  = 512
	republishTimeout  = 5 * time.Second
)

var (
	_             adapter.Inbound                 = (*Inbound)(nil)
	_             adapter.InterfaceUpdateListener = (*Inbound)(nil)
	_             N.UDPConnectionHandlerEx        = (*Inbound)(nil)
	sharedRuntime runtimeCoordinator
)

type Inbound struct {
	inbound.Adapter
	rootCtx        context.Context
	ctx            context.Context
	cancel         context.CancelFunc
	router         adapter.Router
	networkManager adapter.NetworkManager
	logger         log.ContextLogger
	capture        ebpfinbound.CaptureConfig
	udpNat         *tun.UDPNat

	access      sync.Mutex
	startCalled bool
	startDone   chan struct{}
	startErr    error
	closed      bool
	closeOnce   sync.Once
	closeErr    error
	runtime     ebpfinbound.Runtime
	member      *runtimeMember
	generation  ebpfinbound.Generation
	serveCtx    context.Context
	serveCancel context.CancelFunc
	waiter      sync.WaitGroup
	userNames   sync.Map // map[int32]string
}

type runtimeCoordinator struct {
	access sync.Mutex
	lease  *runtimeLease
}

type runtimeLease struct {
	config  ebpfinbound.CaptureConfig
	runtime ebpfinbound.Runtime
	active  *runtimeMember
	members map[*runtimeMember]struct{}
}

type runtimeMember struct {
	generation ebpfinbound.Generation
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DAEInboundOptions) (adapter.Inbound, error) {
	capture := normalizeCaptureConfig(ebpfinbound.CaptureConfig{
		TProxyPort:                options.TProxyPort,
		LANInterfaces:             options.LANInterface,
		WANInterfaces:             options.WANInterface,
		OutputMark:                uint32(options.OutputMark),
		AutoConfigureKernel:       options.AutoConfigureKernel,
		ConnectionStateMapEntries: options.BPFConnStateMapSize,
	})
	if err := capture.Validate(); err != nil {
		return nil, E.Cause(err, "validate dae capture configuration")
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	inboundCtx, cancel := context.WithCancel(ctx)
	instance := &Inbound{
		Adapter:        inbound.NewAdapter(C.TypeDAE, tag),
		rootCtx:        ctx,
		ctx:            inboundCtx,
		cancel:         cancel,
		router:         router,
		networkManager: networkManager,
		logger:         logger,
		capture:        capture,
		startDone:      make(chan struct{}),
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

func normalizeCaptureConfig(config ebpfinbound.CaptureConfig) ebpfinbound.CaptureConfig {
	config = config.WithDefaults()
	config.LANInterfaces = normalizeInterfaces(config.LANInterfaces)
	config.WANInterfaces = normalizeInterfaces(config.WANInterfaces)
	return config
}

func normalizeInterfaces(interfaces []string) []string {
	result := make([]string, 0, len(interfaces))
	for _, interfaceName := range interfaces {
		if interfaceName = strings.TrimSpace(interfaceName); interfaceName != "" {
			result = append(result, interfaceName)
		}
	}
	sort.Strings(result)
	return slices.Compact(result)
}

func equalCaptureConfig(left, right ebpfinbound.CaptureConfig) bool {
	return left.TProxyPort == right.TProxyPort &&
		left.OutputMark == right.OutputMark &&
		left.AutoConfigureKernel == right.AutoConfigureKernel &&
		left.ConnectionStateMapEntries == right.ConnectionStateMapEntries &&
		slices.Equal(left.LANInterfaces, right.LANInterfaces) &&
		slices.Equal(left.WANInterfaces, right.WANInterfaces)
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
	if i.startCalled {
		done := i.startDone
		i.access.Unlock()
		<-done
		i.access.Lock()
		err := i.startErr
		i.access.Unlock()
		return err
	}
	i.startCalled = true
	i.access.Unlock()

	err := sharedRuntime.start(i)
	i.access.Lock()
	if err == nil && i.closed {
		err = net.ErrClosed
	}
	i.startErr = err
	close(i.startDone)
	closed := i.closed
	i.access.Unlock()
	if closed {
		_ = i.closeResources()
	}
	return err
}

func (c *runtimeCoordinator) start(i *Inbound) error {
	c.access.Lock()
	defer c.access.Unlock()

	var (
		runtime    ebpfinbound.Runtime
		generation ebpfinbound.Generation
		created    bool
		err        error
	)
	if c.lease == nil {
		runtime, err = daeembedded.New(i.rootCtx, daeembedded.Options{
			Capture:   i.capture,
			LogOutput: &daeLogWriter{logger: i.logger},
			LogLevel:  "info",
		})
		if err != nil {
			return E.Cause(err, "create dae eBPF runtime")
		}
		created = true
		generation, err = runtime.OpenGeneration(i.ctx, i.capture.TProxyPort)
	} else {
		if !equalCaptureConfig(c.lease.config, i.capture) {
			return E.New("changing dae capture settings requires a sing-box process restart")
		}
		runtime = c.lease.runtime
		generation, err = runtime.CloneGeneration(i.ctx, c.lease.active.generation)
	}
	if err != nil {
		if created {
			_ = runtime.Close()
		}
		return E.Cause(err, "open dae listener generation")
	}
	cleanup := func() {
		_ = generation.Close()
		if created {
			_ = runtime.Close()
		}
	}
	if mark := runtime.OutputMark(); mark == 0 || mark != i.capture.OutputMark {
		cleanup()
		return E.New("dae output mark mismatch: runtime=", mark, " configured=", i.capture.OutputMark)
	}
	if err = i.networkManager.RegisterAutoRedirectOutputMark(runtime.OutputMark()); err != nil {
		cleanup()
		return E.Cause(err, "register dae output mark")
	}
	if err = i.udpNat.Start(); err != nil {
		cleanup()
		return err
	}

	i.access.Lock()
	i.runtime = runtime
	i.generation = generation
	i.serveCtx, i.serveCancel = context.WithCancel(i.ctx)
	i.access.Unlock()
	i.startGenerationLoops(generation)
	if err = runtime.CommitGeneration(i.ctx, generation); err != nil {
		i.stopGenerationLoops()
		_ = i.udpNat.Close()
		cleanup()
		i.access.Lock()
		i.runtime = nil
		i.generation = nil
		i.access.Unlock()
		return E.Cause(err, "commit dae listener generation")
	}

	member := &runtimeMember{generation: generation}
	if c.lease == nil {
		c.lease = &runtimeLease{
			config:  i.capture,
			runtime: runtime,
			members: make(map[*runtimeMember]struct{}),
		}
	}
	c.lease.members[member] = struct{}{}
	c.lease.active = member
	i.access.Lock()
	i.member = member
	i.access.Unlock()
	i.logger.Info("dae eBPF inbound started on transparent port ", generation.Port())
	return nil
}

func (i *Inbound) Close() error {
	i.access.Lock()
	if !i.closed {
		i.closed = true
		i.cancel()
	}
	startCalled := i.startCalled
	startDone := i.startDone
	i.access.Unlock()
	if startCalled {
		<-startDone
	}
	return i.closeResources()
}

func (i *Inbound) closeResources() error {
	i.closeOnce.Do(func() {
		i.access.Lock()
		member := i.member
		generation := i.generation
		i.member = nil
		i.generation = nil
		i.runtime = nil
		serveCancel := i.serveCancel
		i.access.Unlock()

		releaseErr, runtimeToClose := sharedRuntime.release(member)
		if serveCancel != nil {
			serveCancel()
		}
		var err error
		if generation != nil {
			err = E.Errors(err, generation.Close())
		}
		i.waiter.Wait()
		err = E.Errors(err, i.udpNat.Close(), releaseErr)
		if runtimeToClose != nil {
			err = E.Errors(err, runtimeToClose.Close())
		}
		i.closeErr = err
	})
	return i.closeErr
}

func (c *runtimeCoordinator) release(member *runtimeMember) (error, ebpfinbound.Runtime) {
	if member == nil {
		return nil, nil
	}
	c.access.Lock()
	defer c.access.Unlock()
	lease := c.lease
	if lease == nil {
		return nil, nil
	}
	if _, exists := lease.members[member]; !exists {
		return nil, nil
	}
	var commitErr error
	if lease.active == member && len(lease.members) > 1 {
		var replacement *runtimeMember
		for candidate := range lease.members {
			if candidate != member {
				replacement = candidate
				break
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), republishTimeout)
		commitErr = lease.runtime.CommitGeneration(ctx, replacement.generation)
		cancel()
		lease.active = replacement
	}
	delete(lease.members, member)
	if len(lease.members) != 0 {
		return commitErr, nil
	}
	c.lease = nil
	return commitErr, lease.runtime
}

func (i *Inbound) InterfaceUpdated(context.Context) {
	i.udpNat.Purge()
}

func (i *Inbound) startGenerationLoops(generation ebpfinbound.Generation) {
	i.waiter.Add(3)
	go i.acceptLoop(generation.TCP4())
	go i.acceptLoop(generation.TCP6())
	go i.udpLoop(generation.UDP())
}

func (i *Inbound) stopGenerationLoops() {
	if i.serveCancel != nil {
		i.serveCancel()
	}
	if i.generation != nil {
		_ = i.generation.Close()
	}
	i.waiter.Wait()
}

func (i *Inbound) acceptLoop(listener net.Listener) {
	defer i.waiter.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if i.serveCtx != nil && i.serveCtx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				i.logger.Error("accept dae TCP connection: ", err)
			}
			return
		}
		go i.handleTCP(conn)
	}
}

func (i *Inbound) handleTCP(conn net.Conn) {
	ctx := log.ContextWithNewID(i.ctx)
	source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	destination := M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata := i.lookupMetadata(ctx, N.NetworkTCP, source, destination)
	i.logger.InfoContext(ctx, "inbound connection from ", source)
	i.logger.InfoContext(ctx, "inbound connection to ", destination)
	i.router.RouteConnectionEx(ctx, conn, metadata, nil)
}

func (i *Inbound) udpLoop(conn *net.UDPConn) {
	defer i.waiter.Done()
	payload := make([]byte, udpReadBufferSize)
	oob := make([]byte, udpOOBBufferSize)
	for {
		n, oobN, flags, source, err := conn.ReadMsgUDPAddrPort(payload, oob)
		if err != nil {
			if i.serveCtx != nil && i.serveCtx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				i.logger.Error("read dae UDP packet: ", err)
			}
			return
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == len(payload) {
			i.logger.Warn("drop truncated dae UDP packet from ", source)
			continue
		}
		destination := ebpfinbound.OriginalDestination(oob[:oobN])
		if !destination.IsValid() {
			i.logger.Warn("drop dae UDP packet without original destination from ", source)
			continue
		}
		packet := append([]byte(nil), payload[:n]...)
		i.udpNat.NewPacket(
			[][]byte{packet},
			M.SocksaddrFromNetIP(source).Unwrap(),
			M.SocksaddrFromNetIP(destination).Unwrap(),
			nil,
		)
	}
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(i.ctx)
	metadata := i.lookupMetadata(ctx, N.NetworkUDP, source, destination)
	_, generation := i.runtimeSnapshot()
	if generation != nil && generation.UDP() != nil {
		metadata.OriginDestination = M.SocksaddrFromNet(generation.UDP().LocalAddr()).Unwrap()
	}
	ctx = adapter.WithContext(ctx, &metadata)
	writer := &packetWriter{
		ctx:         ctx,
		outputMark:  i.capture.OutputMark,
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
		metadata = i.baseMetadata(N.NetworkUDP, source, destination)
	}
	i.logger.InfoContext(ctx, "inbound packet connection from ", source)
	i.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	i.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) baseMetadata(network string, source, destination M.Socksaddr) adapter.InboundContext {
	return adapter.InboundContext{
		Inbound:     i.Tag(),
		InboundType: i.Type(),
		Network:     network,
		Source:      source,
		Destination: destination,
	}
}

func (i *Inbound) runtimeSnapshot() (ebpfinbound.Runtime, ebpfinbound.Generation) {
	i.access.Lock()
	defer i.access.Unlock()
	return i.runtime, i.generation
}

func (i *Inbound) lookupMetadata(ctx context.Context, network string, source, destination M.Socksaddr) adapter.InboundContext {
	result := i.baseMetadata(network, source, destination)
	runtime, _ := i.runtimeSnapshot()
	if runtime == nil || !source.IsIP() || !destination.IsIP() {
		return result
	}
	metadata, found, err := runtime.LookupMetadata(ctx, ebpfinbound.Flow{
		Network:     ebpfinbound.Network(network),
		Source:      source.AddrPort(),
		Destination: destination.AddrPort(),
	})
	if err != nil {
		i.logger.WarnContext(ctx, "lookup dae flow metadata: ", err)
		return result
	}
	if !found {
		return result
	}
	if metadata.HasSourceMAC {
		result.SourceMACAddress = append(net.HardwareAddr(nil), metadata.SourceMAC[:]...)
	}
	result.DSCP = metadata.DSCP
	if metadata.ProcessID != 0 || metadata.ProcessName != "" {
		owner := &adapter.ConnectionOwner{
			ProcessID:   metadata.ProcessID,
			ProcessName: metadata.ProcessName,
			UserId:      -1,
		}
		i.enrichProcessOwner(owner)
		result.ProcessInfo = owner
	}
	return result
}

func (i *Inbound) enrichProcessOwner(owner *adapter.ConnectionOwner) {
	if owner == nil || owner.ProcessID == 0 {
		return
	}
	pid := strconv.FormatUint(uint64(owner.ProcessID), 10)
	if path, err := os.Readlink("/proc/" + pid + "/exe"); err == nil {
		owner.ProcessPath = path
	}
	info, err := os.Stat("/proc/" + pid)
	if err != nil {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	owner.UserId = int32(stat.Uid)
	owner.UserName = i.lookupUserName(owner.UserId)
}

func (i *Inbound) lookupUserName(userID int32) string {
	if cached, loaded := i.userNames.Load(userID); loaded {
		return cached.(string)
	}
	entry, err := user.LookupId(strconv.FormatInt(int64(userID), 10))
	if err != nil {
		i.userNames.Store(userID, "")
		return ""
	}
	i.userNames.Store(userID, entry.Username)
	return entry.Username
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

	if w.destination == destination && w.conn != nil {
		_, err := w.conn.WriteToUDPAddrPort(buffer.Bytes(), w.source)
		if err == nil {
			return nil
		}
		_ = w.conn.Close()
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
		defer func() { _ = udpConn.Close() }()
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

type daeLogWriter struct {
	logger log.ContextLogger
	access sync.Mutex
	buffer bytes.Buffer
}

func (w *daeLogWriter) Write(content []byte) (int, error) {
	w.access.Lock()
	defer w.access.Unlock()
	length := len(content)
	_, _ = w.buffer.Write(content)
	for {
		line, err := w.buffer.ReadString('\n')
		if err != nil {
			w.buffer.WriteString(line)
			break
		}
		line = strings.TrimSpace(line)
		if line != "" {
			w.logger.Debug("[dae-ebpf] ", line)
		}
	}
	return length, nil
}

func (w *daeLogWriter) Flush() {
	w.access.Lock()
	defer w.access.Unlock()
	line := strings.TrimSpace(w.buffer.String())
	w.buffer.Reset()
	if line != "" {
		w.logger.Debug("[dae-ebpf] ", line)
	}
}
