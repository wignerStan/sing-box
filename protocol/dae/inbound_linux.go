//go:build linux && !android && with_dae

package dae

import (
	"bytes"
	"context"
	stderrors "errors"
	"math"
	"net"
	"net/netip"
	"os"
	"os/user"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/ebpfinbound"
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
	coordinator    *runtimeCoordinator

	access      sync.Mutex
	startCalled bool
	startDone   chan struct{}
	startErr    error
	closed      bool
	closeOnce   sync.Once
	closeErr    error
	runtime     ebpfinbound.Runtime
	member      *runtimeMember
	userNames   sync.Map // map[int32]string
}

type runtimeCoordinator struct {
	access     sync.Mutex
	condition  *sync.Cond
	closing    bool
	lease      *runtimeLease
	newRuntime func(context.Context, ebpfinbound.Options) (ebpfinbound.Runtime, error)
}

type runtimeLease struct {
	config         ebpfinbound.CaptureConfig
	tag            string
	runtime        ebpfinbound.Runtime
	listeners      ebpfinbound.ListenerSet
	networkManager adapter.NetworkManager
	active         *runtimeMember
	members        map[*runtimeMember]struct{}
	nextSequence   uint64
	loopCtx        context.Context
	loopCancel     context.CancelFunc
	loops          sync.WaitGroup
	dispatches     sync.WaitGroup
	memberCleanup  sync.WaitGroup
	logger         log.ContextLogger
	logWriter      *daeLogWriter
}

type runtimeMember struct {
	inbound  *Inbound
	sequence uint64

	access    sync.Mutex
	condition *sync.Cond
	closing   bool
	active    int
}

type dispatchTarget struct {
	lease   *runtimeLease
	member  *runtimeMember
	inbound *Inbound
	runtime ebpfinbound.Runtime
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DAEInboundOptions) (adapter.Inbound, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if logger == nil {
		logger = log.NewNOPFactory().Logger()
	}
	capture := normalizeCaptureConfig(ebpfinbound.CaptureConfig{
		TProxyPort:                options.TProxyPort,
		LANInterfaces:             options.LANInterface,
		WANInterfaces:             options.WANInterface,
		OutputMark:                uint32(options.OutputMark),
		AutoConfigureKernel:       options.AutoConfigureKernel,
		ConnectionStateMapEntries: options.BPFConnStateMapSize,
		RequireProcessMetadata:    options.RequireProcessMetadata,
	})
	if err := capture.Validate(); err != nil {
		return nil, E.Cause(err, "validate dae capture configuration")
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager == nil {
		return nil, E.New("missing network manager")
	}
	udpTimeout := C.UDPTimeout
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
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
		coordinator:    &sharedRuntime,
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
		left.RequireProcessMetadata == right.RequireProcessMetadata &&
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

	err := i.coordinator.start(i)
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
	c.initializeLocked()
	for c.closing {
		c.condition.Wait()
	}
	if lease := c.lease; lease != nil {
		if lease.tag != i.Tag() {
			return E.New("only one dae eBPF inbound tag can own the host capture runtime")
		}
		if !equalCaptureConfig(lease.config, i.capture) {
			return E.New("changing dae capture settings requires a sing-box process restart")
		}
		if !sameNetworkManager(lease.networkManager, i.networkManager) {
			return E.New("dae eBPF runtime cannot span different sing-box network managers")
		}
		if i.networkManager.AutoRedirectOutputMark() != lease.runtime.OutputMark() {
			return E.New("dae output mark registration changed while the runtime was active")
		}
		if i.isClosed() {
			return net.ErrClosed
		}
		if err := i.udpNat.Start(); err != nil {
			return err
		}
		member := lease.addMember(i)
		i.bindRuntime(lease.runtime, member)
		i.logger.Info("dae eBPF inbound adopted the active capture runtime on transparent port ", lease.listeners.Port())
		return nil
	}

	logWriter := &daeLogWriter{logger: i.logger}
	newRuntime := c.newRuntime
	if newRuntime == nil {
		newRuntime = ebpfinbound.New
	}
	runtime, err := newRuntime(i.rootCtx, ebpfinbound.Options{
		Capture:   i.capture,
		LogOutput: logWriter,
		LogLevel:  "info",
	})
	if err != nil {
		return E.Cause(err, "create dae eBPF runtime")
	}
	fail := func(startErr error, markRegistered bool, udpStarted bool) error {
		var cleanupErr error
		if udpStarted {
			cleanupErr = stderrors.Join(cleanupErr, i.udpNat.Close())
		}
		runtimeCloseErr := runtime.Close()
		cleanupErr = stderrors.Join(cleanupErr, runtimeCloseErr)
		if markRegistered && runtimeCloseErr == nil {
			cleanupErr = stderrors.Join(cleanupErr, i.networkManager.UnregisterAutoRedirectOutputMark(runtime.OutputMark()))
		}
		logWriter.Flush()
		return stderrors.Join(startErr, cleanupErr)
	}
	listeners := runtime.Listeners()
	status := runtime.Status()
	if !status.Ready || listeners == nil || listeners.TCP4() == nil || listeners.TCP6() == nil || listeners.UDP() == nil || listeners.Port() == 0 {
		return fail(E.New("dae eBPF runtime returned an incomplete listener set"), false, false)
	}
	if mark := runtime.OutputMark(); mark == 0 || mark != i.capture.OutputMark {
		return fail(E.New("dae output mark mismatch: runtime=", mark, " configured=", i.capture.OutputMark), false, false)
	}
	if i.isClosed() {
		return fail(net.ErrClosed, false, false)
	}
	if err := i.networkManager.RegisterAutoRedirectOutputMark(runtime.OutputMark()); err != nil {
		return fail(E.Cause(err, "register dae output mark"), false, false)
	}
	if err := i.udpNat.Start(); err != nil {
		return fail(err, true, false)
	}
	loopCtx, loopCancel := context.WithCancel(context.Background())
	lease := &runtimeLease{
		config:         i.capture,
		tag:            i.Tag(),
		runtime:        runtime,
		listeners:      listeners,
		networkManager: i.networkManager,
		members:        make(map[*runtimeMember]struct{}),
		loopCtx:        loopCtx,
		loopCancel:     loopCancel,
		logger:         i.logger,
		logWriter:      logWriter,
	}
	member := lease.addMember(i)
	i.bindRuntime(runtime, member)
	c.lease = lease
	c.startLoopsLocked(lease)
	i.logger.Info("dae eBPF inbound started on transparent port ", listeners.Port())
	return nil
}

func (c *runtimeCoordinator) initializeLocked() {
	if c.condition == nil {
		c.condition = sync.NewCond(&c.access)
	}
}

func (c *runtimeCoordinator) startLoopsLocked(lease *runtimeLease) {
	lease.loops.Add(3)
	go c.acceptLoop(lease, lease.listeners.TCP4())
	go c.acceptLoop(lease, lease.listeners.TCP6())
	go c.udpLoop(lease, lease.listeners.UDP())
}

func (lease *runtimeLease) addMember(i *Inbound) *runtimeMember {
	lease.nextSequence++
	member := &runtimeMember{inbound: i, sequence: lease.nextSequence}
	member.condition = sync.NewCond(&member.access)
	lease.members[member] = struct{}{}
	lease.memberCleanup.Add(1)
	lease.active = member
	return member
}

func (i *Inbound) bindRuntime(runtime ebpfinbound.Runtime, member *runtimeMember) {
	i.access.Lock()
	i.runtime = runtime
	i.member = member
	i.access.Unlock()
}

func (i *Inbound) isClosed() bool {
	i.access.Lock()
	defer i.access.Unlock()
	return i.closed
}

func sameNetworkManager(left, right adapter.NetworkManager) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	leftValue := reflect.ValueOf(left)
	rightValue := reflect.ValueOf(right)
	return leftValue.Type() == rightValue.Type() && leftValue.Kind() == reflect.Pointer && leftValue.Pointer() == rightValue.Pointer()
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
		i.member = nil
		i.access.Unlock()

		var err error
		if member != nil {
			err = i.coordinator.release(member)
		} else if i.udpNat != nil {
			err = i.udpNat.Close()
		}
		i.access.Lock()
		i.runtime = nil
		i.access.Unlock()
		i.closeErr = err
	})
	return i.closeErr
}

func (c *runtimeCoordinator) release(member *runtimeMember) error {
	if member == nil {
		return nil
	}
	c.access.Lock()
	c.initializeLocked()
	lease := c.lease
	if lease == nil {
		c.access.Unlock()
		return nil
	}
	if _, exists := lease.members[member]; !exists {
		c.access.Unlock()
		return nil
	}
	member.beginClose()
	delete(lease.members, member)
	if lease.active == member {
		lease.active = newestMember(lease.members)
	}
	final := len(lease.members) == 0
	if final {
		lease.active = nil
		c.lease = nil
		c.closing = true
	}
	c.access.Unlock()

	member.wait()
	var errs []error
	if member.inbound.udpNat != nil {
		if err := member.inbound.udpNat.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	lease.memberCleanup.Done()
	if !final {
		return stderrors.Join(errs...)
	}

	lease.memberCleanup.Wait()
	lease.dispatches.Wait()
	lease.loopCancel()
	runtimeCloseErr := lease.runtime.Close()
	if runtimeCloseErr != nil {
		errs = append(errs, runtimeCloseErr)
	}
	lease.loops.Wait()
	if runtimeCloseErr == nil {
		if err := lease.networkManager.UnregisterAutoRedirectOutputMark(lease.runtime.OutputMark()); err != nil {
			errs = append(errs, E.Cause(err, "unregister dae output mark"))
		}
	} else {
		lease.logger.Warn("retaining dae output mark because the capture runtime did not close cleanly")
	}
	lease.logWriter.Flush()

	c.access.Lock()
	c.closing = false
	c.condition.Broadcast()
	c.access.Unlock()
	return stderrors.Join(errs...)
}

func newestMember(members map[*runtimeMember]struct{}) *runtimeMember {
	var newest *runtimeMember
	for member := range members {
		if newest == nil || member.sequence > newest.sequence {
			newest = member
		}
	}
	return newest
}

func (member *runtimeMember) acquire() bool {
	member.access.Lock()
	defer member.access.Unlock()
	if member.closing {
		return false
	}
	member.active++
	return true
}

func (member *runtimeMember) release() {
	member.access.Lock()
	member.active--
	if member.active == 0 {
		member.condition.Broadcast()
	}
	member.access.Unlock()
}

func (member *runtimeMember) beginClose() {
	member.access.Lock()
	member.closing = true
	member.access.Unlock()
}

func (member *runtimeMember) wait() {
	member.access.Lock()
	for member.active != 0 {
		member.condition.Wait()
	}
	member.access.Unlock()
}

func (c *runtimeCoordinator) acquireTarget(expected *runtimeLease) *dispatchTarget {
	c.access.Lock()
	defer c.access.Unlock()
	if c.lease != expected || expected.active == nil || !expected.active.acquire() {
		return nil
	}
	expected.dispatches.Add(1)
	return &dispatchTarget{
		lease:   expected,
		member:  expected.active,
		inbound: expected.active.inbound,
		runtime: expected.runtime,
	}
}

func (target *dispatchTarget) done() {
	target.member.release()
	target.lease.dispatches.Done()
}

func (c *runtimeCoordinator) acceptLoop(lease *runtimeLease, listener *net.TCPListener) {
	defer lease.loops.Done()
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if lease.loopCtx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				lease.logger.Error("accept dae TCP connection: ", err)
			}
			return
		}
		target := c.acquireTarget(lease)
		if target == nil {
			_ = conn.Close()
			continue
		}
		go func() {
			defer target.done()
			target.inbound.handleTCP(target.runtime, conn)
		}()
	}
}

func (c *runtimeCoordinator) udpLoop(lease *runtimeLease, conn *net.UDPConn) {
	defer lease.loops.Done()
	payload := make([]byte, udpReadBufferSize)
	oob := make([]byte, udpOOBBufferSize)
	for {
		n, oobN, flags, source, err := conn.ReadMsgUDPAddrPort(payload, oob)
		if err != nil {
			if lease.loopCtx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				lease.logger.Error("read dae UDP packet: ", err)
			}
			return
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == len(payload) {
			lease.logger.Warn("drop truncated dae UDP packet from ", source)
			continue
		}
		destination := ebpfinbound.OriginalDestination(oob[:oobN])
		if !destination.IsValid() {
			lease.logger.Warn("drop dae UDP packet without original destination from ", source)
			continue
		}
		target := c.acquireTarget(lease)
		if target == nil {
			continue
		}
		packet := append([]byte(nil), payload[:n]...)
		target.inbound.udpNat.NewPacket(
			[][]byte{packet},
			M.SocksaddrFromNetIP(source).Unwrap(),
			M.SocksaddrFromNetIP(destination).Unwrap(),
			nil,
		)
		target.done()
	}
}

func (i *Inbound) InterfaceUpdated(context.Context) {
	if i != nil && i.udpNat != nil {
		i.udpNat.Purge()
	}
}

func (i *Inbound) handleTCP(runtime ebpfinbound.Runtime, conn net.Conn) {
	ctx := log.ContextWithNewID(i.ctx)
	source := M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	destination := M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata := i.lookupMetadata(ctx, runtime, N.NetworkTCP, source, destination)
	i.logger.InfoContext(ctx, "inbound connection from ", source)
	i.logger.InfoContext(ctx, "inbound connection to ", destination)
	i.router.RouteConnectionEx(ctx, conn, metadata, nil)
}

func (i *Inbound) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
	ctx := log.ContextWithNewID(i.ctx)
	runtime := i.runtimeSnapshot()
	metadata := i.lookupMetadata(ctx, runtime, N.NetworkUDP, source, destination)
	if runtime != nil {
		listeners := runtime.Listeners()
		if listeners != nil && listeners.UDP() != nil {
			metadata.OriginDestination = M.SocksaddrFromNet(listeners.UDP().LocalAddr()).Unwrap()
		}
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

func (i *Inbound) runtimeSnapshot() ebpfinbound.Runtime {
	i.access.Lock()
	defer i.access.Unlock()
	return i.runtime
}

func (i *Inbound) lookupMetadata(ctx context.Context, runtime ebpfinbound.Runtime, network string, source, destination M.Socksaddr) adapter.InboundContext {
	result := i.baseMetadata(network, source, destination)
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
	if metadata.ProcessID != 0 || metadata.ProcessName != "" || metadata.HasProcessUID {
		owner := &adapter.ConnectionOwner{ProcessID: metadata.ProcessID, UserId: -1}
		if metadata.ProcessName != "" {
			owner.ProcessNames = []string{metadata.ProcessName}
		}
		if path := verifiedProcessPath(metadata.ProcessID, metadata.ProcessStartTime); path != "" {
			owner.ProcessPaths = []string{path}
		}
		if metadata.HasProcessUID && metadata.ProcessUID <= math.MaxInt32 {
			owner.UserId = int32(metadata.ProcessUID)
			owner.UserName = i.lookupUserName(owner.UserId)
		}
		result.ProcessInfo = owner
	}
	return result
}

func verifiedProcessPath(processID uint32, expectedStartTime uint64) string {
	if processID == 0 || expectedStartTime == 0 {
		return ""
	}
	pid := strconv.FormatUint(uint64(processID), 10)
	if actual, err := readProcessStartTime("/proc/" + pid + "/stat"); err != nil || actual != expectedStartTime {
		return ""
	}
	path, err := os.Readlink("/proc/" + pid + "/exe")
	if err != nil {
		return ""
	}
	if actual, err := readProcessStartTime("/proc/" + pid + "/stat"); err != nil || actual != expectedStartTime {
		return ""
	}
	return path
}

func readProcessStartTime(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	closeIndex := bytes.LastIndexByte(raw, ')')
	if closeIndex < 0 || closeIndex+2 > len(raw) {
		return 0, E.New("invalid process stat record")
	}
	fields := strings.Fields(string(raw[closeIndex+1:]))
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0, E.New("short process stat record")
	}
	return strconv.ParseUint(fields[startTimeIndex], 10, 64)
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
