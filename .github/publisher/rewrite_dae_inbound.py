from pathlib import Path

path = Path('protocol/dae/inbound_linux.go')
old = path.read_text()

def extract_func(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth = 0
    i = brace
    in_string = False
    escaped = False
    quote = ''
    while i < len(text):
        char = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == quote:
                in_string = False
        else:
            if char in ('"', "'", '`'):
                in_string = True
                quote = char
            elif char == '{':
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        i += 1
    raise ValueError(signature)

parts = []
for signature in (
    'func (i *Inbound) handleTCP',
    'func (i *Inbound) preparePacketConnection',
    'func (i *Inbound) NewPacketConnectionEx',
    'func (i *Inbound) baseMetadata',
    'func (i *Inbound) lookupMetadata',
    'func (i *Inbound) enrichProcessOwner',
    'func (i *Inbound) lookupUserName',
):
    parts.append(extract_func(old, signature))
parts.append(old[old.index('type packetWriter struct'):])
tail = '\n\n'.join(parts)
tail = tail.replace(
    '_, generation := i.runtimeSnapshot()\n\tif generation != nil',
    'service := i.serviceSnapshot()\n\tvar generation ebpfinbound.Generation\n\tif service != nil {\n\t\tgeneration = service.generation\n\t}\n\tif generation != nil',
)
tail = tail.replace(
    'runtime, _ := i.runtimeSnapshot()\n\tif runtime == nil',
    'service := i.serviceSnapshot()\n\tvar runtime ebpfinbound.Runtime\n\tif service != nil {\n\t\truntime = service.runtime\n\t}\n\tif runtime == nil',
)

header = r'''//go:build linux && !android && with_dae

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
    "sync/atomic"
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
    udpOOBBufferSize = 512
)

var (
    _ adapter.Inbound = (*Inbound)(nil)
    _ adapter.InterfaceUpdateListener = (*Inbound)(nil)
    _ N.UDPConnectionHandlerEx = (*captureService)(nil)
    sharedRuntime runtimeCoordinator
)

type Inbound struct {
    inbound.Adapter
    rootCtx context.Context
    ctx context.Context
    cancel context.CancelFunc
    router adapter.Router
    networkManager adapter.NetworkManager
    logger log.ContextLogger
    capture ebpfinbound.CaptureConfig
    udpOptions udpRuntimeOptions

    access sync.Mutex
    startCalled bool
    startDone chan struct{}
    startErr error
    closed bool
    closeOnce sync.Once
    closeErr error
    service *captureService
    userNames sync.Map
}

type udpRuntimeOptions struct {
    timeout time.Duration
    mapping tun.NATMapping
    filtering tun.NATFiltering
    maxSize uint32
}

type runtimeCoordinator struct {
    access sync.Mutex
    lease *runtimeLease
}

type runtimeLease struct {
    tag string
    config ebpfinbound.CaptureConfig
    udp udpRuntimeOptions
    service *captureService
    members []*Inbound
}

type captureService struct {
    ctx context.Context
    cancel context.CancelFunc
    runtime ebpfinbound.Runtime
    generation ebpfinbound.Generation
    udpNat *tun.UDPNat
    logger log.ContextLogger
    active atomic.Pointer[Inbound]
    waiter sync.WaitGroup
    closeOnce sync.Once
    closeErr error
}

type flowInboundKey struct{}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DAEInboundOptions) (adapter.Inbound, error) {
    capture := normalizeCaptureConfig(ebpfinbound.CaptureConfig{
        TProxyPort: options.TProxyPort,
        LANInterfaces: options.LANInterface,
        WANInterfaces: options.WANInterface,
        OutputMark: uint32(options.OutputMark),
        AutoConfigureKernel: options.AutoConfigureKernel,
        ConnectionStateMapEntries: options.BPFConnStateMapSize,
        AllowLazyInterfaces: options.AllowLazyInterface,
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
    return &Inbound{
        Adapter: inbound.NewAdapter(C.TypeDAE, tag),
        rootCtx: ctx,
        ctx: inboundCtx,
        cancel: cancel,
        router: router,
        networkManager: networkManager,
        logger: logger,
        capture: capture,
        udpOptions: udpRuntimeOptions{
            timeout: udpTimeout,
            mapping: tun.NATMapping(options.UDPMapping),
            filtering: tun.NATFiltering(options.UDPFiltering),
            maxSize: options.UDPNATMax,
        },
        startDone: make(chan struct{}),
    }, nil
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
        left.AllowLazyInterfaces == right.AllowLazyInterfaces &&
        slices.Equal(left.LANInterfaces, right.LANInterfaces) &&
        slices.Equal(left.WANInterfaces, right.WANInterfaces)
}

func equalUDPOptions(left, right udpRuntimeOptions) bool {
    return left.timeout == right.timeout && left.mapping == right.mapping && left.filtering == right.filtering && left.maxSize == right.maxSize
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

    if c.lease != nil {
        if c.lease.tag != i.Tag() {
            return E.New("only one logical dae inbound is allowed; existing tag=", c.lease.tag, " new tag=", i.Tag())
        }
        if !equalCaptureConfig(c.lease.config, i.capture) || !equalUDPOptions(c.lease.udp, i.udpOptions) {
            return E.New("changing dae capture or UDP NAT settings requires a sing-box process restart")
        }
        c.lease.members = append(c.lease.members, i)
        c.lease.service.active.Store(i)
        i.access.Lock()
        i.service = c.lease.service
        i.access.Unlock()
        i.logger.Info("dae eBPF inbound handler activated on transparent port ", c.lease.service.generation.Port())
        return nil
    }

    runtime, err := daeembedded.New(i.rootCtx, daeembedded.Options{
        Capture: i.capture,
        LogOutput: &daeLogWriter{logger: i.logger},
        LogLevel: "info",
    })
    if err != nil {
        return E.Cause(err, "create dae eBPF runtime")
    }
    generation, err := runtime.OpenGeneration(i.ctx, i.capture.TProxyPort)
    if err != nil {
        _ = runtime.Close()
        return E.Cause(err, "open dae listener generation")
    }
    cleanup := func() {
        _ = generation.Close()
        _ = runtime.Close()
    }
    if mark := runtime.OutputMark(); mark == 0 || mark != i.capture.OutputMark {
        cleanup()
        return E.New("dae output mark mismatch: runtime=", mark, " configured=", i.capture.OutputMark)
    }
    if err = i.networkManager.RegisterAutoRedirectOutputMark(runtime.OutputMark()); err != nil {
        cleanup()
        return E.Cause(err, "register dae output mark")
    }

    serviceCtx, serviceCancel := context.WithCancel(i.rootCtx)
    capture := &captureService{
        ctx: serviceCtx,
        cancel: serviceCancel,
        runtime: runtime,
        generation: generation,
        logger: i.logger,
    }
    capture.udpNat = tun.NewUDPNat(tun.UDPNatOptions{
        Handler: capture,
        Prepare: capture.preparePacketConnection,
        Timeout: i.udpOptions.timeout,
        Mapping: i.udpOptions.mapping,
        Filtering: i.udpOptions.filtering,
        MaxSize: i.udpOptions.maxSize,
        InterfaceFinder: i.networkManager.InterfaceFinder(),
    })
    if err = capture.udpNat.Start(); err != nil {
        serviceCancel()
        cleanup()
        return E.Cause(err, "start dae UDP NAT")
    }
    capture.active.Store(i)
    capture.startLoops()
    if err = runtime.CommitGeneration(i.ctx, generation); err != nil {
        _ = capture.Close()
        return E.Cause(err, "commit dae listener generation")
    }

    c.lease = &runtimeLease{
        tag: i.Tag(),
        config: i.capture,
        udp: i.udpOptions,
        service: capture,
        members: []*Inbound{i},
    }
    i.access.Lock()
    i.service = capture
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
        i.closeErr = sharedRuntime.release(i)
        i.access.Lock()
        i.service = nil
        i.access.Unlock()
    })
    return i.closeErr
}

func (c *runtimeCoordinator) release(i *Inbound) error {
    c.access.Lock()
    defer c.access.Unlock()
    if c.lease == nil {
        return nil
    }
    index := slices.Index(c.lease.members, i)
    if index < 0 {
        return nil
    }
    c.lease.members = slices.Delete(c.lease.members, index, index + 1)
    if len(c.lease.members) == 0 {
        service := c.lease.service
        c.lease = nil
        return service.Close()
    }
    if c.lease.service.active.Load() == i {
        c.lease.service.active.Store(c.lease.members[len(c.lease.members) - 1])
    }
    return nil
}

func (i *Inbound) InterfaceUpdated(context.Context) {
    if service := i.serviceSnapshot(); service != nil && service.udpNat != nil {
        service.udpNat.Purge()
    }
}

func (i *Inbound) serviceSnapshot() *captureService {
    i.access.Lock()
    defer i.access.Unlock()
    return i.service
}

func (s *captureService) startLoops() {
    s.waiter.Add(3)
    go s.acceptLoop(s.generation.TCP4())
    go s.acceptLoop(s.generation.TCP6())
    go s.udpLoop(s.generation.UDP())
}

func (s *captureService) acceptLoop(listener net.Listener) {
    defer s.waiter.Done()
    for {
        conn, err := listener.Accept()
        if err != nil {
            if s.ctx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
                s.logger.Error("accept dae TCP connection: ", err)
            }
            return
        }
        inbound := s.active.Load()
        if inbound == nil {
            _ = conn.Close()
            continue
        }
        go inbound.handleTCP(conn)
    }
}

func (s *captureService) udpLoop(conn *net.UDPConn) {
    defer s.waiter.Done()
    payload := make([]byte, udpReadBufferSize)
    oob := make([]byte, udpOOBBufferSize)
    for {
        n, oobN, flags, source, err := conn.ReadMsgUDPAddrPort(payload, oob)
        if err != nil {
            if s.ctx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
                s.logger.Error("read dae UDP packet: ", err)
            }
            return
        }
        if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n == len(payload) {
            s.logger.Warn("drop truncated dae UDP packet from ", source)
            continue
        }
        destination := ebpfinbound.OriginalDestination(oob[:oobN])
        if !destination.IsValid() {
            s.logger.Warn("drop dae UDP packet without original destination from ", source)
            continue
        }
        packet := append([]byte(nil), payload[:n]...)
        s.udpNat.NewPacket(
            [][]byte{packet},
            M.SocksaddrFromNetIP(source).Unwrap(),
            M.SocksaddrFromNetIP(destination).Unwrap(),
            nil,
        )
    }
}

func (s *captureService) preparePacketConnection(source M.Socksaddr, destination M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
    inbound := s.active.Load()
    if inbound == nil {
        return false, nil, nil, nil
    }
    ok, ctx, writer, onClose := inbound.preparePacketConnection(source, destination, nil)
    if ok && ctx != nil {
        ctx = context.WithValue(ctx, flowInboundKey{}, inbound)
    }
    return ok, ctx, writer, onClose
}

func (s *captureService) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
    inbound, _ := ctx.Value(flowInboundKey{}).(*Inbound)
    if inbound == nil {
        inbound = s.active.Load()
    }
    if inbound == nil {
        _ = conn.Close()
        if onClose != nil {
            onClose(net.ErrClosed)
        }
        return
    }
    inbound.NewPacketConnectionEx(ctx, conn, source, destination, onClose)
}

func (s *captureService) Close() error {
    s.closeOnce.Do(func() {
        s.active.Store(nil)
        s.cancel()
        var err error
        if s.generation != nil {
            err = E.Errors(err, s.generation.Close())
        }
        s.waiter.Wait()
        if s.udpNat != nil {
            err = E.Errors(err, s.udpNat.Close())
        }
        if s.runtime != nil {
            err = E.Errors(err, s.runtime.Close())
        }
        s.closeErr = err
    })
    return s.closeErr
}
'''

path.write_text(header + '\n\n' + tail + '\n')

option_path = Path('option/dae.go')
option_text = option_path.read_text()
if 'AllowLazyInterface' not in option_text:
    option_text = option_text.replace('type DAEInboundOptions struct {', 'type DAEInboundOptions struct {\n\tAllowLazyInterface bool `json:"allow_lazy_interface,omitempty"`')
option_path.write_text(option_text)

Path('protocol/dae/inbound_linux_test.go').write_text(r'''//go:build linux && !android && with_dae

package dae

import (
    "context"
    "net"
    "testing"

    "github.com/daeuniverse/dae/pkg/ebpfinbound"
)

type testGeneration struct{ port uint16 }
func (*testGeneration) TCP4() net.Listener { return nil }
func (*testGeneration) TCP6() net.Listener { return nil }
func (*testGeneration) UDP() *net.UDPConn { return nil }
func (g *testGeneration) Port() uint16 { return g.port }
func (*testGeneration) Close() error { return nil }

type testRuntime struct{}
func (*testRuntime) OpenGeneration(context.Context, uint16) (ebpfinbound.Generation, error) { return nil, nil }
func (*testRuntime) CloneGeneration(context.Context, ebpfinbound.Generation) (ebpfinbound.Generation, error) { return nil, nil }
func (*testRuntime) CommitGeneration(context.Context, ebpfinbound.Generation) error { return nil }
func (*testRuntime) LookupMetadata(context.Context, ebpfinbound.Flow) (ebpfinbound.Metadata, bool, error) { return ebpfinbound.Metadata{}, false, nil }
func (*testRuntime) OutputMark() uint32 { return ebpfinbound.DefaultOutputMark }
func (*testRuntime) Close() error { return nil }

func TestNormalizeCaptureConfig(t *testing.T) {
    config := normalizeCaptureConfig(ebpfinbound.CaptureConfig{WANInterfaces: []string{"eth1", "", " eth0 ", "eth1"}})
    if len(config.WANInterfaces) != 2 || config.WANInterfaces[0] != "eth0" || config.WANInterfaces[1] != "eth1" { t.Fatalf("WANInterfaces = %v", config.WANInterfaces) }
}

func TestRuntimeCoordinatorKeepsStableService(t *testing.T) {
    first := &Inbound{}
    second := &Inbound{}
    service := &captureService{}
    service.active.Store(first)
    coordinator := &runtimeCoordinator{lease: &runtimeLease{service: service, members: []*Inbound{first, second}}}
    service.active.Store(second)
    if err := coordinator.release(first); err != nil { t.Fatal(err) }
    if service.active.Load() != second { t.Fatal("active handler changed") }
    if len(coordinator.lease.members) != 1 || coordinator.lease.members[0] != second { t.Fatal("wrong surviving members") }
}
''')

for doc_name in ('docs/configuration/inbound/dae.md', 'docs/configuration/inbound/dae.zh.md'):
    doc = Path(doc_name)
    if not doc.exists():
        continue
    text = doc.read_text()
    if 'allow_lazy_interface' not in text:
        text = text.replace('"auto_config_kernel_parameter": true,', '"allow_lazy_interface": false,\n  "auto_config_kernel_parameter": true,')
    if doc_name.endswith('/dae.md'):
        text += '\n\n### Safe startup and reload\n\n`wan_interface: ["auto"]` is resolved during provider preflight. Patterns that match no current link fail startup unless `allow_lazy_interface` is enabled explicitly. The eBPF runtime and transparent listeners remain stable across ordinary sing-box reloads; a fully prepared handler is activated with one atomic pointer swap. Capture and UDP NAT setting changes require a process restart.\n'
    else:
        text += '\n\n### 安全启动与重载\n\n`wan_interface: ["auto"]` 会在启动预检时解析默认路由接口。不匹配任何现有网卡的模式默认使启动失败，只有显式启用 `allow_lazy_interface` 才会等待未来接口。普通重载复用同一组 eBPF 透明监听器，并在新处理器完全就绪后原子切换；捕获和 UDP NAT 设置变更需要重启进程。\n'
    doc.write_text(text)
