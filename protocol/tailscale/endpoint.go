//go:build with_gvisor

package tailscale

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/icmp"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/iponly"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/tailscale/tailssh"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
	tailscaleroot "github.com/sagernet/tailscale"
	_ "github.com/sagernet/tailscale/feature/relayserver"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnlocal"
	tsDNS "github.com/sagernet/tailscale/net/dns"
	"github.com/sagernet/tailscale/net/netmon"
	"github.com/sagernet/tailscale/net/netns"
	"github.com/sagernet/tailscale/net/tsaddr"
	tsTUN "github.com/sagernet/tailscale/net/tstun"
	"github.com/sagernet/tailscale/tailcfg"
	"github.com/sagernet/tailscale/tsnet"
	"github.com/sagernet/tailscale/types/nettype"
	"github.com/sagernet/tailscale/version"
	"github.com/sagernet/tailscale/wgengine"
	"github.com/sagernet/tailscale/wgengine/router"
	"github.com/sagernet/tailscale/wgengine/wgcfg"
	wgTun "github.com/sagernet/wireguard-go/tun"

	mDNS "github.com/miekg/dns"
)

var (
	_ adapter.OutboundWithPreferredRoutes = (*Endpoint)(nil)
	_ adapter.InterfaceUpdateListener     = (*Endpoint)(nil)
	_ dialer.PacketDialerWithDestination  = (*Endpoint)(nil)
	_ tun.Port                            = (*userspaceEndpoint)(nil)

	tailscaleGlobalHookAccess sync.Mutex
	tailscaleGlobalHookOwner  *Endpoint
)

func init() {
	version.SetVersion(strings.TrimSpace(tailscaleroot.VersionDotTxt) + "-0-(sing-box " + C.Version + ")")
}

func RegisterEndpoint(registry *endpoint.Registry) {
	endpoint.Register[option.TailscaleEndpointOptions](registry, C.TypeTailscale, NewEndpoint)
}

// userspaceEndpoint adds the packet-level tun.Port capability used by
// sing-box flow routing. A system-interface endpoint intentionally does not
// implement tun.Port: packets must traverse the real OS TUN exactly once.
type userspaceEndpoint struct {
	*Endpoint
}

type Endpoint struct {
	endpoint.Adapter
	ctx               context.Context
	router            adapter.Router
	logger            logger.ContextLogger
	queryOptions      adapter.DNSQueryOptions
	dnsRouter         adapter.DNSRouter
	network           adapter.NetworkManager
	platformInterface adapter.PlatformInterface
	server            *tsnet.Server
	stack             *stack.Stack
	icmpForwarder     *tun.ICMPForwarder
	returnAccess      sync.Mutex
	returnPath        tun.Return
	wgEngine          wgengine.ExportedUserspaceEngine
	onReconfigHook    wgengine.ReconfigListener
	sshReconfigHook   wgengine.ReconfigListener

	cfg           *wgcfg.Config
	routerCfg     *router.Config
	dnsCfg        *tsDNS.Config
	routeDomains  common.TypedValue[map[string]bool]
	routeSuffixes common.TypedValue[[]string]
	searchDomains atomic.Bool

	acceptRoutes               bool
	exitNode                   string
	exitNodeAllowLANAccess     bool
	advertiseRoutes            []netip.Prefix
	advertiseExitNode          bool
	advertiseTags              []string
	relayServerPort            *uint16
	relayServerStaticEndpoints []netip.AddrPort

	udpTimeout  time.Duration
	icmpTimeout time.Duration

	sshServerInstance *tailssh.Server
	sshServerOptions  *option.TailscaleSSHServerOptions
	taildrop          *taildropManager
	localBackend      *ipnlocal.LocalBackend

	systemInterface     bool
	systemInterfaceName string
	systemInterfaceMTU  uint32
	keyAuth             bool
	serverStarted       atomic.Bool
	started             atomic.Bool
	// Tailscale's WireGuard engine owns this adapter after it is assigned to
	// server.Tun. Keep the adapter for idempotent cleanup; closing the raw
	// sing-tun device after Server.Close would close it a second time.
	systemTunDevice       wgTun.Device
	systemDialer          *dialer.DefaultDialer
	systemRouteManager    systemRouteManager
	systemRouteMu         sync.Mutex
	systemRouteUpdate     chan struct{}
	systemRouteStop       chan struct{}
	systemRouteWG         sync.WaitGroup
	systemRouteStopping   bool
	systemRouteGeneration uint64
	systemRouteWaiters    map[uint64]chan error
	exitNodeUpdateMu      sync.Mutex
	exitNodeActive        atomic.Bool
	globalHooksAcquired   bool
	userspaceHandler      tun.Handler
	fallbackTCPCloser     func()
}

const (
	systemRouteRetryMinDelay = 250 * time.Millisecond
	systemRouteRetryMaxDelay = 5 * time.Second
	systemRouteCloseAttempts = 4
	systemRouteCloseDelay    = 200 * time.Millisecond
	systemRouteApplyTimeout  = 15 * time.Second
)

func NewEndpoint(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TailscaleEndpointOptions) (adapter.Endpoint, error) {
	stateDirectory := options.StateDirectory
	if stateDirectory == "" {
		stateDirectory = "tailscale"
	}
	platformInterface := service.FromContext[adapter.PlatformInterface](ctx)
	hostname := options.Hostname
	if hostname == "" && platformInterface != nil {
		hostname = platformInterface.TailscaleHostname()
	}
	if hostname == "" {
		osHostname, _ := os.Hostname()
		osHostname = strings.TrimSpace(osHostname)
		hostname = osHostname
	}
	if hostname == "" {
		hostname = "sing-box"
	}
	stateDirectory = filemanager.BasePath(ctx, os.ExpandEnv(stateDirectory))
	stateDirectory, _ = filepath.Abs(stateDirectory)
	if options.SystemInterface && options.SSHServer != nil && options.SSHServer.Enabled {
		return nil, E.New("Tailscale `ssh_server` requires the userspace service netstack and cannot be used with `system_interface`")
	}
	if options.SSHServer != nil && options.SSHServer.Enabled {
		err := adapter.CheckSecurityFeature(ctx, "Tailscale `ssh_server`")
		if err != nil {
			return nil, err
		}
	}
	for _, advertiseRoute := range options.AdvertiseRoutes {
		if advertiseRoute.Addr().IsUnspecified() && advertiseRoute.Bits() == 0 {
			return nil, E.New("`advertise_routes` cannot be default, use `advertise_exit_node` instead.")
		}
	}
	if options.AdvertiseExitNode && options.ExitNode != "" {
		return nil, E.New("cannot advertise an exit node and use an exit node at the same time.")
	}
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:          ctx,
		Options:          options.DialerOptions,
		RemoteIsDomain:   true,
		ResolverOnDetour: true,
		NewDialer:        true,
	})
	if err != nil {
		return nil, err
	}
	dialerQueryOptions := outboundDialer.(dialer.ResolveDialer).QueryOptions()
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	taildropDirectory := options.TaildropDirectory
	if taildropDirectory == "" {
		taildropDirectory = "Taildrop"
	}
	taildropDirectory = filemanager.BasePath(ctx, os.ExpandEnv(taildropDirectory))
	taildropDirectory, _ = filepath.Abs(taildropDirectory)
	tailscaleEndpoint := &Endpoint{
		Adapter:           endpoint.NewAdapter(C.TypeTailscale, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, nil),
		ctx:               ctx,
		router:            router,
		logger:            logger,
		dnsRouter:         dnsRouter,
		queryOptions:      dialerQueryOptions,
		network:           service.FromContext[adapter.NetworkManager](ctx),
		platformInterface: platformInterface,
		server: &tsnet.Server{
			Dir:      stateDirectory,
			Hostname: hostname,
			Logf: func(format string, args ...any) {
				logger.Trace(fmt.Sprintf(format, args...))
			},
			UserLogf: func(format string, args ...any) {
				logger.Debug(fmt.Sprintf(format, args...))
			},
			Ephemeral:     options.Ephemeral,
			AuthKey:       options.AuthKey,
			ControlURL:    options.ControlURL,
			Port:          options.ListenPort,
			AdvertiseTags: options.AdvertiseTags,
			Dialer:        &endpointDialer{Dialer: outboundDialer, logger: logger},
			LookupHook: func(ctx context.Context, host string) ([]netip.Addr, error) {
				return dnsRouter.Lookup(ctx, host, dialerQueryOptions)
			},
			DNS: &dnsConfigurtor{},
			HTTPClient: &http.Client{
				Transport: &http.Transport{
					ForceAttemptHTTP2: true,
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return outboundDialer.DialContext(ctx, network, M.ParseSocksaddr(address))
					},
					TLSClientConfig: &tls.Config{
						RootCAs: adapter.RootPoolFromContext(ctx),
						Time:    ntp.TimeFuncFromContext(ctx),
					},
				},
			},
		},
		acceptRoutes:               options.AcceptRoutes,
		exitNode:                   options.ExitNode,
		exitNodeAllowLANAccess:     options.ExitNodeAllowLANAccess,
		advertiseRoutes:            options.AdvertiseRoutes,
		advertiseExitNode:          options.AdvertiseExitNode,
		advertiseTags:              options.AdvertiseTags,
		relayServerPort:            options.RelayServerPort,
		relayServerStaticEndpoints: options.RelayServerStaticEndpoints,
		sshServerOptions:           options.SSHServer,
		taildrop:                   newTaildropManager(ctx, logger, tag, taildropDirectory, platformInterface),
		udpTimeout:                 udpTimeout,
		icmpTimeout:                C.ICMPTimeout,
		systemInterface:            options.SystemInterface,
		systemInterfaceName:        options.SystemInterfaceName,
		systemInterfaceMTU:         options.SystemInterfaceMTU,
		keyAuth:                    options.AuthKey != "",
	}
	tailscaleEndpoint.exitNodeActive.Store(false)
	if options.SystemInterface {
		return tailscaleEndpoint, nil
	}
	userspaceEndpoint := &userspaceEndpoint{Endpoint: tailscaleEndpoint}
	tailscaleEndpoint.userspaceHandler = userspaceEndpoint
	return userspaceEndpoint, nil
}

func unwrapEndpoint(raw adapter.Endpoint) (*Endpoint, bool) {
	switch endpoint := raw.(type) {
	case *Endpoint:
		return endpoint, true
	case *userspaceEndpoint:
		return endpoint.Endpoint, true
	default:
		return nil, false
	}
}

func (t *Endpoint) configureDataPlane() {
	if t.systemInterface {
		t.server.DataPlaneMode = tsnet.DataPlaneSystem
	}
}

func (t *Endpoint) acquireGlobalHooks() error {
	tailscaleGlobalHookAccess.Lock()
	defer tailscaleGlobalHookAccess.Unlock()
	if tailscaleGlobalHookOwner != nil && tailscaleGlobalHookOwner != t {
		return E.New("only one Tailscale endpoint can be active per sing-box process while Tailscale socket hooks are process-global")
	}
	tailscaleGlobalHookOwner = t
	t.globalHooksAcquired = true
	return nil
}

func (t *Endpoint) releaseGlobalHooks() {
	tailscaleGlobalHookAccess.Lock()
	defer tailscaleGlobalHookAccess.Unlock()
	if !t.globalHooksAcquired || tailscaleGlobalHookOwner != t {
		t.globalHooksAcquired = false
		return
	}
	netmon.RegisterInterfaceGetter(nil)
	netns.SetControlFunc(nil)
	netns.SetListenPacketFunc(nil)
	tailscaleGlobalHookOwner = nil
	t.globalHooksAcquired = false
}

func (t *Endpoint) Start(stage adapter.StartStage) error {
	switch stage {
	case adapter.StartStateInitialize:
		mkdirErr := filemanager.MkdirAll(t.ctx, t.server.Dir, 0o700)
		if mkdirErr != nil {
			return E.Cause(mkdirErr, "create state directory")
		}
		if !version.IsAppleTV() {
			mkdirErr = filemanager.MkdirAll(t.ctx, t.taildrop.directory, 0o700)
			if mkdirErr != nil {
				return E.Cause(mkdirErr, "create taildrop directory")
			}
		}
		t.server.PeerDNSQueryHandler = (*peerDNSQueryHandler)(t)
	case adapter.StartStateStart:
		return t.start()
	case adapter.StartStatePostStart:
		return t.postStart()
	}
	return nil
}

func (t *Endpoint) start() (retErr error) {
	if err := t.acquireGlobalHooks(); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			t.releaseGlobalHooks()
		}
	}()
	if t.platformInterface != nil && t.platformInterface.UsePlatformNetworkInterfaces() {
		err := t.network.UpdateInterfaces()
		if err != nil {
			return err
		}
		netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
			return common.Map(t.network.InterfaceFinder().Interfaces(), func(it control.Interface) netmon.Interface {
				return netmon.Interface{
					Interface: &net.Interface{
						Index:        it.Index,
						MTU:          it.MTU,
						Name:         it.Name,
						HardwareAddr: it.HardwareAddr,
						Flags:        it.Flags,
					},
					AltAddrs: common.Map(it.Addresses, func(it netip.Prefix) net.Addr {
						return &net.IPNet{
							IP:   it.Addr().AsSlice(),
							Mask: net.CIDRMask(it.Bits(), it.Addr().BitLen()),
						}
					}),
				}
			}), nil
		})
	}
	if t.systemInterface {
		mtu := t.systemInterfaceMTU
		if mtu == 0 {
			mtu = uint32(tsTUN.DefaultTUNMTU())
		}
		t.systemInterfaceMTU = mtu
		tunName := t.systemInterfaceName
		if tunName == "" {
			tunName = tun.CalculateInterfaceName("tailscale")
		}
		tunOptions := tun.Options{
			Name:                      tunName,
			MTU:                       mtu,
			GSO:                       true,
			InterfaceScope:            true,
			InterfaceMonitor:          t.network.InterfaceMonitor(),
			InterfaceFinder:           t.network.InterfaceFinder(),
			Logger:                    t.logger,
			EXP_ExternalConfiguration: true,
		}
		systemTun, err := tun.New(tunOptions)
		if err != nil {
			return err
		}
		err = systemTun.Start()
		if err != nil {
			_ = systemTun.Close()
			return err
		}
		wgTunDevice, err := newTunDeviceAdapter(systemTun, int(mtu), t.logger)
		if err != nil {
			_ = systemTun.Close()
			return err
		}
		systemDialer, err := dialer.NewDefault(t.ctx, option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{
				BindInterface: tunName,
			},
		})
		if err != nil {
			_ = systemTun.Close()
			return err
		}
		t.systemTunDevice = wgTunDevice
		t.systemDialer = systemDialer
		t.systemRouteMu.Lock()
		t.systemRouteManager = newSystemRouteManager(tunName, mtu, t.server.Dir)
		t.systemRouteMu.Unlock()
		t.startSystemRouteUpdater()
		t.server.Tun = wgTunDevice
		t.configureDataPlane()
	}
	if t.network.AutoRedirectOutputMark() != 0 {
		netns.SetControlFunc(t.network.AutoRedirectOutputMarkFunc())
	} else if t.platformInterface != nil && t.platformInterface.UsePlatformNetworkInterfaces() {
		if t.platformInterface.UsePlatformAutoDetectInterfaceControl() {
			netns.SetControlFunc(func(network, address string, conn syscall.RawConn) error {
				return control.Raw(conn, func(fileDescriptor uintptr) error {
					return t.platformInterface.AutoDetectInterfaceControl(int(fileDescriptor))
				})
			})
		} else {
			// NEPacketTunnelProvider sockets are excluded from tunnel routes by
			// NECP; the empty override only suppresses tailscale's own
			// default-interface bind, which would select the sing-box utun.
			netns.SetControlFunc(func(string, string, syscall.RawConn) error {
				return nil
			})
		}
	} else {
		bindFunc := t.network.AutoDetectInterfaceFunc()
		if bindFunc != nil {
			netns.SetControlFunc(bindFunc)
			netns.SetListenPacketFunc(t.listenPacket)
		}
	}
	return nil
}

func (t *Endpoint) listenPacket(ctx context.Context, network string, address string) (nettype.PacketConn, error) {
	listenConfig := net.ListenConfig{
		Control: control.Append(t.network.AutoDetectInterfaceFunc(), control.DisableUDPNetReset()),
	}
	packetConn, err := listenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}
	udpConn := packetConn.(*net.UDPConn)
	egressPool := tun.NewUDPEgressPool(tun.UDPEgressPoolOptions{
		Logger:           t.logger,
		Network:          network,
		InterfaceFinder:  t.network.InterfaceFinder(),
		InterfaceMonitor: t.network.InterfaceMonitor(),
		IsExempt: func() bool {
			return t.network.AutoRedirectOutputMark() != 0
		},
	})
	if !egressPool.SetEgressPort(udpConn.LocalAddr().(*net.UDPAddr).AddrPort().Port()) {
		egressPool.Close()
		return udpConn, nil
	}
	return tun.NewUDPEgressConn(udpConn, egressPool), nil
}

func (t *Endpoint) postStart() error {
	err := t.server.Start()
	if err != nil {
		// tsnet may already have run its error cleanup (which closes the
		// WireGuard device). The adapter's Close is once-guarded, so it is
		// safe to release the ownership retained by start in either case.
		t.stopSystemRouteUpdater()
		if routeErr := t.closeSystemRouteManager(); routeErr != nil {
			err = E.Errors(err, routeErr)
		}
		if t.systemTunDevice != nil {
			_ = t.systemTunDevice.Close()
			t.systemTunDevice = nil
		}
		t.releaseGlobalHooks()
		return err
	}
	localBackend := t.server.ExportLocalBackend()
	t.localBackend = localBackend
	// Publish the started state only after the backend handle is available. This
	// keeps callbacks and route reconciliation from observing a half-initialized
	// server during the startup handoff.
	t.serverStarted.Store(true)
	if !version.IsAppleTV() && !t.systemInterface {
		registerTaildropEndpoint(localBackend, t)
		go t.taildrop.start()
	}
	wgEngine := localBackend.ExportEngine().(wgengine.ExportedUserspaceEngine)
	wgEngine.SetOnReconfigListener(t.onReconfig)
	t.wgEngine = wgEngine
	// Server.Start can complete before the first engine reconfiguration is
	// delivered to our listener.  Queue one reconciliation after the listener
	// and server state are ready so an already-configured exit node cannot
	// miss its initial scoped routes.
	t.requestSystemRouteUpdate()

	if !t.systemInterface {
		err = t.startUserspaceDataPlane()
		if err != nil {
			return err
		}
	}

	sshEnabled := t.sshServerOptions != nil && t.sshServerOptions.Enabled
	if sshEnabled {
		degraded, fatal := tailssh.CheckServerSupport(t.platformInterface)
		if fatal != nil {
			t.logger.Warn(E.Cause(fatal, "SSH server unavailable"))
			sshEnabled = false
		} else if degraded != "" {
			t.logger.Warn("SSH server degraded: ", degraded)
		}
	}
	err = t.editPrefs(sshEnabled)
	if err != nil {
		return err
	}
	if sshEnabled {
		sshServer, err := tailssh.New(t.ctx, t.server, t.platformInterface, t.sshServerOptions, t.logger)
		if err != nil {
			return E.Cause(err, "create SSH server")
		}
		err = sshServer.Start()
		if err != nil {
			return E.Cause(err, "start SSH server")
		}
		t.sshReconfigHook = sshServer.OnReconfig
		t.sshServerInstance = sshServer
	}
	go t.watchState()
	t.started.Store(true)
	return nil
}

func (t *Endpoint) startUserspaceDataPlane() error {
	if t.fallbackTCPCloser == nil {
		t.fallbackTCPCloser = t.server.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
			return func(conn net.Conn) {
				ctx := log.ContextWithNewID(t.ctx)
				source := M.SocksaddrFrom(src.Addr(), src.Port())
				destination := M.SocksaddrFrom(dst.Addr(), dst.Port())
				t.NewConnectionEx(ctx, conn, source, destination, nil)
			}, true
		})
	}
	netstack := t.server.ExportNetstack()
	if netstack == nil {
		return E.New("missing Tailscale userspace netstack")
	}
	ipStack := netstack.ExportIPStack()
	gErr := ipStack.SetSpoofing(tun.DefaultNIC, true)
	if gErr != nil {
		return gonet.TranslateNetstackError(gErr)
	}
	gErr = ipStack.SetPromiscuousMode(tun.DefaultNIC, true)
	if gErr != nil {
		return gonet.TranslateNetstackError(gErr)
	}
	if t.userspaceHandler == nil {
		return E.New("missing Tailscale userspace packet handler")
	}
	icmpForwarder := tun.NewICMPForwarder(ipStack, t.userspaceHandler, t.logger)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpForwarder.HandlePacket)
	t.stack = ipStack
	t.icmpForwarder = icmpForwarder

	previousTCP := netstack.GetTCPHandlerForFlow
	netstack.GetTCPHandlerForFlow = func(src, dst netip.AddrPort) (handler func(net.Conn), intercept bool) {
		if previousTCP != nil {
			handler, intercept = previousTCP(src, dst)
			if handler != nil || !intercept {
				return handler, intercept
			}
		}
		return func(conn net.Conn) {
			ctx := log.ContextWithNewID(t.ctx)
			source := M.SocksaddrFrom(src.Addr(), src.Port())
			destination := M.SocksaddrFrom(dst.Addr(), dst.Port())
			t.NewConnectionEx(ctx, conn, source, destination, nil)
		}, true
	}

	previousUDP := netstack.GetUDPHandlerForFlow
	netstack.GetUDPHandlerForFlow = func(src, dst netip.AddrPort) (handler func(nettype.ConnPacketConn), intercept bool) {
		if previousUDP != nil {
			handler, intercept = previousUDP(src, dst)
			if handler != nil || !intercept {
				return handler, intercept
			}
		}
		return func(conn nettype.ConnPacketConn) {
			ctx := log.ContextWithNewID(t.ctx)
			source := M.SocksaddrFrom(src.Addr(), src.Port())
			destination := M.SocksaddrFrom(dst.Addr(), dst.Port())
			packetConn := bufio.NewUnbindPacketConnWithAddr(conn, destination)
			t.NewPacketConnectionEx(ctx, packetConn, source, destination, nil)
		}, true
	}
	return nil
}

func (t *Endpoint) watchState() {
	localBackend := t.server.ExportLocalBackend()
	var reportedAuthURL string
	exitNodePending := t.exitNode != ""
	running := false
	tryApplyExitNode := func() {
		err := t.applyExitNode()
		if err != nil {
			t.logger.Error("set exit node: ", err)
		} else {
			exitNodePending = false
		}
	}
	for {
		var busError string
		localBackend.WatchNotifications(t.ctx, ipn.NotifyInitialState|ipn.NotifyPeerPatches, nil, func(roNotify *ipn.Notify) (keepGoing bool) {
			if roNotify.ErrMessage != nil {
				busError = *roNotify.ErrMessage
				return false
			}
			if running && exitNodePending && len(roNotify.PeersChanged) > 0 {
				tryApplyExitNode()
			}
			if roNotify.State == nil && roNotify.BrowseToURL == nil {
				return true
			}
			status := localBackend.StatusWithoutPeers()
			prefs := localBackend.Prefs()
			t.exitNodeActive.Store(prefs.ExitNodeID() != "" || prefs.ExitNodeIP().IsValid() || prefs.AutoExitNode().IsSet())
			t.requestSystemRouteUpdate()
			running = status.BackendState == ipn.Running.String()
			switch status.BackendState {
			case ipn.NoState.String(), ipn.NeedsLogin.String():
				if t.exitNode != "" {
					exitNodePending = true
				}
				authURL := status.AuthURL
				if authURL == "" || authURL == reportedAuthURL {
					return true
				}
				reportedAuthURL = authURL
				t.logger.Info("Waiting for authentication: ", authURL)
				if t.platformInterface != nil && t.platformInterface.UsePlatformNotification() {
					err := t.platformInterface.SendNotification(&adapter.Notification{
						Identifier: "tailscale-authentication",
						TypeName:   "Tailscale Authentication Notifications",
						TypeID:     10,
						Title:      "Tailscale Authentication",
						Body:       F.ToString("Tailscale outbound[", t.Tag(), "] is waiting for authentication."),
						OpenURL:    authURL,
					})
					if err != nil {
						t.logger.Error("send authentication notification: ", err)
					}
				}
			case ipn.Running.String():
				reportedAuthURL = ""
				if exitNodePending {
					tryApplyExitNode()
				}
			}
			return true
		})
		if t.ctx.Err() != nil {
			return
		}
		if busError != "" {
			t.logger.Warn("restarting state watcher: ", busError)
		} else {
			t.logger.Warn("state watcher stopped unexpectedly, restarting")
		}
		select {
		case <-t.ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (t *Endpoint) editPrefs(sshEnabled bool) error {
	perfs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			RouteAll:        t.acceptRoutes,
			AdvertiseRoutes: t.advertiseRoutes,
			RunSSH:          sshEnabled,
		},
		RouteAllSet:                   true,
		ExitNodeIPSet:                 true,
		AdvertiseRoutesSet:            true,
		RunSSHSet:                     true,
		RelayServerPortSet:            true,
		RelayServerStaticEndpointsSet: true,
	}
	if t.advertiseExitNode {
		perfs.AdvertiseRoutes = append(perfs.AdvertiseRoutes, tsaddr.ExitRoutes()...)
	}
	if t.relayServerPort != nil {
		perfs.RelayServerPort = t.relayServerPort
	}
	if len(t.relayServerStaticEndpoints) > 0 {
		perfs.RelayServerStaticEndpoints = t.relayServerStaticEndpoints
	}
	_, err := t.server.ExportLocalBackend().EditPrefs(perfs)
	if err != nil {
		return E.Cause(err, "update prefs")
	}
	return nil
}

func (t *Endpoint) applyExitNode() error {
	t.exitNodeUpdateMu.Lock()
	defer t.exitNodeUpdateMu.Unlock()
	status, err := common.Must1(t.server.LocalClient()).Status(t.ctx)
	if err != nil {
		return err
	}
	perfs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ExitNodeAllowLANAccess: t.exitNodeAllowLANAccess,
		},
		ExitNodeIPSet:             true,
		ExitNodeAllowLANAccessSet: true,
	}
	err = perfs.SetExitNodeIP(t.exitNode, status)
	if err != nil {
		return err
	}
	_, err = t.server.ExportLocalBackend().EditPrefs(perfs)
	if err != nil {
		return err
	}
	t.exitNodeActive.Store(t.exitNode != "")
	ctx, cancel := context.WithTimeout(t.ctx, systemRouteApplyTimeout)
	defer cancel()
	if err = t.requestSystemRouteUpdateAndWait(ctx); err != nil {
		return E.Cause(err, "activate Tailscale system exit route")
	}
	return nil
}

func (t *Endpoint) SetTailscaleExitNode(ctx context.Context, stableID string) error {
	t.exitNodeUpdateMu.Lock()
	defer t.exitNodeUpdateMu.Unlock()
	if !t.started.Load() {
		return E.New("Tailscale is not ready yet")
	}
	if t.advertiseExitNode && stableID != "" {
		return E.New("cannot advertise an exit node and use an exit node at the same time")
	}
	perfs := &ipn.MaskedPrefs{
		Prefs: ipn.Prefs{
			ExitNodeID:             tailcfg.StableNodeID(stableID),
			ExitNodeAllowLANAccess: t.exitNodeAllowLANAccess,
		},
		ExitNodeIDSet:             true,
		ExitNodeIPSet:             true,
		ExitNodeAllowLANAccessSet: true,
	}
	if stableID != "" {
		status, err := common.Must1(t.server.LocalClient()).Status(ctx)
		if err != nil {
			return E.Cause(err, "get tailscale status")
		}
		found := false
		for _, peer := range status.Peer {
			if peer.ID != tailcfg.StableNodeID(stableID) {
				continue
			}
			if !peer.ExitNodeOption {
				return E.New("peer does not offer exit node: ", stableID)
			}
			found = true
			break
		}
		if !found {
			return E.New("peer not found: ", stableID)
		}
	}
	_, err := t.server.ExportLocalBackend().EditPrefs(perfs)
	if err != nil {
		return E.Cause(err, "update prefs")
	}
	t.exitNodeActive.Store(stableID != "")
	if err = t.requestSystemRouteUpdateAndWait(ctx); err != nil {
		return E.Cause(err, "reconcile Tailscale system exit route")
	}
	return nil
}

func (t *Endpoint) Logout(ctx context.Context) error {
	t.exitNodeUpdateMu.Lock()
	defer t.exitNodeUpdateMu.Unlock()
	if !t.started.Load() {
		return E.New("Tailscale is not ready yet")
	}
	err := common.Must1(t.server.LocalClient()).Logout(ctx)
	if err != nil {
		return E.Cause(err, "tailscale logout")
	}
	// LocalBackend.Logout deletes the profile and restarts the backend with
	// empty preferences, and only tsnet.Server.Start performs the login
	// bootstrap, so redo it here to obtain a new auth URL.
	localBackend := t.server.ExportLocalBackend()
	prefs := ipn.NewPrefs()
	prefs.Hostname = t.server.Hostname
	prefs.WantRunning = true
	prefs.ControlURL = t.server.ControlURL
	prefs.AdvertiseTags = t.server.AdvertiseTags
	err = localBackend.Start(ipn.Options{UpdatePrefs: prefs})
	if err != nil {
		return E.Cause(err, "restart backend")
	}
	err = t.editPrefs(t.sshServerInstance != nil)
	if err != nil {
		return err
	}
	err = localBackend.StartLoginInteractive(ctx)
	if err != nil {
		return E.Cause(err, "start interactive login")
	}
	t.exitNodeActive.Store(false)
	if err = t.requestSystemRouteUpdateAndWait(ctx); err != nil {
		return E.Cause(err, "remove Tailscale system exit route")
	}
	return nil
}

func (t *Endpoint) Close() error {
	var err error
	t.started.Store(false)
	serverWasStarted := t.serverStarted.Swap(false)
	t.stopSystemRouteUpdater()
	if routeErr := t.closeSystemRouteManagerWithRetry(); routeErr != nil {
		err = routeErr
	}
	if t.localBackend != nil {
		unregisterTaildropEndpoint(t.localBackend)
		t.localBackend = nil
	}
	t.taildrop.close()
	if t.icmpForwarder != nil {
		t.icmpForwarder.Close()
		t.icmpForwarder = nil
	}
	common.Close(common.PtrOrNil(t.sshServerInstance))
	t.sshServerInstance = nil
	if serverWasStarted {
		err = E.Errors(err, common.Close(common.PtrOrNil(t.server)))
	}
	t.releaseGlobalHooks()
	if t.fallbackTCPCloser != nil {
		t.fallbackTCPCloser()
		t.fallbackTCPCloser = nil
	}
	if t.systemTunDevice != nil {
		// Server.Close normally closes this first through wgengine. The
		// adapter owns the raw TUN and makes this second cleanup harmless.
		_ = t.systemTunDevice.Close()
		t.systemTunDevice = nil
	}
	return err
}

func (t *Endpoint) InterfaceUpdated(ctx context.Context) {
	if !t.started.Load() {
		return
	}
	netMon, loaded := t.server.Sys().NetMon.GetOK()
	if loaded && netMon != nil {
		netMon.InjectEvent()
	}
	t.requestSystemRouteUpdate()
}

func (t *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch network {
	case N.NetworkTCP:
		t.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		t.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if !t.started.Load() {
		return nil, E.New("Tailscale is not ready yet")
	}
	if destination.IsDomain() {
		destinationAddresses, err := t.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, t, network, destination, destinationAddresses)
	}
	if t.systemDialer != nil {
		return t.systemDialer.DialContext(ctx, network, destination)
	}
	addr4, addr6 := t.server.TailscaleIPs()
	remoteAddr := tcpip.FullAddress{
		NIC:  1,
		Port: destination.Port,
		Addr: addressFromAddr(destination.Addr),
	}
	var localAddr tcpip.FullAddress
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		if !addr4.IsValid() {
			return nil, E.New("missing Tailscale IPv4 address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		localAddr = tcpip.FullAddress{
			NIC:  1,
			Addr: addressFromAddr(addr4),
		}
	} else {
		if !addr6.IsValid() {
			return nil, E.New("missing Tailscale IPv6 address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		localAddr = tcpip.FullAddress{
			NIC:  1,
			Addr: addressFromAddr(addr6),
		}
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		tcpConn, err := gonet.DialTCPWithBind(ctx, t.stack, localAddr, remoteAddr, networkProtocol)
		if err != nil {
			return nil, err
		}
		return tcpConn, nil
	case N.NetworkUDP:
		udpConn, err := gonet.DialUDP(t.stack, &localAddr, &remoteAddr, networkProtocol)
		if err != nil {
			return nil, err
		}
		return udpConn, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (t *Endpoint) listenPacketWithAddress(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !t.started.Load() {
		return nil, E.New("Tailscale is not ready yet")
	}
	if t.systemDialer != nil {
		return t.systemDialer.ListenPacket(ctx, destination)
	}
	addr4, addr6 := t.server.TailscaleIPs()
	bind := tcpip.FullAddress{
		NIC: 1,
	}
	var networkProtocol tcpip.NetworkProtocolNumber
	if destination.IsIPv4() {
		if !addr4.IsValid() {
			return nil, E.New("missing Tailscale IPv4 address")
		}
		networkProtocol = header.IPv4ProtocolNumber
		bind.Addr = addressFromAddr(addr4)
	} else {
		if !addr6.IsValid() {
			return nil, E.New("missing Tailscale IPv6 address")
		}
		networkProtocol = header.IPv6ProtocolNumber
		bind.Addr = addressFromAddr(addr6)
	}
	udpConn, err := gonet.DialUDP(t.stack, &bind, nil, networkProtocol)
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}

func (t *Endpoint) ListenPacketWithDestination(ctx context.Context, destination M.Socksaddr) (net.PacketConn, netip.Addr, error) {
	t.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if destination.IsDomain() {
		destinationAddresses, err := t.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, netip.Addr{}, err
		}
		var errors []error
		for _, address := range destinationAddresses {
			packetConn, packetErr := t.listenPacketWithAddress(ctx, M.SocksaddrFrom(address, destination.Port))
			if packetErr == nil {
				return iponly.NewPacketConn(t.logger, packetConn), address, nil
			}
			errors = append(errors, packetErr)
		}
		return nil, netip.Addr{}, E.Errors(errors...)
	}
	packetConn, err := t.listenPacketWithAddress(ctx, destination)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if destination.IsIP() {
		return iponly.NewPacketConn(t.logger, packetConn), destination.Addr, nil
	}
	return iponly.NewPacketConn(t.logger, packetConn), netip.Addr{}, nil
}

func (t *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	packetConn, destinationAddress, err := t.ListenPacketWithDestination(ctx, destination)
	if err != nil {
		return nil, err
	}
	if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
	}
	return packetConn, nil
}

func (t *Endpoint) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = t.Tag()
	metadata.InboundType = t.Type()
	metadata.Source = source
	destinationAddress := tsaddr.UnmapVia(destination.Addr)
	if destinationAddress != destination.Addr {
		destination.Addr = destinationAddress
	} else {
		addr4, addr6 := t.server.TailscaleIPs()
		switch destination.Addr {
		case addr4:
			destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
		case addr6:
			destination.Addr = netip.IPv6Loopback()
		}
	}
	metadata.Destination = destination
	t.logger.InfoContext(ctx, "inbound connection from ", source)
	t.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	t.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (t *Endpoint) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = t.Tag()
	metadata.InboundType = t.Type()
	metadata.Source = source
	originDestination := destination
	destinationAddress := tsaddr.UnmapVia(destination.Addr)
	if destinationAddress != destination.Addr {
		destination.Addr = destinationAddress
	} else {
		addr4, addr6 := t.server.TailscaleIPs()
		switch destination.Addr {
		case addr4:
			destination.Addr = netip.AddrFrom4([4]uint8{127, 0, 0, 1})
		case addr6:
			destination.Addr = netip.IPv6Loopback()
		}
	}
	if destination != originDestination {
		metadata.OriginDestination = originDestination
		conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), originDestination, destination)
	}
	metadata.Destination = destination
	t.logger.InfoContext(ctx, "inbound packet connection from ", source)
	t.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
	t.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (t *Endpoint) PreferredDomain(metadata *adapter.InboundContext, domain string) bool {
	routeDomains := t.routeDomains.Load()
	if routeDomains == nil {
		return false
	}
	domain = strings.ToLower(domain)
	if routeDomains[domain] {
		return true
	}
	if t.started.Load() {
		magicHosts := t.server.ExportLocalBackend().ExportMagicDNSHosts()
		if _, found := lookupHosts(nil, magicHosts, domain); found {
			return true
		}
	}
	for _, suffix := range t.routeSuffixes.Load() {
		if mDNS.IsSubDomain(suffix, domain) {
			return true
		}
	}
	return !strings.Contains(domain, ".") && t.searchDomains.Load()
}

func (t *Endpoint) PreferredAddress(metadata *adapter.InboundContext, address netip.Addr) bool {
	if !t.started.Load() {
		return false
	}
	peer, found := t.server.ExportLocalBackend().PeerForIP(address)
	return found && !peer.IsSelf && peer.Route.Bits() > 0
}

func (t *Endpoint) Server() *tsnet.Server {
	return t.server
}

func (t *Endpoint) onReconfig(cfg *wgcfg.Config, routerCfg *router.Config, dnsCfg *tsDNS.Config) {
	// Route readiness depends on the WireGuard/TUN address state, not on DNS.
	// Queue reconciliation before the config guard so an address-only reconfig
	// can wake a pending exit-node activation.
	t.requestSystemRouteUpdate()
	if cfg == nil || dnsCfg == nil {
		return
	}
	// The Tailscale fork intentionally removes exit-node /0 routes from the
	// OS router configuration. Reconcile the scoped defaults independently so
	// sockets bound to this system interface still reach the selected exit
	// node without hijacking Tailscale's control-plane sockets.
	// The engine invokes the listener on every Reconfig call, including
	// unchanged ones: SSH policy lives only in the netmap, outside the
	// three configs, so the SSH hook must run before the change check.
	if t.sshReconfigHook != nil {
		t.sshReconfigHook(cfg, routerCfg, dnsCfg)
	}
	if t.cfg != nil && reflect.DeepEqual(t.cfg, cfg) &&
		t.routerCfg != nil && reflect.DeepEqual(t.routerCfg, routerCfg) &&
		t.dnsCfg != nil && reflect.DeepEqual(t.dnsCfg, dnsCfg) {
		return
	}
	t.cfg = cfg
	t.routerCfg = routerCfg
	t.dnsCfg = dnsCfg

	routeDomains := make(map[string]bool)
	for fqdn := range dnsCfg.Hosts {
		routeDomains[fqdn.WithoutTrailingDot()] = true
	}
	for _, fqdn := range dnsCfg.SearchDomains {
		routeDomains[fqdn.WithoutTrailingDot()] = true
	}
	routeSuffixes := make([]string, 0, len(dnsCfg.Routes))
	for fqdn := range dnsCfg.Routes {
		routeSuffixes = append(routeSuffixes, fqdn.WithoutTrailingDot())
	}
	t.routeDomains.Store(routeDomains)
	t.routeSuffixes.Store(routeSuffixes)
	t.searchDomains.Store(len(dnsCfg.SearchDomains) > 0)

	if t.onReconfigHook != nil {
		t.onReconfigHook(cfg, routerCfg, dnsCfg)
	}
}

func (t *Endpoint) updateSystemRoutes() {
	_, _ = t.updateSystemRoutesResult()
}

func (t *Endpoint) updateSystemRoutesResult() (uint64, error) {
	t.systemRouteMu.Lock()
	generation := t.systemRouteGeneration
	manager := t.systemRouteManager
	t.systemRouteMu.Unlock()
	if manager == nil || t.server == nil || !t.serverStarted.Load() {
		return generation, nil
	}
	ip4, ip6 := t.server.TailscaleIPs()
	enabled := t.exitNodeActive.Load()
	if systemRouteRequiresAddress && enabled && !validSystemRouteAddress(ip4) && !validSystemRouteAddress(ip6) {
		if err := manager.Update(enabled, ip4, ip6); err != nil {
			return generation, err
		}
		return generation, errSystemRouteAddressPending
	}
	if err := manager.Update(enabled, ip4, ip6); err != nil {
		if isTransientSystemRouteError(err) {
			t.logger.Debug("update Tailscale system exit routes: ", err)
		} else {
			t.logger.Warn("update Tailscale system exit routes: ", err)
		}
		return generation, err
	}
	return generation, nil
}

func validSystemRouteAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified()
}

// startSystemRouteUpdater moves route socket I/O off Tailscale's reconfigure
// callback. The callback runs while the engine's internal wireguard lock is
// held; a stalled routing socket must not block control-plane convergence.
func (t *Endpoint) startSystemRouteUpdater() {
	t.systemRouteMu.Lock()
	if t.systemRouteUpdate != nil || t.systemRouteStopping {
		t.systemRouteMu.Unlock()
		return
	}
	updates := make(chan struct{}, 1)
	stop := make(chan struct{})
	t.systemRouteUpdate = updates
	t.systemRouteStop = stop
	if t.systemRouteWaiters == nil {
		t.systemRouteWaiters = make(map[uint64]chan error)
	}
	t.systemRouteWG.Add(1)
	t.systemRouteMu.Unlock()
	go func() {
		defer t.systemRouteWG.Done()
		runSystemRouteUpdater(
			updates,
			stop,
			t.updateSystemRoutesResult,
			t.completeSystemRouteGeneration,
			systemRouteRetryMinDelay,
			systemRouteRetryMaxDelay,
		)
	}()
}

func runSystemRouteUpdater(
	updates <-chan struct{},
	stop <-chan struct{},
	update func() (uint64, error),
	complete func(uint64, error),
	retryMinDelay time.Duration,
	retryMaxDelay time.Duration,
) {
	if retryMinDelay <= 0 {
		retryMinDelay = time.Millisecond
	}
	if retryMaxDelay < retryMinDelay {
		retryMaxDelay = retryMinDelay
	}
	for {
		select {
		case _, loaded := <-updates:
			if !loaded {
				return
			}
		case <-stop:
			return
		}
		retryDelay := retryMinDelay
		for {
			select {
			case <-stop:
				return
			default:
			}
			generation, err := update()
			if err == nil {
				complete(generation, nil)
				break
			}
			if !isTransientSystemRouteError(err) {
				complete(generation, err)
				break
			}
			timer := time.NewTimer(retryDelay)
			select {
			case _, loaded := <-updates:
				stopSystemRouteRetryTimer(timer)
				if !loaded {
					return
				}
				retryDelay = retryMinDelay
				continue
			case <-stop:
				stopSystemRouteRetryTimer(timer)
				return
			case <-timer.C:
				if retryDelay < retryMaxDelay {
					retryDelay *= 2
					if retryDelay > retryMaxDelay {
						retryDelay = retryMaxDelay
					}
				}
			}
		}
	}
}

func stopSystemRouteRetryTimer(timer *time.Timer) {
	if timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (t *Endpoint) queueSystemRouteUpdate(waiter chan error) (uint64, bool) {
	t.systemRouteMu.Lock()
	updates := t.systemRouteUpdate
	if updates == nil || !t.serverStarted.Load() {
		t.systemRouteMu.Unlock()
		return 0, false
	}
	t.systemRouteGeneration++
	generation := t.systemRouteGeneration
	if waiter != nil {
		if t.systemRouteWaiters == nil {
			t.systemRouteWaiters = make(map[uint64]chan error)
		}
		t.systemRouteWaiters[generation] = waiter
	}
	t.systemRouteMu.Unlock()
	select {
	case updates <- struct{}{}:
	default:
	}
	return generation, true
}

func (t *Endpoint) requestSystemRouteUpdate() {
	_, _ = t.queueSystemRouteUpdate(nil)
}

func (t *Endpoint) requestSystemRouteUpdateAndWait(ctx context.Context) error {
	if !t.systemInterface {
		return nil
	}
	waiter := make(chan error, 1)
	generation, queued := t.queueSystemRouteUpdate(waiter)
	if !queued {
		return nil
	}
	select {
	case err := <-waiter:
		return err
	case <-ctx.Done():
		t.systemRouteMu.Lock()
		if current, loaded := t.systemRouteWaiters[generation]; loaded && current == waiter {
			delete(t.systemRouteWaiters, generation)
		}
		t.systemRouteMu.Unlock()
		return ctx.Err()
	}
}

func (t *Endpoint) completeSystemRouteGeneration(generation uint64, err error) {
	t.systemRouteMu.Lock()
	for waiterGeneration, waiter := range t.systemRouteWaiters {
		if waiterGeneration > generation {
			continue
		}
		delete(t.systemRouteWaiters, waiterGeneration)
		waiter <- err
	}
	t.systemRouteMu.Unlock()
}

func (t *Endpoint) failSystemRouteWaiters(err error) {
	t.systemRouteMu.Lock()
	for generation, waiter := range t.systemRouteWaiters {
		delete(t.systemRouteWaiters, generation)
		waiter <- err
	}
	t.systemRouteMu.Unlock()
}

func (t *Endpoint) stopSystemRouteUpdater() {
	t.systemRouteMu.Lock()
	stop := t.systemRouteStop
	if stop == nil || t.systemRouteStopping {
		t.systemRouteMu.Unlock()
		return
	}
	t.systemRouteStopping = true
	close(stop)
	t.systemRouteMu.Unlock()
	t.systemRouteWG.Wait()
	t.systemRouteMu.Lock()
	if t.systemRouteStop == stop {
		t.systemRouteStop = nil
		t.systemRouteUpdate = nil
	}
	t.systemRouteStopping = false
	t.systemRouteMu.Unlock()
	t.failSystemRouteWaiters(net.ErrClosed)
}

func (t *Endpoint) closeSystemRouteManager() error {
	t.systemRouteMu.Lock()
	manager := t.systemRouteManager
	t.systemRouteMu.Unlock()
	if manager == nil {
		return nil
	}
	err := manager.Close()
	if err == nil {
		t.systemRouteMu.Lock()
		if t.systemRouteManager == manager {
			t.systemRouteManager = nil
		}
		t.systemRouteMu.Unlock()
	}
	return err
}

func (t *Endpoint) closeSystemRouteManagerWithRetry() error {
	var lastErr error
	for attempt := 0; attempt < systemRouteCloseAttempts; attempt++ {
		lastErr = t.closeSystemRouteManager()
		if lastErr == nil || !isTransientSystemRouteError(lastErr) {
			return lastErr
		}
		if attempt+1 == systemRouteCloseAttempts {
			break
		}
		time.Sleep(systemRouteCloseDelay)
	}
	return lastErr
}

func addressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	} else {
		return tcpip.AddrFrom4(destination.As4())
	}
}

type endpointDialer struct {
	N.Dialer
	logger logger.ContextLogger
}

func (d *endpointDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		d.logger.InfoContext(ctx, "output connection to ", destination)
	case N.NetworkUDP:
		d.logger.InfoContext(ctx, "output packet connection to ", destination)
	}
	return d.Dialer.DialContext(ctx, network, destination)
}

func (d *endpointDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	d.logger.InfoContext(ctx, "output packet connection")
	return d.Dialer.ListenPacket(ctx, destination)
}

type dnsConfigurtor struct {
	baseConfig tsDNS.OSConfig
}

func (c *dnsConfigurtor) SetDNS(cfg tsDNS.OSConfig) error {
	c.baseConfig = cfg
	return nil
}

func (c *dnsConfigurtor) SupportsSplitDNS() bool {
	return true
}

func (c *dnsConfigurtor) GetBaseConfig() (tsDNS.OSConfig, error) {
	return c.baseConfig, nil
}

func (c *dnsConfigurtor) Close() error {
	return nil
}

type peerDNSQueryHandler Endpoint

func (t *peerDNSQueryHandler) HandlePeerDNSQuery(ctx context.Context, query []byte, sourceAddress netip.AddrPort, allowName func(name string) bool) ([]byte, error) {
	var message mDNS.Msg
	err := message.Unpack(query)
	if err != nil {
		return nil, err
	}
	for _, question := range message.Question {
		if allowName != nil && !allowName(question.Name) {
			return dns.FixedResponseStatus(&message, mDNS.RcodeRefused).Pack()
		}
	}
	var metadata adapter.InboundContext
	metadata.Inbound = t.Tag()
	metadata.InboundType = t.Type()
	metadata.Source = M.SocksaddrFromNetIP(sourceAddress)
	response, err := t.dnsRouter.Exchange(adapter.WithContext(ctx, &metadata), &message, adapter.DNSQueryOptions{})
	if err != nil {
		if !R.IsRejected(err) && !E.IsClosedOrCanceled(err) {
			t.logger.ErrorContext(ctx, E.Cause(err, "process peer DNS query"))
		}
		return nil, err
	}
	return response.Pack()
}
