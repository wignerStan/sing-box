package socks

import (
	std_bufio "bufio"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SocksInboundOptions](registry, C.TypeSOCKS, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

// CredentialProvider is the reverse-control boundary used by an embedding
// application that owns credential persistence and source-admission policy.
// Verifier returns one immutable per-connection view. The verifier receives
// the SOCKS username and password while its provider-bound closure retains the
// observed source address.
type CredentialProvider interface {
	Verifier(source M.Socksaddr) (auth.Verifier, error)
}

type credentialProviderRef struct {
	provider CredentialProvider
}

type Inbound struct {
	inbound.Adapter
	router             adapter.ConnectionRouterEx
	logger             logger.ContextLogger
	listener           *listener.Listener
	authenticator      *auth.Authenticator
	credentialProvider atomic.Pointer[credentialProviderRef]
	udpTimeout         time.Duration
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SocksInboundOptions) (adapter.Inbound, error) {
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	inbound := &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeSOCKS, tag),
		router:        uot.NewRouter(router, logger),
		logger:        logger,
		authenticator: auth.NewAuthenticator(options.Users),
		udpTimeout:    udpTimeout,
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.listener == nil {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	if h.listener == nil {
		return nil
	}
	return h.listener.Close()
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	var verifier auth.Verifier = h.authenticator
	providerRef := h.credentialProvider.Load()
	if providerRef != nil {
		providedVerifier, err := providerRef.provider.Verifier(metadata.Source)
		if err != nil || providedVerifier == nil {
			N.CloseOnHandshakeFailure(conn, onClose, errors.New("SOCKS credentials unavailable"))
			h.logger.WarnContext(ctx, "rejected connection from ", metadata.Source)
			return
		}
		verifier = providedVerifier
	}
	var packetListener socks.PacketListener = disabledPacketListener{}
	if h.listener != nil {
		packetListener = h.listener
	}
	err := socks.HandleConnectionEx(ctx, conn, std_bufio.NewReader(conn), verifier, adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.streamUserPacketConnection), packetListener, h.udpTimeout, metadata.Source, onClose)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed during SOCKS handshake")
		} else {
			// sing's authentication error currently includes the supplied
			// password. Never forward a SOCKS handshake error into logs.
			h.logger.ErrorContext(ctx, "SOCKS handshake failed from ", metadata.Source)
		}
	}
}

type disabledPacketListener struct{}

func (disabledPacketListener) ListenPacket(net.ListenConfig, context.Context, string, string) (net.PacketConn, error) {
	return nil, errors.New("SOCKS UDP associate is disabled")
}

// SetCredentialProvider installs the application-owned credential and source
// admission boundary before the inbound starts. Runtime credential revisions
// remain inside that stable provider and cannot replace protocol behavior.
func (h *Inbound) SetCredentialProvider(provider CredentialProvider) error {
	if provider == nil {
		return errors.New("nil SOCKS credential provider")
	}
	if !h.credentialProvider.CompareAndSwap(nil, &credentialProviderRef{provider: provider}) {
		return errors.New("SOCKS credential provider is already set")
	}
	return nil
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (h *Inbound) streamUserPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		if !metadata.Destination.IsValid() {
			h.logger.InfoContext(ctx, "inbound packet connection")
		} else {
			h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
		}
		h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	if !metadata.Destination.IsValid() {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection")
	} else {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}
