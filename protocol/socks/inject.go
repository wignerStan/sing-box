package socks

import (
	"errors"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
)

// NewInjectableInbound constructs a SOCKS protocol endpoint with no network
// listener. The embedding transport injects accepted net.Conn values through
// NewConnection and remains responsible for waiting on the close callback.
func NewInjectableInbound(router adapter.Router, logger log.ContextLogger, tag string, provider CredentialProvider) (*Inbound, error) {
	if provider == nil {
		return nil, errors.New("nil SOCKS credential provider")
	}
	h := &Inbound{
		Adapter:    inbound.NewAdapter(C.TypeSOCKS, tag),
		router:     uot.NewRouter(router, logger),
		logger:     logger,
		udpTimeout: C.UDPTimeout,
	}
	if err := h.SetCredentialProvider(provider); err != nil {
		return nil, err
	}
	return h, nil
}
