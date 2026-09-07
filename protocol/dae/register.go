//go:build linux && !android && with_dae

package dae

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.DAEInboundOptions](registry, C.TypeDAE, NewInbound)
}
