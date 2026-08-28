//go:build !linux || android || !with_dae

package include

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func registerDAEInbound(registry *inbound.Registry) {
	inbound.Register[option.DAEInboundOptions](registry, C.TypeDAE, func(context.Context, adapter.Router, log.ContextLogger, string, option.DAEInboundOptions) (adapter.Inbound, error) {
		return nil, E.New(`dae eBPF inbound is not included in this build; use Linux and rebuild with -tags with_dae`)
	})
}
