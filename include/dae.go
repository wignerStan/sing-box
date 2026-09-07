//go:build linux && !android && with_dae

package include

import (
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/protocol/dae"
)

func registerDAEInbound(registry *inbound.Registry) {
	dae.RegisterInbound(registry)
}
