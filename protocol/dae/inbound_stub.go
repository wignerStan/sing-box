//go:build !linux || android

package dae

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewInbound(context.Context, adapter.Router, log.ContextLogger, string, option.DAEInboundOptions) (adapter.Inbound, error) {
	return nil, E.New("dae inbound is only supported on Linux")
}
