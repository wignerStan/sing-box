package dialer

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

type exclusiveOutputMarkOwnerKey struct{}

// ContextWithExclusiveOutputMark declares socket mark ownership before the
// capture runtime starts. Dialers can then reject conflicting explicit marks
// during configuration checks, before any capture hooks are attached.
func ContextWithExclusiveOutputMark(ctx context.Context, owner string) context.Context {
	return context.WithValue(ctx, exclusiveOutputMarkOwnerKey{}, owner)
}

func checkExclusiveOutputMark(ctx context.Context, options option.DialerOptions) error {
	owner, _ := ctx.Value(exclusiveOutputMarkOwnerKey{}).(string)
	if owner == "" {
		return nil
	}
	if options.RoutingMark != 0 {
		return E.New("routing_mark conflicts with ", owner, " automatic output mark; remove the explicit mark")
	}
	networkManager := service.FromContext[adapter.NetworkManager](ctx)
	if networkManager != nil && networkManager.DefaultOptions().RoutingMark != 0 {
		return E.New("route.default_mark conflicts with ", owner, " automatic output mark; remove the explicit mark")
	}
	return nil
}
