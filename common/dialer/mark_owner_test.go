package dialer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/service"
)

type configuredMarkNetworkManager struct {
	*route.NetworkManager
	options adapter.NetworkOptions
}

func (m *configuredMarkNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return m.options
}

func TestDeclaredOutputMarkRejectsExplicitMarksBeforeRuntime(t *testing.T) {
	for _, source := range []string{"routing_mark", "route.default_mark"} {
		t.Run(source, func(t *testing.T) {
			manager := &configuredMarkNetworkManager{NetworkManager: new(route.NetworkManager)}
			options := option.DialerOptions{}
			if source == "routing_mark" {
				options.RoutingMark = 0x100
			} else {
				manager.options.RoutingMark = 0x100
			}
			ctx := service.ContextWith[adapter.NetworkManager](context.Background(), manager)
			ctx = dialer.ContextWithExclusiveOutputMark(ctx, "dae")
			_, err := dialer.NewDefault(ctx, options)
			if err == nil || !strings.Contains(err.Error(), source+" conflicts with dae automatic output mark") {
				t.Fatalf("construction error = %v", err)
			}
			if manager.AutoRedirectOutputMark() != 0 {
				t.Fatal("validation acquired runtime output mark")
			}
		})
	}
}

func TestDeclaredOutputMarkRejectsDetourMark(t *testing.T) {
	ctx := dialer.ContextWithExclusiveOutputMark(context.Background(), "dae")
	_, err := dialer.NewWithOptions(dialer.Options{
		Context: ctx,
		Options: option.DialerOptions{
			Detour:                "direct",
			AbstractDialerOptions: option.AbstractDialerOptions{RoutingMark: 0x100},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "routing_mark conflicts with dae automatic output mark") {
		t.Fatalf("detour construction error = %v", err)
	}
}
