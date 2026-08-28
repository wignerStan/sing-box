package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestProcessItemUsesInjectedProcessName(t *testing.T) {
	item := NewProcessItem([]string{"browser"})
	metadata := &adapter.InboundContext{
		ProcessInfo: &adapter.ConnectionOwner{ProcessName: "browser"},
	}
	if !item.Match(metadata) {
		t.Fatal("process_name did not match injected process name")
	}
}

func TestProcessItemPrefersPathAndFallsBackToName(t *testing.T) {
	item := NewProcessItem([]string{"browser"})
	metadata := &adapter.InboundContext{
		ProcessInfo: &adapter.ConnectionOwner{
			ProcessPath: "/usr/bin/not-browser",
			ProcessName: "browser",
		},
	}
	if !item.Match(metadata) {
		t.Fatal("process_name did not fall back after path basename missed")
	}
}
