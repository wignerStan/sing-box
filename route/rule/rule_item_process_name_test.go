package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestProcessItemKeepsProcessPathPrecedence(t *testing.T) {
	item := NewProcessItem([]string{"curl"})
	metadata := &adapter.InboundContext{
		ProcessInfo: &adapter.ConnectionOwner{
			ProcessName: "not-curl",
			ProcessPath: "/usr/bin/curl",
		},
	}
	if !item.Match(metadata) {
		t.Fatal("process path basename did not match")
	}
}

func TestProcessItemFallsBackToExplicitProcessName(t *testing.T) {
	item := NewProcessItem([]string{"curl"})
	metadata := &adapter.InboundContext{
		ProcessInfo: &adapter.ConnectionOwner{ProcessName: "curl"},
	}
	if !item.Match(metadata) {
		t.Fatal("explicit process name did not match")
	}
}
