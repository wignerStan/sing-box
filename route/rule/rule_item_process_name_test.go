package rule

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestProcessItemMatchesObservedProcessName(t *testing.T) {
	rule := NewProcessItem([]string{"curl"})
	metadata := &adapter.InboundContext{ProcessInfo: &adapter.ConnectionOwner{ProcessNames: []string{"curl"}}}
	if !rule.Match(metadata) {
		t.Fatal("process_name did not match observed process metadata")
	}
	metadata.ProcessInfo.ProcessNames[0] = "wget"
	if rule.Match(metadata) {
		t.Fatal("process_name matched a different observed process")
	}
	metadata.ProcessInfo.ProcessNames = nil
	metadata.ProcessInfo.ProcessPaths = []string{"/usr/bin/curl"}
	if !rule.Match(metadata) {
		t.Fatal("process_name no longer matched the executable basename")
	}
}
