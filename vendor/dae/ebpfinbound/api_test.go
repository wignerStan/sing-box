// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"net/netip"
	"testing"
)

func TestFlowValidate(t *testing.T) {
	valid := Flow{
		Network:     NetworkTCP,
		Source:      netip.MustParseAddrPort("192.0.2.1:1234"),
		Destination: netip.MustParseAddrPort("[2001:db8::1]:443"),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid flow: %v", err)
	}
	for name, mutate := range map[string]func(*Flow){
		"network":     func(flow *Flow) { flow.Network = "icmp" },
		"source":      func(flow *Flow) { flow.Source = netip.AddrPort{} },
		"destination": func(flow *Flow) { flow.Destination = netip.AddrPort{} },
	} {
		t.Run(name, func(t *testing.T) {
			flow := valid
			mutate(&flow)
			if err := flow.Validate(); err == nil {
				t.Fatal("invalid flow was accepted")
			}
		})
	}
}

func TestCaptureConfigDefaultsAndValidation(t *testing.T) {
	config := (CaptureConfig{WANInterfaces: []string{"eth0"}}).WithDefaults()
	if config.TProxyPort != DefaultTProxyPort || config.OutputMark != DefaultOutputMark || config.ConnectionStateMapEntries != DefaultConnStateEntries {
		t.Fatalf("unexpected defaults: %+v", config)
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if err := (CaptureConfig{}).Validate(); err == nil {
		t.Fatal("config without interfaces was accepted")
	}
	if err := (CaptureConfig{WANInterfaces: []string{"eth0"}, ConnectionStateMapEntries: 100}).Validate(); err == nil {
		t.Fatal("undersized connection-state map was accepted")
	}
}

func TestParseLogLevel(t *testing.T) {
	for _, value := range []string{"", "info", "trace", "debug", "warn", "warning", "error", "fatal", "panic"} {
		if _, err := parseLogLevel(value); err != nil {
			t.Fatalf("parse %q: %v", value, err)
		}
	}
	if _, err := parseLogLevel("verbose"); err == nil {
		t.Fatal("unsupported log level was accepted")
	}
}
