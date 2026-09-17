// SPDX-License-Identifier: AGPL-3.0-only

// Package ebpfinbound implements dae's policy-neutral Linux transparent
// capture runtime. DNS, sniffing, routing, and outbounds remain owned by the
// embedding traffic engine.
package ebpfinbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type Network string

const (
	NetworkTCP Network = "tcp"
	NetworkUDP Network = "udp"
)

type Flow struct {
	Network     Network
	Source      netip.AddrPort
	Destination netip.AddrPort
}

func (f Flow) Validate() error {
	switch f.Network {
	case NetworkTCP, NetworkUDP:
	default:
		return fmt.Errorf("unsupported network %q", f.Network)
	}
	if !f.Source.IsValid() {
		return errors.New("invalid source address")
	}
	if !f.Destination.IsValid() {
		return errors.New("invalid destination address")
	}
	return nil
}

// Metadata contains observed flow facts only. It deliberately contains no
// routing, DNS, sniffing, or outbound decision.
type Metadata struct {
	ProcessID        uint32
	ProcessName      string
	ProcessStartTime uint64
	ProcessUID       uint32
	HasProcessUID    bool
	SourceMAC        [6]byte
	HasSourceMAC     bool
	DSCP             uint8
}

// ListenerSet is owned by Runtime. Consumers may Accept and Read from these
// sockets, but must not Close or duplicate them. Runtime.Close closes the set.
// TCP listeners are concrete because BPF sockmap publication requires access
// to their raw socket descriptors.
type ListenerSet interface {
	TCP4() *net.TCPListener
	TCP6() *net.TCPListener
	UDP() *net.UDPConn
	Port() uint16
}

type Status struct {
	Ready                  bool
	LANInterfaces          []string
	WANInterfaces          []string
	ProcessMetadataEnabled bool
	OutputMark             uint32
	Port                   uint16
}

// Runtime is a one-shot capture runtime. New returns only after the listener
// sockmap and all required TC/cgroup attachments are ready. A runtime cannot be
// recommitted or cloned; policy reload belongs above this boundary.
type Runtime interface {
	Listeners() ListenerSet
	LookupMetadata(context.Context, Flow) (Metadata, bool, error)
	OutputMark() uint32
	Status() Status
	Close() error
}
