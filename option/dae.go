package option

import "github.com/sagernet/sing/common/json/badoption"

// DAEInboundOptions configures the Linux-only dae eBPF datapath handoff.
// dae owns capture and transparent listener creation; sing-box owns all
// userspace routing, DNS, FakeIP, sniffing, and outbound behavior.
type DAEInboundOptions struct {
	SocketPath      string             `json:"socket_path"`
	SocketMode      uint32             `json:"socket_mode,omitempty"`
	ProducerUID     *uint32            `json:"producer_uid,omitempty"`
	OutputMark      FwMark             `json:"output_mark,omitempty"`
	MetadataTimeout badoption.Duration `json:"metadata_timeout,omitempty"`
	UDPTimeout      UDPTimeoutCompat   `json:"udp_timeout,omitempty"`
	UDPMapping      UDPNATBehavior     `json:"udp_mapping,omitempty"`
	UDPFiltering    UDPNATBehavior     `json:"udp_filtering,omitempty"`
	UDPNATMax       uint32             `json:"udp_nat_max,omitempty"`
}
