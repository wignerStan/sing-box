package option

// DAEInboundOptions configures dae's in-process Linux eBPF capture runtime.
// sing-box remains the sole DNS, sniffing, routing, and outbound authority.
type DAEInboundOptions struct {
	TProxyPort          uint16           `json:"tproxy_port,omitempty"`
	LANInterface        []string         `json:"lan_interface,omitempty"`
	WANInterface        []string         `json:"wan_interface,omitempty"`
	OutputMark          FwMark           `json:"output_mark,omitempty"`
	AutoConfigureKernel bool             `json:"auto_config_kernel_parameter,omitempty"`
	BPFConnStateMapSize uint32           `json:"bpf_conn_state_map_size,omitempty"`
	UDPTimeout          UDPTimeoutCompat `json:"udp_timeout,omitempty"`
	UDPMapping          UDPNATBehavior   `json:"udp_mapping,omitempty"`
	UDPFiltering        UDPNATBehavior   `json:"udp_filtering,omitempty"`
	UDPNATMax           uint32           `json:"udp_nat_max,omitempty"`
}
