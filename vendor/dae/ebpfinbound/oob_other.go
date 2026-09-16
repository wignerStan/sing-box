//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import "net/netip"

func OriginalDestination([]byte) netip.AddrPort { return netip.AddrPort{} }
