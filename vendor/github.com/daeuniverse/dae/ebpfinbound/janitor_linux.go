//go:build linux && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"time"

	"github.com/cilium/ebpf"
)

func (r *captureRuntime) runJanitor() {
	defer close(r.janitorDone)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.lifecycle.Done():
			return
		case <-ticker.C:
		}
		if err := r.gate.enter(); err != nil {
			return
		}
		r.stateMu.RLock()
		objects := r.bpf
		r.stateMu.RUnlock()
		if objects != nil && objects.RoutingHandoffMap != nil {
			now, err := monotonicNowNano()
			if err == nil {
				iterator := objects.RoutingHandoffMap.Iterate()
				var key bpfTuplesKey
				var value bpfRoutingHandoffEntry
				for iterator.Next(&key, &value) {
					if staleTimestamp(now, value.LastSeenNs, routingHandoffTimeout) {
						_ = objects.RoutingHandoffMap.Delete(&key)
					}
				}
				if err := iterator.Err(); err != nil && err != ebpf.ErrKeyNotExist && r.log != nil {
					r.log.Debug("scan routing handoff map", "error", err)
				}
			}
		}
		r.gate.leave()
	}
}
