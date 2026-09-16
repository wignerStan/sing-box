//go:build linux && dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

func (r *captureRuntime) runJanitor() {
	defer close(r.janitorDone)
	<-r.lifecycle.Done()
}
