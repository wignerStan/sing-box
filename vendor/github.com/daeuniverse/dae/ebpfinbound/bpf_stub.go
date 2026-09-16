//go:build linux && dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"context"
	"errors"
	"os"
)

type captureObjects struct{}

func (o *captureObjects) Close() error { return nil }
func loadCaptureBPF(*captureNetNS, CaptureConfig) (*captureObjects, error) {
	return &captureObjects{}, nil
}
func publishListenersOnce(*captureObjects, ListenerSet) ([]*os.File, error) { return nil, nil }
func lookupFlowMetadata(context.Context, *captureObjects, Flow) (Metadata, bool, error) {
	return Metadata{}, false, nil
}
func stubBPFError() error { return errors.New("dae stub BPF build cannot attach traffic") }
