//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"context"
	"errors"
)

var ErrUnsupportedPlatform = errors.New("dae eBPF inbound is supported only on Linux")

type PreflightReport struct{ Config CaptureConfig }

func New(context.Context, Options) (Runtime, error) { return nil, ErrUnsupportedPlatform }
func Doctor(context.Context, CaptureConfig) (PreflightReport, error) {
	return PreflightReport{}, ErrUnsupportedPlatform
}
func CleanupStale(context.Context) error { return ErrUnsupportedPlatform }
