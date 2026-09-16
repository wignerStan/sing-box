//go:build linux && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRunCleanupReverse(t *testing.T) {
	var order []int
	wantErr := errors.New("cleanup failed")
	err := runCleanupReverse([]func() error{
		func() error { order = append(order, 1); return nil },
		func() error { order = append(order, 2); return wantErr },
		func() error { order = append(order, 3); return nil },
	})
	if !reflect.DeepEqual(order, []int{3, 2, 1}) {
		t.Fatalf("cleanup order = %v", order)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("cleanup error = %v", err)
	}
}

func TestStaleTimestamp(t *testing.T) {
	timeout := 10 * time.Second
	if !staleTimestamp(100, 0, timeout) {
		t.Fatal("zero timestamp is not stale")
	}
	if staleTimestamp(100, 101, timeout) {
		t.Fatal("future timestamp is stale")
	}
	if staleTimestamp(uint64(timeout.Nanoseconds()), 1, timeout) {
		t.Fatal("fresh timestamp is stale")
	}
	if !staleTimestamp(uint64(timeout.Nanoseconds()+2), 1, timeout) {
		t.Fatal("expired timestamp is fresh")
	}
}
