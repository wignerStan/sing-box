//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestSysctlManagerRestoresOnlyItsAppliedValue(t *testing.T) {
	const path = "/proc/sys/net/ipv4/conf/test/rp_filter"
	values := map[string]string{path: "2"}
	var snapshots [][]sysctlMutation
	journaledBeforeWrite := false
	manager := newSysctlManager(func(mutations []sysctlMutation) error {
		snapshots = append(snapshots, append([]sysctlMutation(nil), mutations...))
		if len(mutations) != 0 && values[path] == "2" {
			journaledBeforeWrite = true
		}
		return nil
	})
	manager.readFile = func(name string) ([]byte, error) { return []byte(values[name]), nil }
	manager.writeFile = func(name string, value []byte, _ os.FileMode) error {
		values[name] = string(value)
		return nil
	}
	if err := manager.Set(path, "0"); err != nil {
		t.Fatal(err)
	}
	if values[path] != "0" {
		t.Fatalf("applied value = %q", values[path])
	}
	if !journaledBeforeWrite {
		t.Fatal("sysctl intent was not journaled before the kernel write")
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if values[path] != "2" {
		t.Fatalf("restored value = %q", values[path])
	}
	if len(snapshots) != 2 || !reflect.DeepEqual(snapshots[len(snapshots)-1], []sysctlMutation(nil)) {
		t.Fatalf("journal snapshots = %#v", snapshots)
	}

	values[path] = "2"
	manager = newSysctlManager(nil)
	manager.readFile = func(name string) ([]byte, error) { return []byte(values[name]), nil }
	manager.writeFile = func(name string, value []byte, _ os.FileMode) error {
		values[name] = string(value)
		return nil
	}
	if err := manager.Set(path, "0"); err != nil {
		t.Fatal(err)
	}
	values[path] = "1"
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if values[path] != "1" {
		t.Fatalf("externally changed value was overwritten: %q", values[path])
	}
}

func TestSysctlManagerDoesNotWriteWithoutJournal(t *testing.T) {
	const path = "/proc/sys/net/ipv4/conf/test/rp_filter"
	wantErr := errors.New("journal unavailable")
	writes := 0
	manager := newSysctlManager(func([]sysctlMutation) error { return wantErr })
	manager.readFile = func(string) ([]byte, error) { return []byte("2"), nil }
	manager.writeFile = func(string, []byte, os.FileMode) error {
		writes++
		return nil
	}
	if err := manager.Set(path, "0"); !errors.Is(err, wantErr) {
		t.Fatalf("set error = %v", err)
	}
	if writes != 0 {
		t.Fatalf("kernel was written %d times without a durable journal", writes)
	}
	if len(manager.order) != 0 || len(manager.mutations) != 0 {
		t.Fatal("failed journal left an in-memory lease")
	}
}

func TestSysctlManagerRetainsFailedRestore(t *testing.T) {
	const path = "/proc/sys/net/ipv4/conf/test/rp_filter"
	wantErr := errors.New("restore failed")
	value := "2"
	var snapshots [][]sysctlMutation
	manager := newSysctlManager(func(mutations []sysctlMutation) error {
		snapshots = append(snapshots, append([]sysctlMutation(nil), mutations...))
		return nil
	})
	manager.readFile = func(string) ([]byte, error) { return []byte(value), nil }
	manager.writeFile = func(_ string, raw []byte, _ os.FileMode) error {
		if string(raw) == "2" {
			return wantErr
		}
		value = string(raw)
		return nil
	}
	if err := manager.Set(path, "0"); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(); !errors.Is(err, wantErr) {
		t.Fatalf("close error = %v", err)
	}
	if len(snapshots) < 2 || len(snapshots[len(snapshots)-1]) != 1 {
		t.Fatalf("failed restore was removed from the journal: %#v", snapshots)
	}
	if len(manager.order) != 1 || len(manager.mutations) != 1 {
		t.Fatal("failed restore was removed from the manager")
	}
}
