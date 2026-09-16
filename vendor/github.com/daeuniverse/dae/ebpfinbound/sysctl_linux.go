//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type sysctlMutation struct {
	Path     string `json:"path"`
	Original string `json:"original"`
	Applied  string `json:"applied"`
}

type sysctlManager struct {
	mu        sync.Mutex
	closed    bool
	order     []string
	mutations map[string]sysctlMutation
	onChange  func([]sysctlMutation) error
	readFile  func(string) ([]byte, error)
	writeFile func(string, []byte, os.FileMode) error
}

func newSysctlManager(onChange func([]sysctlMutation) error) *sysctlManager {
	return &sysctlManager{mutations: make(map[string]sysctlMutation), onChange: onChange, readFile: os.ReadFile, writeFile: os.WriteFile}
}

func (m *sysctlManager) Set(path, value string) error {
	if m == nil {
		return errors.New("nil sysctl manager")
	}
	clean := filepath.Clean(path)
	if !strings.HasPrefix(clean, "/proc/sys/net/") {
		return fmt.Errorf("refuse non-network sysctl path %q", path)
	}
	value = strings.TrimSpace(value)
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("sysctl manager is closed")
	}
	raw, err := m.readFile(clean)
	if err != nil {
		m.mu.Unlock()
		return fmt.Errorf("read sysctl %s: %w", clean, err)
	}
	current := strings.TrimSpace(string(raw))
	previous, existed := m.mutations[clean]
	if existed && previous.Applied != value {
		m.mu.Unlock()
		return fmt.Errorf("sysctl %s is already leased at value %s", clean, previous.Applied)
	}
	mutation := previous
	if !existed {
		mutation = sysctlMutation{Path: clean, Original: current}
		m.order = append(m.order, clean)
	}
	mutation.Applied = value
	m.mutations[clean] = mutation
	callback := m.onChange
	if callback != nil {
		// Persist intent before changing the kernel. If the process exits after
		// the write, stale cleanup already knows the original value.
		if err := callback(m.snapshotLocked()); err != nil {
			m.rollbackSetLocked(clean, previous, existed)
			m.mu.Unlock()
			return fmt.Errorf("record sysctl mutation: %w", err)
		}
	}
	if current != value {
		if err := m.writeFile(clean, []byte(value), 0o644); err != nil {
			m.rollbackSetLocked(clean, previous, existed)
			var rollbackErr error
			if callback != nil {
				rollbackErr = callback(m.snapshotLocked())
			}
			m.mu.Unlock()
			return errors.Join(
				fmt.Errorf("write sysctl %s=%s: %w", clean, value, err),
				wrapError("roll back sysctl mutation record", rollbackErr),
			)
		}
	}
	m.mu.Unlock()
	return nil
}

func (m *sysctlManager) rollbackSetLocked(path string, previous sysctlMutation, existed bool) {
	if existed {
		m.mutations[path] = previous
		return
	}
	delete(m.mutations, path)
	if length := len(m.order); length != 0 && m.order[length-1] == path {
		m.order = m.order[:length-1]
	}
}

func wrapError(message string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

func (m *sysctlManager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	var errs []error
	remaining := make(map[string]sysctlMutation)
	for index := len(m.order) - 1; index >= 0; index-- {
		mutation := m.mutations[m.order[index]]
		raw, err := m.readFile(mutation.Path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("read sysctl %s before restore: %w", mutation.Path, err))
				remaining[mutation.Path] = mutation
			}
			continue
		}
		if strings.TrimSpace(string(raw)) != mutation.Applied {
			continue
		}
		if err := m.writeFile(mutation.Path, []byte(mutation.Original), 0o644); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("restore sysctl %s: %w", mutation.Path, err))
			remaining[mutation.Path] = mutation
		}
	}
	order := make([]string, 0, len(remaining))
	for _, path := range m.order {
		if _, exists := remaining[path]; exists {
			order = append(order, path)
		}
	}
	m.order = order
	m.mutations = remaining
	callback := m.onChange
	snapshot := m.snapshotLocked()
	m.mu.Unlock()
	if callback != nil {
		if err := callback(snapshot); err != nil {
			errs = append(errs, fmt.Errorf("update sysctl mutation record: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (m *sysctlManager) snapshotLocked() []sysctlMutation {
	result := make([]sysctlMutation, 0, len(m.order))
	for _, path := range m.order {
		result = append(result, m.mutations[path])
	}
	return result
}

func interfaceSysctlPath(family, interfaceName, key string) (string, error) {
	if interfaceName == "" || strings.Contains(interfaceName, "/") || interfaceName == "." || interfaceName == ".." {
		return "", fmt.Errorf("invalid interface name %q", interfaceName)
	}
	if family != "ipv4" && family != "ipv6" {
		return "", fmt.Errorf("invalid IP family %q", family)
	}
	return filepath.Join("/proc/sys/net", family, "conf", interfaceName, key), nil
}
