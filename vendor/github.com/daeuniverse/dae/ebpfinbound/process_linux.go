//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func enrichNumericProcessMetadata(metadata *Metadata) {
	if metadata == nil || metadata.ProcessID == 0 {
		return
	}
	pid := metadata.ProcessID
	commRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return
	}
	comm := strings.TrimSpace(string(commRaw))
	if metadata.ProcessName != "" && truncateTaskComm(comm) != truncateTaskComm(metadata.ProcessName) {
		return
	}
	statRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return
	}
	startTime, err := parseProcessStartTime(string(statRaw))
	if err != nil {
		return
	}
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return
	}
	verifyRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return
	}
	verifyStart, err := parseProcessStartTime(string(verifyRaw))
	if err != nil || verifyStart != startTime {
		return
	}
	metadata.ProcessName = comm
	metadata.ProcessStartTime = startTime
	metadata.ProcessUID = stat.Uid
	metadata.HasProcessUID = true
}

func parseProcessStartTime(raw string) (uint64, error) {
	closeIndex := strings.LastIndex(raw, ")")
	if closeIndex < 0 || closeIndex+2 > len(raw) {
		return 0, fmt.Errorf("invalid /proc stat record")
	}
	fields := strings.Fields(raw[closeIndex+1:])
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0, fmt.Errorf("short /proc stat record")
	}
	value, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse process start time: %w", err)
	}
	return value, nil
}

func truncateTaskComm(value string) string {
	bytes := []byte(value)
	if len(bytes) > 15 {
		bytes = bytes[:15]
	}
	return string(bytes)
}
