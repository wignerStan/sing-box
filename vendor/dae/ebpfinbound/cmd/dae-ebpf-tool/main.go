// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/ebpfinbound"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "help", "-h", "--help":
		usage()
		return
	case "doctor":
		err = doctor(os.Args[2:])
	case "cleanup-stale":
		if len(os.Args) != 2 {
			err = errors.New("cleanup-stale does not accept arguments")
		} else {
			err = ebpfinbound.CleanupStale(context.Background())
		}
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dae-ebpf-tool doctor [options] | cleanup-stale")
}

func doctor(arguments []string) error {
	set := flag.NewFlagSet("doctor", flag.ContinueOnError)
	var lan, wan string
	var port uint
	var mark string
	var auto, requireProcess bool
	set.StringVar(&lan, "lan", "", "comma-separated LAN interface selectors")
	set.StringVar(&wan, "wan", "auto", "comma-separated WAN interface selectors")
	set.UintVar(&port, "port", uint(ebpfinbound.DefaultTProxyPort), "transparent listener port")
	set.StringVar(&mark, "mark", fmt.Sprintf("%#x", ebpfinbound.DefaultOutputMark), "output socket mark")
	set.BoolVar(&auto, "auto-configure-kernel", false, "allow runtime to modify required host sysctls")
	set.BoolVar(&requireProcess, "require-process-metadata", false, "require cgroup process metadata hooks")
	if err := set.Parse(arguments); err != nil {
		return err
	}
	if port > uint(^uint16(0)) {
		return fmt.Errorf("port %d is outside the valid range 0-65535", port)
	}
	markValue, err := strconv.ParseUint(mark, 0, 32)
	if err != nil {
		return fmt.Errorf("parse mark: %w", err)
	}
	report, doctorErr := ebpfinbound.Doctor(context.Background(), ebpfinbound.CaptureConfig{
		TProxyPort:             uint16(port),
		LANInterfaces:          splitList(lan),
		WANInterfaces:          splitList(wan),
		OutputMark:             uint32(markValue),
		AutoConfigureKernel:    auto,
		RequireProcessMetadata: requireProcess,
	})
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	return doctorErr
}

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			result = append(result, value)
		}
	}
	return result
}
