// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"errors"
	"fmt"
)

const (
	DefaultTProxyPort       = uint16(12345)
	DefaultOutputMark       = uint32(0x100)
	DefaultConnStateEntries = uint32(262144)
)

type CaptureConfig struct {
	TProxyPort                uint16
	LANInterfaces             []string
	WANInterfaces             []string
	OutputMark                uint32
	AutoConfigureKernel       bool
	ConnectionStateMapEntries uint32
	RequireProcessMetadata    bool
}

func (c CaptureConfig) WithDefaults() CaptureConfig {
	c.LANInterfaces = append([]string(nil), c.LANInterfaces...)
	c.WANInterfaces = append([]string(nil), c.WANInterfaces...)
	if c.TProxyPort == 0 {
		c.TProxyPort = DefaultTProxyPort
	}
	if c.OutputMark == 0 {
		c.OutputMark = DefaultOutputMark
	}
	if c.ConnectionStateMapEntries == 0 {
		c.ConnectionStateMapEntries = DefaultConnStateEntries
	}
	return c
}

func (c CaptureConfig) Validate() error {
	c = c.WithDefaults()
	if len(c.LANInterfaces) == 0 && len(c.WANInterfaces) == 0 {
		return errors.New("at least one LAN or WAN interface is required")
	}
	if c.ConnectionStateMapEntries < 1024 {
		return fmt.Errorf("connection-state map size %d is too small", c.ConnectionStateMapEntries)
	}
	return nil
}
