// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

type Options struct {
	Capture   CaptureConfig
	Logger    *slog.Logger
	LogOutput io.Writer
	LogLevel  string
}

func (o Options) logger() (*slog.Logger, error) {
	if o.Logger != nil {
		return o.Logger, nil
	}
	level, err := parseLogLevel(o.LogLevel)
	if err != nil {
		return nil, err
	}
	output := o.LogOutput
	if output == nil {
		output = io.Discard
	}
	return slog.New(slog.NewTextHandler(output, &slog.HandlerOptions{Level: level})), nil
}

func parseLogLevel(raw string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "trace", "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "fatal", "panic":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unsupported log level %q", raw)
	}
}
