//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/vishvananda/netlink"
)

type PreflightReport struct {
	Config                 CaptureConfig
	InterfaceNames         []string
	DefaultRouteInterfaces []string
	CgroupV2Mounted        bool
	BPFFSMounted           bool
	ExistingResources      []string
	KernelProblems         []string
}

func ResolveConfig(ctx context.Context, config CaptureConfig) (CaptureConfig, PreflightReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return CaptureConfig{}, PreflightReport{}, err
	}
	config = config.WithDefaults()
	if err := config.Validate(); err != nil {
		return CaptureConfig{}, PreflightReport{}, err
	}
	links, err := netlink.LinkList()
	if err != nil {
		return CaptureConfig{}, PreflightReport{}, fmt.Errorf("list interfaces: %w", err)
	}
	names := make([]string, 0, len(links))
	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}
		name := link.Attrs().Name
		if name == "" || name == "lo" || name == captureHostLink || name == capturePeerLink {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	defaults := defaultRouteInterfaces()
	config.LANInterfaces, err = resolveInterfacePatterns(config.LANInterfaces, names, nil)
	if err != nil {
		return CaptureConfig{}, PreflightReport{}, fmt.Errorf("resolve LAN interfaces: %w", err)
	}
	config.WANInterfaces, err = resolveInterfacePatterns(config.WANInterfaces, names, defaults)
	if err != nil {
		return CaptureConfig{}, PreflightReport{}, fmt.Errorf("resolve WAN interfaces: %w", err)
	}
	if len(config.LANInterfaces) == 0 && len(config.WANInterfaces) == 0 {
		return CaptureConfig{}, PreflightReport{}, errors.New("no capture interface matched the configured LAN/WAN selectors")
	}
	report := PreflightReport{
		Config:                 config,
		InterfaceNames:         names,
		DefaultRouteInterfaces: defaults,
		CgroupV2Mounted:        cgroupV2Mounted(),
		BPFFSMounted:           bpfFSMounted(),
		ExistingResources:      existingCaptureResources(),
	}
	if !config.AutoConfigureKernel {
		report.KernelProblems = verifyHostKernelSettings(config)
	}
	return config, report, nil
}

func Doctor(ctx context.Context, config CaptureConfig) (PreflightReport, error) {
	resolved, report, err := ResolveConfig(ctx, config)
	report.Config = resolved
	if err != nil {
		return report, err
	}
	var problems []error
	if os.Geteuid() != 0 {
		problems = append(problems, errors.New("root privileges are required"))
	}
	if !report.CgroupV2Mounted && resolved.RequireProcessMetadata {
		problems = append(problems, errors.New("cgroup v2 is not mounted but process metadata is required"))
	}
	if len(report.ExistingResources) > 0 {
		problems = append(problems, fmt.Errorf("capture resources already exist: %s", strings.Join(report.ExistingResources, ", ")))
	}
	if len(report.KernelProblems) > 0 {
		problems = append(problems, fmt.Errorf("automatic kernel configuration is disabled: %s", strings.Join(report.KernelProblems, "; ")))
	}
	return report, errors.Join(problems...)
}

func resolveInterfacePatterns(selectors, names, defaults []string) ([]string, error) {
	result := make([]string, 0)
	seen := make(map[string]struct{})
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	for _, selector := range selectors {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			continue
		}
		if selector == "auto" {
			if defaults == nil {
				return nil, errors.New("auto is valid only for WAN interfaces")
			}
			if len(defaults) == 0 {
				return nil, errors.New("auto did not resolve any default-route interface")
			}
			for _, name := range defaults {
				add(name)
			}
			continue
		}
		if _, err := path.Match(selector, "probe"); err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", selector, err)
		}
		matched := false
		for _, name := range names {
			ok, _ := path.Match(selector, name)
			if ok {
				add(name)
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("selector %q matched no current interface", selector)
		}
	}
	sort.Strings(result)
	return result, nil
}

func defaultRouteInterfaces() []string {
	seen := make(map[string]struct{})
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := netlink.RouteList(nil, family)
		if err != nil {
			continue
		}
		for _, route := range routes {
			if route.Dst != nil || route.LinkIndex <= 0 {
				continue
			}
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil || link == nil || link.Attrs() == nil {
				continue
			}
			if name := link.Attrs().Name; name != "" && name != "lo" {
				seen[name] = struct{}{}
			}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func verifyHostKernelSettings(config CaptureConfig) []string {
	if len(config.LANInterfaces) == 0 {
		return nil
	}
	checks := map[string]string{
		"/proc/sys/net/ipv4/ip_forward":                  "1",
		"/proc/sys/net/ipv6/conf/all/forwarding":         "1",
		"/proc/sys/net/ipv4/conf/all/src_valid_mark":     "1",
		"/proc/sys/net/ipv4/conf/default/src_valid_mark": "1",
	}
	for _, interfaceName := range config.LANInterfaces {
		checks["/proc/sys/net/ipv4/conf/"+interfaceName+"/forwarding"] = "1"
		checks["/proc/sys/net/ipv4/conf/"+interfaceName+"/send_redirects"] = "0"
		checks["/proc/sys/net/ipv6/conf/"+interfaceName+"/forwarding"] = "1"
	}
	var problems []string
	paths := make([]string, 0, len(checks))
	for sysctlPath := range checks {
		paths = append(paths, sysctlPath)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			if strings.Contains(path, "/ipv6/") && errors.Is(err, os.ErrNotExist) {
				continue
			}
			problems = append(problems, fmt.Sprintf("%s unavailable: %v", path, err))
			continue
		}
		current := strings.TrimSpace(string(raw))
		if current != checks[path] {
			problems = append(problems, fmt.Sprintf("%s=%s (need %s)", path, current, checks[path]))
		}
	}
	return problems
}

func cgroupV2Mounted() bool {
	_, err := detectCgroupPath()
	return err == nil
}

func bpfFSMounted() bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "/sys/fs/bpf" && fields[2] == "bpf" {
			return true
		}
	}
	return false
}

func existingCaptureResources() []string {
	var result []string
	if _, err := netlink.LinkByName(captureHostLink); err == nil {
		result = append(result, captureHostLink)
	}
	if _, err := netlink.LinkByName(capturePeerLink); err == nil {
		result = append(result, capturePeerLink)
	}
	if _, err := os.Stat("/run/netns/" + captureNetNSName); err == nil {
		result = append(result, captureNetNSName)
	}
	if _, err := os.Stat(ownerRecordPath()); err == nil {
		result = append(result, ownerRecordPath())
	}
	sort.Strings(result)
	return result
}
