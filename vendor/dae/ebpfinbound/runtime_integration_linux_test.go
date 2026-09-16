//go:build linux && integration && !dae_stub_ebpf

// SPDX-License-Identifier: AGPL-3.0-only

package ebpfinbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	integrationWAN        = "daeciwan0"
	integrationWANPeer    = "daeciwpeer0"
	integrationWANNetNS   = "dae-ci-wan"
	integrationLAN        = "daecilan0"
	integrationLANPeer    = "daecilpeer0"
	integrationLANNetNS   = "dae-ci-lan"
	integrationChildEnv   = "DAE_EBPF_INTEGRATION_CHILD"
	integrationClientEnv  = "DAE_EBPF_INTEGRATION_CLIENT"
	integrationDestEnv    = "DAE_EBPF_INTEGRATION_DESTINATION"
	integrationPayloadEnv = "DAE_EBPF_INTEGRATION_PAYLOAD"
)

func TestPrivilegedCaptureLifecycleAndTraffic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if network := os.Getenv(integrationClientEnv); network != "" {
		runIntegrationClient(t, network, os.Getenv(integrationDestEnv), os.Getenv(integrationPayloadEnv))
		return
	}
	if os.Getenv(integrationChildEnv) == "1" {
		runtime := startIntegrationRuntime(t)
		if !runtime.Status().Ready {
			t.Fatal("child runtime is not ready")
		}
		// Intentionally do not close the runtime. Process exit simulates an
		// ungraceful consumer crash for the parent's stale-cleanup check.
		return
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("iproute2 is required")
	}
	if _, err := exec.LookPath("tc"); err != nil {
		t.Skip("iproute2 tc is required")
	}

	prepareIntegrationNetwork(t)
	if err := CleanupStale(context.Background()); err != nil {
		t.Fatalf("clean pre-existing provider state: %v", err)
	}
	assertProviderGone(t)

	beforeSysctls := readIntegrationSysctls(t)
	testStartupCollisionRollback(t)
	assertIntegrationSysctls(t, beforeSysctls)
	assertProviderGone(t)

	runtime := startIntegrationRuntime(t)
	defer runtime.Close()
	status := runtime.Status()
	if !status.Ready || status.Port != 23456 || status.OutputMark != 0x1ee0 || len(status.LANInterfaces) != 1 || status.LANInterfaces[0] != integrationLAN {
		t.Fatalf("unexpected runtime status: %+v", status)
	}
	if !status.ProcessMetadataEnabled {
		t.Fatal("required process metadata hooks are not active")
	}
	assertCaptureAttached(t)

	if _, err := New(context.Background(), integrationOptions()); err == nil || !strings.Contains(err.Error(), "owns the host resources") {
		t.Fatalf("second owner was not rejected: %v", err)
	}
	if err := CleanupStale(context.Background()); err == nil || !strings.Contains(err.Error(), "lock is held") {
		t.Fatalf("stale cleanup did not reject a live owner: %v", err)
	}

	testCapturedTCP(t, runtime, "tcp4", "198.18.0.2:18080", "wan-tcp4-captured", "")
	testCapturedTCP(t, runtime, "tcp6", "[2001:db8:dae::2]:18081", "wan-tcp6-captured", "")
	testCapturedUDP(t, runtime, "udp4", "198.18.0.2:18082", "wan-udp4-captured", "")
	testCapturedUDP(t, runtime, "udp6", "[2001:db8:dae::2]:18083", "wan-udp6-captured", "")
	testCapturedTCP(t, runtime, "tcp4", "198.18.0.2:18180", "lan-tcp4-captured", integrationLANNetNS)
	testCapturedTCP(t, runtime, "tcp6", "[2001:db8:dae::2]:18181", "lan-tcp6-captured", integrationLANNetNS)
	testCapturedUDP(t, runtime, "udp4", "198.18.0.2:18182", "lan-udp4-captured", integrationLANNetNS)
	testCapturedUDP(t, runtime, "udp6", "[2001:db8:dae::2]:18183", "lan-udp6-captured", integrationLANNetNS)

	if err := runtime.Close(); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	assertProviderGone(t)
	assertIntegrationSysctls(t, beforeSysctls)

	// A clean restart must work after a complete teardown.
	restarted := startIntegrationRuntime(t)
	if err := restarted.Close(); err != nil {
		t.Fatalf("close restarted runtime: %v", err)
	}
	assertProviderGone(t)

	// A process crash leaves persistent TC/netns resources behind. The
	// ownership journal must make their removal safe and complete.
	runCrashedIntegrationRuntime(t)
	raw, err := os.ReadFile(ownerRecordPath())
	if err != nil {
		t.Fatal(err)
	}
	var legacyRecord ownershipRecord
	if err := json.Unmarshal(raw, &legacyRecord); err != nil {
		t.Fatal(err)
	}
	legacyRecord.NamespaceDevice = 0
	legacyRecord.NamespaceInode = 0
	raw, err = json.MarshalIndent(legacyRecord, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownerRecordPath(), append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CleanupStale(context.Background()); err != nil {
		t.Fatalf("clean crashed runtime from a legacy journal: %v", err)
	}
	assertProviderGone(t)
	assertIntegrationSysctls(t, beforeSysctls)
	if err := CleanupStale(context.Background()); err != nil {
		t.Fatalf("idempotent stale cleanup: %v", err)
	}

	// Replacing the well-known namespace name must never authorize deletion of
	// the replacement. Once it is removed, cleanup can safely resume using the
	// remaining journal entries.
	runCrashedIntegrationRuntime(t)
	raw, err = os.ReadFile(ownerRecordPath())
	if err != nil {
		t.Fatal(err)
	}
	var record ownershipRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.NamespaceDevice == 0 || record.NamespaceInode == 0 {
		t.Fatal("crashed runtime did not persist its network namespace identity")
	}
	mustRunIP(t, "netns", "del", captureNetNSName)
	mustRunIP(t, "netns", "add", captureNetNSName)
	if err := CleanupStale(context.Background()); err == nil || !strings.Contains(err.Error(), "kernel identity changed") {
		t.Fatalf("stale cleanup did not reject a replacement namespace: %v", err)
	}
	if namespace, err := netns.GetFromName(captureNetNSName); err != nil {
		t.Fatalf("replacement namespace was deleted: %v", err)
	} else {
		namespace.Close()
	}
	if _, err := os.Stat(ownerRecordPath()); err != nil {
		t.Fatalf("replacement refusal did not preserve ownership journal: %v", err)
	}
	mustRunIP(t, "netns", "del", captureNetNSName)
	if err := CleanupStale(context.Background()); err != nil {
		t.Fatalf("resume stale cleanup after removing replacement namespace: %v", err)
	}
	assertProviderGone(t)
	assertIntegrationSysctls(t, beforeSysctls)
}

func runCrashedIntegrationRuntime(t *testing.T) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestPrivilegedCaptureLifecycleAndTraffic$", "-test.v")
	command.Env = append(os.Environ(), integrationChildEnv+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("crash-simulation child failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(ownerRecordPath()); err != nil {
		t.Fatalf("crashed runtime did not leave an ownership record: %v\n%s", err, output)
	}
	assertCaptureAttached(t)
}

func testStartupCollisionRollback(t *testing.T) {
	t.Helper()
	mustRunTC(t, "qdisc", "add", "dev", integrationWAN, "clsact")
	t.Cleanup(func() { _ = runTC("qdisc", "del", "dev", integrationWAN, "clsact") })
	mustRunTC(t, "filter", "add", "dev", integrationWAN, "ingress", "protocol", "all", "priority", "1", "matchall", "action", "pass")

	runtime, err := New(context.Background(), integrationOptions())
	if err == nil {
		_ = runtime.Close()
		t.Fatal("startup unexpectedly succeeded with an occupied TC slot")
	}
	if !strings.Contains(err.Error(), "TC slot collision") {
		t.Fatalf("startup collision error = %v", err)
	}
	assertFixedProviderResourcesGone(t)
	if _, err := os.Stat(ownerRecordPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful startup rollback left an ownership record: %v", err)
	}

	link, err := netlink.LinkByName(integrationWAN)
	if err != nil {
		t.Fatal(err)
	}
	if !hasClsact(link) {
		t.Fatal("startup rollback removed a pre-existing clsact qdisc")
	}
	ingress, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		t.Fatal(err)
	}
	egress, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(ingress) != 1 || len(egress) != 0 {
		t.Fatalf("startup rollback left ingress=%d egress=%d filters", len(ingress), len(egress))
	}
	mustRunTC(t, "qdisc", "del", "dev", integrationWAN, "clsact")
}

func integrationOptions() Options {
	return Options{
		Capture: CaptureConfig{
			TProxyPort:             23456,
			LANInterfaces:          []string{integrationLAN},
			WANInterfaces:          []string{integrationWAN},
			OutputMark:             0x1ee0,
			AutoConfigureKernel:    true,
			RequireProcessMetadata: true,
		},
		LogOutput: os.Stderr,
		LogLevel:  "debug",
	}
}

func startIntegrationRuntime(t *testing.T) Runtime {
	t.Helper()
	runtime, err := New(context.Background(), integrationOptions())
	if err != nil {
		t.Fatalf("start full eBPF capture runtime: %v", err)
	}
	return runtime
}

func prepareIntegrationNetwork(t *testing.T) {
	t.Helper()
	_ = runIP("netns", "del", integrationWANNetNS)
	_ = runIP("netns", "del", integrationLANNetNS)
	_ = runIP("link", "del", integrationWAN)
	_ = runIP("link", "del", integrationLAN)
	mustRunIP(t, "netns", "add", integrationWANNetNS)
	mustRunIP(t, "link", "add", integrationWAN, "type", "veth", "peer", "name", integrationWANPeer)
	mustRunIP(t, "link", "set", integrationWANPeer, "netns", integrationWANNetNS)
	mustRunIP(t, "address", "add", "198.18.0.1/30", "dev", integrationWAN)
	mustRunIP(t, "-6", "address", "add", "2001:db8:dae::1/64", "dev", integrationWAN, "nodad")
	mustRunIP(t, "link", "set", integrationWAN, "up")
	mustRunIP(t, "netns", "exec", integrationWANNetNS, "ip", "link", "set", "lo", "up")
	mustRunIP(t, "netns", "exec", integrationWANNetNS, "ip", "address", "add", "198.18.0.2/30", "dev", integrationWANPeer)
	mustRunIP(t, "netns", "exec", integrationWANNetNS, "ip", "-6", "address", "add", "2001:db8:dae::2/64", "dev", integrationWANPeer, "nodad")
	mustRunIP(t, "netns", "exec", integrationWANNetNS, "ip", "link", "set", integrationWANPeer, "up")

	mustRunIP(t, "netns", "add", integrationLANNetNS)
	mustRunIP(t, "link", "add", integrationLAN, "type", "veth", "peer", "name", integrationLANPeer)
	mustRunIP(t, "link", "set", integrationLANPeer, "netns", integrationLANNetNS)
	mustRunIP(t, "address", "add", "192.0.2.1/30", "dev", integrationLAN)
	mustRunIP(t, "-6", "address", "add", "2001:db8:dae:1::1/64", "dev", integrationLAN, "nodad")
	mustRunIP(t, "link", "set", integrationLAN, "up")
	mustRunIP(t, "netns", "exec", integrationLANNetNS, "ip", "link", "set", "lo", "up")
	mustRunIP(t, "netns", "exec", integrationLANNetNS, "ip", "address", "add", "192.0.2.2/30", "dev", integrationLANPeer)
	mustRunIP(t, "netns", "exec", integrationLANNetNS, "ip", "-6", "address", "add", "2001:db8:dae:1::2/64", "dev", integrationLANPeer, "nodad")
	mustRunIP(t, "netns", "exec", integrationLANNetNS, "ip", "link", "set", integrationLANPeer, "up")
	mustRunIP(t, "netns", "exec", integrationLANNetNS, "ip", "route", "add", "default", "via", "192.0.2.1")
	mustRunIP(t, "netns", "exec", integrationLANNetNS, "ip", "-6", "route", "add", "default", "via", "2001:db8:dae:1::1")
	t.Cleanup(func() {
		_ = runIP("link", "del", integrationWAN)
		_ = runIP("link", "del", integrationLAN)
		_ = runIP("netns", "del", integrationWANNetNS)
		_ = runIP("netns", "del", integrationLANNetNS)
	})
}

func testCapturedTCP(t *testing.T, runtime Runtime, network, destination, payload, clientNetNS string) {
	t.Helper()
	var listener *net.TCPListener
	if network == "tcp4" {
		listener = runtime.Listeners().TCP4()
	} else {
		listener = runtime.Listeners().TCP6()
	}
	if err := listener.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer listener.SetDeadline(time.Time{})

	accepted := make(chan *net.TCPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, output := integrationClientCommand(network, destination, payload, clientNetNS)
	if err := client.Start(); err != nil {
		t.Fatalf("start captured %s client: %v", network, err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = client.Process.Kill()
			_ = client.Wait()
		}
	}()

	var server *net.TCPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("accept captured %s flow: %v", network, err)
	case <-time.After(8 * time.Second):
		t.Fatalf("timed out accepting captured %s flow", network)
	}
	defer server.Close()
	if got := server.LocalAddr().String(); got != destination {
		t.Fatalf("%s original destination = %s, want %s", network, got, destination)
	}
	assertFlowMetadata(t, runtime, NetworkTCP, server.RemoteAddr(), server.LocalAddr(), uint32(client.Process.Pid), clientNetNS == "")
	if _, err := server.Write([]byte(payload)); err != nil {
		t.Fatalf("write captured %s response: %v", network, err)
	}
	if err := client.Wait(); err != nil {
		waited = true
		t.Fatalf("captured %s client failed: %v\n%s", network, err, output)
	}
	waited = true
}

type capturedDatagram struct {
	payload []byte
	oob     []byte
	source  *net.UDPAddr
	err     error
}

func testCapturedUDP(t *testing.T, runtime Runtime, network, destination, payload, clientNetNS string) {
	t.Helper()
	listener := runtime.Listeners().UDP()
	if err := listener.SetReadDeadline(time.Now().Add(8 * time.Second)); err != nil {
		t.Fatal(err)
	}
	defer listener.SetReadDeadline(time.Time{})

	received := make(chan capturedDatagram, 1)
	go func() {
		buffer := make([]byte, 256)
		oob := make([]byte, 256)
		n, oobn, _, source, err := listener.ReadMsgUDP(buffer, oob)
		received <- capturedDatagram{payload: buffer[:n], oob: oob[:oobn], source: source, err: err}
	}()

	destinationAddress, err := net.ResolveUDPAddr(network, destination)
	if err != nil {
		t.Fatal(err)
	}
	client, output := integrationClientCommand(network, destination, payload, clientNetNS)
	if err := client.Start(); err != nil {
		t.Fatalf("start captured %s client: %v", network, err)
	}

	var datagram capturedDatagram
	select {
	case datagram = <-received:
	case <-time.After(8 * time.Second):
		t.Fatalf("timed out receiving captured %s flow", network)
	}
	if datagram.err != nil {
		t.Fatalf("receive captured %s flow: %v", network, datagram.err)
	}
	if !bytes.Equal(datagram.payload, []byte(payload)) {
		t.Fatalf("captured %s payload = %q, want %q", network, datagram.payload, payload)
	}
	original := OriginalDestination(datagram.oob)
	want := netip.MustParseAddrPort(destination)
	if original != want {
		t.Fatalf("%s original destination = %s, want %s", network, original, want)
	}
	assertFlowMetadata(t, runtime, NetworkUDP, datagram.source, destinationAddress, uint32(client.Process.Pid), clientNetNS == "")
	if err := client.Wait(); err != nil {
		t.Fatalf("captured %s client failed: %v\n%s", network, err, output)
	}
}

func assertFlowMetadata(t *testing.T, runtime Runtime, network Network, source, destination net.Addr, expectedPID uint32, expectProcess bool) {
	t.Helper()
	flow := Flow{Network: network, Source: mustAddrPort(t, source), Destination: mustAddrPort(t, destination)}
	metadata, found, err := runtime.LookupMetadata(context.Background(), flow)
	if err != nil {
		t.Fatalf("lookup %s metadata: %v", network, err)
	}
	if !found {
		t.Fatalf("metadata not found for %+v", flow)
	}
	if expectProcess {
		if metadata.ProcessID != expectedPID {
			t.Fatalf("metadata pid = %d, want %d", metadata.ProcessID, expectedPID)
		}
		if metadata.ProcessName == "" {
			t.Fatal("metadata process name is empty")
		}
		return
	}
	if metadata.ProcessID != 0 || metadata.ProcessName != "" {
		t.Fatalf("forwarded flow unexpectedly has local process metadata: %+v", metadata)
	}
	if !metadata.HasSourceMAC {
		t.Fatal("forwarded flow is missing source MAC metadata")
	}
}

func integrationClientCommand(network, destination, payload, clientNetNS string) (*exec.Cmd, *bytes.Buffer) {
	arguments := []string{"-test.run=^TestPrivilegedCaptureLifecycleAndTraffic$"}
	command := exec.Command(os.Args[0], arguments...)
	if clientNetNS != "" {
		command = exec.Command("ip", append([]string{"netns", "exec", clientNetNS, os.Args[0]}, arguments...)...)
	}
	command.Env = append(os.Environ(),
		integrationClientEnv+"="+network,
		integrationDestEnv+"="+destination,
		integrationPayloadEnv+"="+payload,
	)
	output := &bytes.Buffer{}
	command.Stdout = output
	command.Stderr = output
	return command, output
}

func runIntegrationClient(t *testing.T, network, destination, payload string) {
	t.Helper()
	if strings.HasPrefix(network, "tcp") {
		connection, err := net.DialTimeout(network, destination, 8*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(8 * time.Second))
		buffer := make([]byte, len(payload))
		if _, err := connection.Read(buffer); err != nil {
			t.Fatal(err)
		}
		if string(buffer) != payload {
			t.Fatalf("response = %q, want %q", buffer, payload)
		}
		return
	}
	destinationAddress, err := net.ResolveUDPAddr(network, destination)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialUDP(network, nil, destinationAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
}

func mustAddrPort(t *testing.T, address net.Addr) netip.AddrPort {
	t.Helper()
	value, err := netip.ParseAddrPort(address.String())
	if err != nil {
		t.Fatalf("parse address %q: %v", address, err)
	}
	return value
}

func assertCaptureAttached(t *testing.T) {
	t.Helper()
	for _, interfaceName := range []string{integrationLAN, integrationWAN} {
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			t.Fatal(err)
		}
		if !hasClsact(link) {
			t.Fatalf("capture clsact qdisc is not attached to %s", interfaceName)
		}
		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, err := netlink.FilterList(link, parent)
			if err != nil {
				t.Fatal(err)
			}
			if len(filters) != 1 {
				t.Fatalf("%s parent %#x has %d filters, want 1", interfaceName, parent, len(filters))
			}
		}
	}
}

func assertProviderGone(t *testing.T) {
	t.Helper()
	assertFixedProviderResourcesGone(t)
	for _, interfaceName := range []string{integrationLAN, integrationWAN} {
		link, err := netlink.LinkByName(interfaceName)
		if err != nil {
			t.Fatal(err)
		}
		if hasClsact(link) {
			t.Fatalf("owned clsact qdisc remains on %s", interfaceName)
		}
	}
}

func assertFixedProviderResourcesGone(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(ownerRecordPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ownership record remains: %v", err)
	}
	if namespace, err := netns.GetFromName(captureNetNSName); err == nil {
		namespace.Close()
		t.Fatalf("capture namespace %s remains", captureNetNSName)
	}
	for _, name := range []string{captureHostLink, capturePeerLink} {
		if _, err := netlink.LinkByName(name); err == nil {
			t.Fatalf("capture link %s remains", name)
		}
	}
}

func hasClsact(link netlink.Link) bool {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return false
	}
	for _, qdisc := range qdiscs {
		if qdisc != nil && qdisc.Type() == "clsact" {
			return true
		}
	}
	return false
}

func readIntegrationSysctls(t *testing.T) map[string]string {
	t.Helper()
	values := make(map[string]string)
	for _, path := range []string{
		"/proc/sys/net/ipv4/conf/all/rp_filter",
		"/proc/sys/net/ipv4/conf/all/arp_filter",
		"/proc/sys/net/ipv4/conf/all/src_valid_mark",
		"/proc/sys/net/ipv4/conf/default/src_valid_mark",
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/" + integrationLAN + "/forwarding",
		"/proc/sys/net/ipv4/conf/" + integrationLAN + "/send_redirects",
		"/proc/sys/net/ipv4/conf/" + integrationLAN + "/rp_filter",
		"/proc/sys/net/ipv6/conf/all/forwarding",
		"/proc/sys/net/ipv6/conf/" + integrationLAN + "/forwarding",
		"/proc/sys/net/ipv6/conf/" + integrationWAN + "/accept_ra",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		values[path] = strings.TrimSpace(string(raw))
	}
	return values
}

func assertIntegrationSysctls(t *testing.T, want map[string]string) {
	t.Helper()
	for path, expected := range want {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(raw)); got != expected {
			t.Fatalf("%s = %s, want restored value %s", path, got, expected)
		}
	}
}

func mustRunIP(t *testing.T, arguments ...string) {
	t.Helper()
	if err := runIP(arguments...); err != nil {
		t.Fatal(err)
	}
}

func mustRunTC(t *testing.T, arguments ...string) {
	t.Helper()
	if err := runTC(arguments...); err != nil {
		t.Fatal(err)
	}
}

func runIP(arguments ...string) error {
	return runNetworkCommand("ip", arguments...)
}

func runTC(arguments ...string) error {
	return runNetworkCommand("tc", arguments...)
}

func runNetworkCommand(name string, arguments ...string) error {
	command := exec.Command(name, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(arguments, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
