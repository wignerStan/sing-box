//go:build linux && !android && with_dae && integration

package dae

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	integrationBinaryEnv  = "SING_BOX_DAE_BINARY"
	integrationServerEnv  = "SING_BOX_DAE_ECHO_SERVER"
	integrationClientEnv  = "SING_BOX_DAE_CLIENT_NETWORK"
	integrationAddressEnv = "SING_BOX_DAE_CLIENT_ADDRESS"
	integrationPayloadEnv = "SING_BOX_DAE_CLIENT_PAYLOAD"
	integrationWAN        = "sbciwan0"
	integrationWANPeer    = "sbciwpeer0"
	integrationWANNetNS   = "sb-ci-wan"
	integrationLAN        = "sbcilan0"
	integrationLANPeer    = "sbcilpeer0"
	integrationLANNetNS   = "sb-ci-lan"
	providerOwnerRecord   = "/run/dae-ebpfinbound/owner.json"
	providerNetNS         = "dae-ebpf-inbound"
)

func TestDAEInboundRealDatapath(t *testing.T) {
	if os.Getenv(integrationServerEnv) == "1" {
		runIntegrationEchoServer(t)
		return
	}
	if network := os.Getenv(integrationClientEnv); network != "" {
		runIntegrationClient(t, network, os.Getenv(integrationAddressEnv), os.Getenv(integrationPayloadEnv))
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	binary := os.Getenv(integrationBinaryEnv)
	if binary == "" {
		t.Skip(integrationBinaryEnv + " is not set")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal(integrationBinaryEnv + " must be an absolute path")
	}
	for _, tool := range []string{"ip", "tc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " is required")
		}
	}
	if output, err := exec.Command(binary, "tools", "dae", "cleanup-stale").CombinedOutput(); err != nil {
		t.Fatalf("clean stale provider state before test: %v\n%s", err, output)
	}

	prepareIntegrationNetwork(t)
	assertIntegrationProviderGone(t)
	server := startIntegrationEchoServer(t)
	t.Cleanup(func() {
		if server.Process != nil {
			_ = server.Process.Kill()
			_ = server.Wait()
		}
	})
	configPath := writeIntegrationConfig(t)

	var active *integrationSingBox
	t.Cleanup(func() {
		if active != nil {
			active.kill()
		}
		_ = runIntegrationCommand(binary, "tools", "dae", "cleanup-stale")
	})

	active = startIntegrationSingBox(t, binary, configPath)
	testAllIntegrationTraffic(t)
	active.stop(t)
	active = nil
	assertIntegrationProviderGone(t)

	active = startIntegrationSingBox(t, binary, configPath)
	runIntegrationClientProcess(t, "tcp4", "198.18.0.2:19080", "before-crash", integrationLANNetNS)
	active.kill()
	active = nil
	if _, err := os.Stat(providerOwnerRecord); err != nil {
		t.Fatalf("hard crash did not preserve the ownership journal: %v", err)
	}
	if output, err := exec.Command(binary, "tools", "dae", "cleanup-stale").CombinedOutput(); err != nil {
		t.Fatalf("integrated stale cleanup failed: %v\n%s", err, output)
	}
	assertIntegrationProviderGone(t)

	active = startIntegrationSingBox(t, binary, configPath)
	runIntegrationClientProcess(t, "udp6", "[2001:db8:dae::2]:19083", "after-restart", "")
	active.stop(t)
	active = nil
	assertIntegrationProviderGone(t)
}

type integrationSingBox struct {
	command *exec.Cmd
	logs    bytes.Buffer
	done    chan error
}

func startIntegrationSingBox(t *testing.T, binary, configPath string) *integrationSingBox {
	t.Helper()
	process := &integrationSingBox{command: exec.Command(binary, "run", "-c", configPath), done: make(chan error, 1)}
	process.command.Stdout = &process.logs
	process.command.Stderr = &process.logs
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { process.done <- process.command.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(providerOwnerRecord); err == nil {
			if filterOutput, filterErr := exec.Command("tc", "filter", "show", "dev", integrationLAN, "ingress").CombinedOutput(); filterErr == nil && bytes.Contains(filterOutput, []byte("dae_cap_li_")) {
				return process
			}
		}
		select {
		case err := <-process.done:
			t.Fatalf("sing-box exited during startup: %v\n%s", err, process.logs.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	process.kill()
	t.Fatalf("sing-box did not attach the dae dataplane\n%s", process.logs.String())
	return nil
}

func (p *integrationSingBox) stop(t *testing.T) {
	t.Helper()
	if p == nil || p.command.Process == nil {
		return
	}
	if err := p.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		if err != nil {
			t.Fatalf("sing-box graceful stop failed: %v\n%s", err, p.logs.String())
		}
	case <-time.After(10 * time.Second):
		p.kill()
		t.Fatalf("sing-box did not stop cleanly\n%s", p.logs.String())
	}
}

func (p *integrationSingBox) kill() {
	if p == nil || p.command.Process == nil {
		return
	}
	_ = p.command.Process.Kill()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
	}
}

func writeIntegrationConfig(t *testing.T) string {
	t.Helper()
	config := map[string]any{
		"log": map[string]any{"level": "debug", "timestamp": true},
		"inbounds": []any{map[string]any{
			"type":                         "dae",
			"tag":                          "dae-in",
			"lan_interface":                []string{integrationLAN},
			"wan_interface":                []string{integrationWAN},
			"tproxy_port":                  23456,
			"output_mark":                  "0x1ee0",
			"auto_config_kernel_parameter": true,
			"require_process_metadata":     true,
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	}
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testAllIntegrationTraffic(t *testing.T) {
	t.Helper()
	tests := []struct {
		network   string
		address   string
		payload   string
		namespace string
	}{
		{"tcp4", "198.18.0.2:19080", "wan-tcp4", ""},
		{"tcp6", "[2001:db8:dae::2]:19081", "wan-tcp6", ""},
		{"udp4", "198.18.0.2:19082", "wan-udp4", ""},
		{"udp6", "[2001:db8:dae::2]:19083", "wan-udp6", ""},
		{"tcp4", "198.18.0.2:19080", "lan-tcp4", integrationLANNetNS},
		{"tcp6", "[2001:db8:dae::2]:19081", "lan-tcp6", integrationLANNetNS},
		{"udp4", "198.18.0.2:19082", "lan-udp4", integrationLANNetNS},
		{"udp6", "[2001:db8:dae::2]:19083", "lan-udp6", integrationLANNetNS},
	}
	for _, test := range tests {
		t.Run(test.payload, func(t *testing.T) {
			runIntegrationClientProcess(t, test.network, test.address, test.payload, test.namespace)
		})
	}
}

func runIntegrationClientProcess(t *testing.T, network, address, payload, namespace string) {
	t.Helper()
	arguments := []string{os.Args[0], "-test.run=^TestDAEInboundRealDatapath$", "-test.v"}
	if namespace != "" {
		arguments = append([]string{"ip", "netns", "exec", namespace}, arguments...)
	}
	command := exec.Command(arguments[0], arguments[1:]...)
	command.Env = append(os.Environ(),
		integrationClientEnv+"="+network,
		integrationAddressEnv+"="+address,
		integrationPayloadEnv+"="+payload,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s client through %s failed: %v\n%s", network, namespace, err, output)
	}
}

func runIntegrationClient(t *testing.T, network, address, payload string) {
	t.Helper()
	conn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != payload {
		t.Fatalf("reply = %q, want %q", reply, payload)
	}
}

func startIntegrationEchoServer(t *testing.T) *exec.Cmd {
	t.Helper()
	command := exec.Command("ip", "netns", "exec", integrationWANNetNS, os.Args[0], "-test.run=^TestDAEInboundRealDatapath$")
	command.Env = append(os.Environ(), integrationServerEnv+"=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "READY" {
				ready <- nil
				return
			}
		}
		if err := scanner.Err(); err != nil {
			ready <- err
		} else {
			ready <- errors.New("echo server exited before readiness")
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			t.Fatalf("echo server failed to start: %v\n%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("echo server did not become ready\n%s", stderr.String())
	}
	return command
}

func runIntegrationEchoServer(t *testing.T) {
	t.Helper()
	tcp4 := mustListenTCP(t, "tcp4", "198.18.0.2:19080")
	tcp6 := mustListenTCP(t, "tcp6", "[2001:db8:dae::2]:19081")
	udp4 := mustListenUDP(t, "udp4", "198.18.0.2:19082")
	udp6 := mustListenUDP(t, "udp6", "[2001:db8:dae::2]:19083")
	go echoTCP(tcp4)
	go echoTCP(tcp6)
	go echoUDP(udp4)
	go echoUDP(udp6)
	fmt.Println("READY")
	select {}
}

func mustListenTCP(t *testing.T, network, address string) net.Listener {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func mustListenUDP(t *testing.T, network, address string) *net.UDPConn {
	t.Helper()
	resolved, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP(network, resolved)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func echoTCP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func echoUDP(conn *net.UDPConn) {
	buffer := make([]byte, 64<<10)
	for {
		n, source, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDPAddrPort(buffer[:n], source)
	}
}

func prepareIntegrationNetwork(t *testing.T) {
	t.Helper()
	cleanupIntegrationNetwork()
	t.Cleanup(cleanupIntegrationNetwork)
	mustRunIntegrationIP(t, "netns", "add", integrationWANNetNS)
	mustRunIntegrationIP(t, "link", "add", integrationWAN, "type", "veth", "peer", "name", integrationWANPeer)
	mustRunIntegrationIP(t, "link", "set", integrationWANPeer, "netns", integrationWANNetNS)
	mustRunIntegrationIP(t, "address", "add", "198.18.0.1/30", "dev", integrationWAN)
	mustRunIntegrationIP(t, "-6", "address", "add", "2001:db8:dae::1/64", "dev", integrationWAN, "nodad")
	mustRunIntegrationIP(t, "link", "set", integrationWAN, "up")
	mustRunIntegrationIP(t, "netns", "exec", integrationWANNetNS, "ip", "link", "set", "lo", "up")
	mustRunIntegrationIP(t, "netns", "exec", integrationWANNetNS, "ip", "address", "add", "198.18.0.2/30", "dev", integrationWANPeer)
	mustRunIntegrationIP(t, "netns", "exec", integrationWANNetNS, "ip", "-6", "address", "add", "2001:db8:dae::2/64", "dev", integrationWANPeer, "nodad")
	mustRunIntegrationIP(t, "netns", "exec", integrationWANNetNS, "ip", "link", "set", integrationWANPeer, "up")

	mustRunIntegrationIP(t, "netns", "add", integrationLANNetNS)
	mustRunIntegrationIP(t, "link", "add", integrationLAN, "type", "veth", "peer", "name", integrationLANPeer)
	mustRunIntegrationIP(t, "link", "set", integrationLANPeer, "netns", integrationLANNetNS)
	mustRunIntegrationIP(t, "address", "add", "192.0.2.1/30", "dev", integrationLAN)
	mustRunIntegrationIP(t, "-6", "address", "add", "2001:db8:dae:1::1/64", "dev", integrationLAN, "nodad")
	mustRunIntegrationIP(t, "link", "set", integrationLAN, "up")
	mustRunIntegrationIP(t, "netns", "exec", integrationLANNetNS, "ip", "link", "set", "lo", "up")
	mustRunIntegrationIP(t, "netns", "exec", integrationLANNetNS, "ip", "address", "add", "192.0.2.2/30", "dev", integrationLANPeer)
	mustRunIntegrationIP(t, "netns", "exec", integrationLANNetNS, "ip", "-6", "address", "add", "2001:db8:dae:1::2/64", "dev", integrationLANPeer, "nodad")
	mustRunIntegrationIP(t, "netns", "exec", integrationLANNetNS, "ip", "link", "set", integrationLANPeer, "up")
	mustRunIntegrationIP(t, "netns", "exec", integrationLANNetNS, "ip", "route", "add", "default", "via", "192.0.2.1")
	mustRunIntegrationIP(t, "netns", "exec", integrationLANNetNS, "ip", "-6", "route", "add", "default", "via", "2001:db8:dae:1::1")
}

func cleanupIntegrationNetwork() {
	_ = runIntegrationCommand("ip", "link", "del", integrationWAN)
	_ = runIntegrationCommand("ip", "link", "del", integrationLAN)
	_ = runIntegrationCommand("ip", "netns", "del", integrationWANNetNS)
	_ = runIntegrationCommand("ip", "netns", "del", integrationLANNetNS)
}

func mustRunIntegrationIP(t *testing.T, arguments ...string) {
	t.Helper()
	if output, err := exec.Command("ip", arguments...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
}

func runIntegrationCommand(name string, arguments ...string) error {
	return exec.Command(name, arguments...).Run()
}

func assertIntegrationProviderGone(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(providerOwnerRecord); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("provider ownership record remains: %v", err)
	}
	if err := runIntegrationCommand("ip", "link", "show", "dae-ebpf0"); err == nil {
		t.Fatal("provider capture link remains")
	}
	if output, err := exec.Command("ip", "netns", "list").CombinedOutput(); err != nil {
		t.Fatal(err)
	} else if strings.Contains(string(output), providerNetNS) {
		t.Fatalf("provider namespace remains: %s", output)
	}
	for _, interfaceName := range []string{integrationLAN, integrationWAN} {
		output, err := exec.Command("tc", "qdisc", "show", "dev", interfaceName).CombinedOutput()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(output, []byte("clsact")) {
			t.Fatalf("provider clsact remains on %s: %s", interfaceName, output)
		}
	}
}
