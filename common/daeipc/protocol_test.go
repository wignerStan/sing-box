//go:build linux && !android

// SPDX-License-Identifier: GPL-3.0-or-later

package daeipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMessageRoundTrip(t *testing.T) {
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()

	want := NewMessage(TypeLookup)
	want.RequestID = 42
	want.Network = NetworkTCP
	want.Source = "127.0.0.1:1234"
	want.Destination = "1.1.1.1:443"

	errChannel := make(chan error, 1)
	go func() {
		errChannel <- Write(client, want)
	}()
	got, files, err := Read(server)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Fatalf("received %d unexpected files", len(files))
	}
	if err := <-errChannel; err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.RequestID != want.RequestID || got.Source != want.Source || got.Destination != want.Destination {
		t.Fatalf("unexpected round trip: %#v", got)
	}
}

func TestFileDescriptorRoundTrip(t *testing.T) {
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()

	file, err := os.CreateTemp(t.TempDir(), "dae-ipc")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("descriptor payload"); err != nil {
		t.Fatal(err)
	}

	message := NewMessage(TypeRegister)
	message.Listeners = []string{ListenerTCP4}
	errChannel := make(chan error, 1)
	go func() {
		errChannel <- Write(client, message, file)
	}()
	_, files, err := Read(server)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errChannel; err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("received %d files, want 1", len(files))
	}
	defer files[0].Close()
	if _, err := files[0].Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, err := files[0].Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "descriptor payload" {
		t.Fatalf("received %q", got)
	}
}

func unixPacketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ipc.sock")
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		t.Skipf("unixpacket unavailable: %v", err)
	}
	defer listener.Close()

	clientChannel := make(chan *net.UnixConn, 1)
	errorChannel := make(chan error, 1)
	go func() {
		client, dialErr := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
		if dialErr != nil {
			errorChannel <- dialErr
			return
		}
		clientChannel <- client
	}()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	server, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case client := <-clientChannel:
		return server, client
	case err := <-errorChannel:
		server.Close()
		t.Fatal(err)
		return nil, nil
	case <-time.After(5 * time.Second):
		server.Close()
		t.Fatal("timed out creating unixpacket pair")
		return nil, nil
	}
}
