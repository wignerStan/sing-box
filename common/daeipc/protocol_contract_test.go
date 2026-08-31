//go:build linux && !android

// SPDX-License-Identifier: GPL-3.0-or-later

package daeipc

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMessageEnvelopeValidation(t *testing.T) {
	tests := []struct {
		name    string
		message Message
		wantErr string
	}{
		{name: "valid", message: NewMessage(TypePing)},
		{name: "missing protocol", message: Message{Version: Version, Type: TypePing}, wantErr: "unexpected protocol"},
		{name: "wrong protocol", message: Message{Protocol: "other", Version: Version, Type: TypePing}, wantErr: "unexpected protocol"},
		{name: "missing version", message: Message{Protocol: ProtocolName, Type: TypePing}, wantErr: "unsupported protocol version"},
		{name: "wrong version", message: Message{Protocol: ProtocolName, Version: Version + 1, Type: TypePing}, wantErr: "unsupported protocol version"},
		{name: "missing type", message: Message{Protocol: ProtocolName, Version: Version}, wantErr: "missing message type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.message.ValidateEnvelope()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateEnvelope() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ValidateEnvelope() = %v, want error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestMessageWireContract(t *testing.T) {
	message := NewMessage(TypeLookupResponse)
	message.RequestID = 7
	message.Generation = 9
	message.TProxyPort = 12345
	message.OutputMark = 0x100
	message.Listeners = []string{ListenerTCP4, ListenerTCP6, ListenerUDP4}
	message.Network = NetworkTCP
	message.Source = "192.0.2.1:1234"
	message.Destination = "[2001:db8::1]:443"
	message.Found = true
	message.PID = 42
	message.ProcessName = "curl"
	message.ProcessPath = "/usr/bin/curl"
	message.UserID = 1000
	message.HasUserID = true
	message.SourceMAC = "00:11:22:33:44:55"
	message.DSCP = 46
	message.Error = "denied"

	payload, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"protocol":     ProtocolName,
		"version":      float64(Version),
		"type":         TypeLookupResponse,
		"request_id":   float64(7),
		"generation":   float64(9),
		"tproxy_port":  float64(12345),
		"output_mark":  float64(0x100),
		"listeners":    []any{ListenerTCP4, ListenerTCP6, ListenerUDP4},
		"network":      NetworkTCP,
		"source":       "192.0.2.1:1234",
		"destination":  "[2001:db8::1]:443",
		"found":        true,
		"pid":          float64(42),
		"process_name": "curl",
		"process_path": "/usr/bin/curl",
		"user_id":      float64(1000),
		"has_user_id":  true,
		"source_mac":   "00:11:22:33:44:55",
		"dscp":         float64(46),
		"error":        "denied",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("wire message = %#v, want %#v", got, want)
	}
}
func TestWriteInputAndSizeLimits(t *testing.T) {
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()

	if err := Write(nil, NewMessage(TypePing)); err == nil {
		t.Fatal("Write accepted a nil connection")
	}
	if err := Write(client, Message{Protocol: "other", Version: Version, Type: TypePing}); err == nil {
		t.Fatal("Write accepted an invalid protocol")
	}
	if err := Write(client, Message{Protocol: ProtocolName, Version: Version + 1, Type: TypePing}); err == nil {
		t.Fatal("Write accepted an unsupported version")
	}

	files := make([]*os.File, maxFiles+1)
	for index := range files {
		file, err := os.Open("/dev/null")
		if err != nil {
			t.Fatal(err)
		}
		files[index] = file
	}
	defer closeExternalTestFiles(files)
	if err := Write(client, NewMessage(TypePing), files...); err == nil {
		t.Fatal("Write accepted too many file descriptors")
	}
	if err := Write(client, NewMessage(TypePing), (*os.File)(nil)); err == nil {
		t.Fatal("Write accepted a nil file descriptor")
	}

	large := NewMessage(TypePing)
	large.Error = strings.Repeat("x", maxMessageSize)
	if err := Write(client, large); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("Write oversized message error = %v, want ErrMessageTooLarge", err)
	}
}

func TestReadRejectsMalformedEnvelopeAndClosesDescriptors(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "invalid json", payload: []byte("{")},
		{name: "wrong protocol", payload: []byte(`{"protocol":"other","version":1,"type":"ping"}`)},
		{name: "wrong version", payload: []byte(`{"protocol":"dae-sing-box","version":2,"type":"ping"}`)},
		{name: "missing type", payload: []byte(`{"protocol":"dae-sing-box","version":1}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, client := unixPacketPair(t)
			defer server.Close()
			defer client.Close()

			file, err := os.CreateTemp(t.TempDir(), "dae-ipc-malformed")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			before := countFDTarget(t, file.Name())
			writeRawPacket(t, client, test.payload, file)
			if _, files, err := Read(server); err == nil {
				closeExternalTestFiles(files)
				t.Fatal("Read accepted malformed envelope")
			} else if files != nil {
				closeExternalTestFiles(files)
				t.Fatalf("Read returned files with error: %d", len(files))
			}
			if after := countFDTarget(t, file.Name()); after != before {
				t.Fatalf("malformed message leaked descriptor for %q: before=%d after=%d", file.Name(), before, after)
			}
		})
	}
}

func TestReadDescriptorFlagsAndOwnership(t *testing.T) {
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()

	file, err := os.CreateTemp(t.TempDir(), "dae-ipc-owned")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString("owned"); err != nil {
		t.Fatal(err)
	}
	before := countFDTarget(t, file.Name())
	writeRawPacket(t, client, mustJSONMessage(t, NewMessage(TypePing)), file)
	message, files, err := Read(server)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != TypePing || len(files) != 1 {
		closeExternalTestFiles(files)
		t.Fatalf("Read returned message=%#v files=%d", message, len(files))
	}
	if got := countFDTarget(t, file.Name()); got != before+1 {
		closeExternalTestFiles(files)
		t.Fatalf("received descriptor count = %d, want %d", got, before+1)
	}
	flags, err := unix.FcntlInt(files[0].Fd(), unix.F_GETFD, 0)
	if err != nil {
		closeExternalTestFiles(files)
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		closeExternalTestFiles(files)
		t.Fatal("received descriptor is not close-on-exec")
	}
	if _, err := files[0].Seek(0, 0); err != nil {
		closeExternalTestFiles(files)
		t.Fatal(err)
	}
	content := make([]byte, 5)
	if _, err := files[0].Read(content); err != nil {
		closeExternalTestFiles(files)
		t.Fatal(err)
	}
	if string(content) != "owned" {
		closeExternalTestFiles(files)
		t.Fatalf("received descriptor content = %q", content)
	}
	closeExternalTestFiles(files)
	if got := countFDTarget(t, file.Name()); got != before {
		t.Fatalf("descriptor ownership was not released: before=%d after=%d", before, got)
	}

	// Write retains ownership of the sender's descriptor.
	if err := Write(client, NewMessage(TypePing), file); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal("Write unexpectedly closed sender descriptor:", err)
	}
	_, received, err := Read(server)
	if err != nil {
		t.Fatal(err)
	}
	closeExternalTestFiles(received)
}

func TestReadDetectsPayloadAndControlTruncation(t *testing.T) {
	t.Run("payload", func(t *testing.T) {
		server, client := unixPacketPair(t)
		defer server.Close()
		defer client.Close()
		payload := []byte(strings.Repeat("x", maxMessageSize+1))
		writeRawPacket(t, client, payload)
		if _, files, err := Read(server); !errors.Is(err, ErrTruncated) {
			closeExternalTestFiles(files)
			t.Fatalf("Read oversized packet error = %v, want ErrTruncated", err)
		}
	})

	t.Run("control", func(t *testing.T) {
		server, client := unixPacketPair(t)
		defer server.Close()
		defer client.Close()
		files := make([]*os.File, maxFiles+1)
		for index := range files {
			file, err := os.Open("/dev/null")
			if err != nil {
				closeExternalTestFiles(files)
				t.Fatal(err)
			}
			files[index] = file
		}
		defer closeExternalTestFiles(files)
		writeRawPacket(t, client, mustJSONMessage(t, NewMessage(TypePing)), files...)
		if _, received, err := Read(server); err == nil {
			closeExternalTestFiles(received)
			t.Fatal("Read accepted too many descriptors")
		} else if received != nil {
			closeExternalTestFiles(received)
		}
	})
}

func TestPeerCredentials(t *testing.T) {
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()

	credentials, err := PeerCredentials(server)
	if err != nil {
		t.Fatal(err)
	}
	if credentials == nil {
		t.Fatal("PeerCredentials returned nil credentials")
	}
	if credentials.Uid != uint32(os.Getuid()) {
		t.Fatalf("peer uid = %d, want %d", credentials.Uid, os.Getuid())
	}
	if credentials.Gid != uint32(os.Getgid()) {
		t.Fatalf("peer gid = %d, want %d", credentials.Gid, os.Getgid())
	}
	if credentials.Pid <= 0 {
		t.Fatalf("peer pid = %d, want positive pid", credentials.Pid)
	}
	if _, err := PeerCredentials(nil); err == nil {
		t.Fatal("PeerCredentials accepted nil connection")
	}
}

func TestSequencePacketMessageBoundaries(t *testing.T) {
	server, client := unixPacketPair(t)
	defer server.Close()
	defer client.Close()

	first := NewMessage(TypePing)
	first.RequestID = 1
	second := NewMessage(TypePong)
	second.RequestID = 2
	done := make(chan error, 1)
	go func() {
		if err := Write(client, first); err != nil {
			done <- err
			return
		}
		done <- Write(client, second)
	}()
	gotFirst, firstFiles, err := Read(server)
	closeExternalTestFiles(firstFiles)
	if err != nil {
		t.Fatal(err)
	}
	gotSecond, secondFiles, err := Read(server)
	closeExternalTestFiles(secondFiles)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if gotFirst.Type != TypePing || gotFirst.RequestID != 1 {
		t.Fatalf("first packet = %#v", gotFirst)
	}
	if gotSecond.Type != TypePong || gotSecond.RequestID != 2 {
		t.Fatalf("second packet = %#v", gotSecond)
	}
}

func FuzzMessageEnvelopeJSON(f *testing.F) {
	for _, seed := range []string{
		`{"protocol":"dae-sing-box","version":1,"type":"ping"}`,
		`{"protocol":"dae-sing-box","version":1,"type":"lookup","request_id":1}`,
		`{`,
		`null`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		var message Message
		if err := json.Unmarshal([]byte(payload), &message); err == nil {
			_ = message.ValidateEnvelope()
		}
	})
}

func writeRawPacket(t *testing.T, conn *net.UnixConn, payload []byte, files ...*os.File) {
	t.Helper()
	var fds []int
	for _, file := range files {
		if file == nil {
			t.Fatal("writeRawPacket received nil file")
		}
		fds = append(fds, int(file.Fd()))
	}
	var oob []byte
	if len(fds) != 0 {
		oob = unix.UnixRights(fds...)
	}
	n, oobN, err := conn.WriteMsgUnix(payload, oob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) || oobN != len(oob) {
		t.Fatalf("short raw packet write: payload %d/%d control %d/%d", n, len(payload), oobN, len(oob))
	}
}

func mustJSONMessage(t *testing.T, message Message) []byte {
	t.Helper()
	payload, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func countFDTarget(t *testing.T, target string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("/proc/self/fd unavailable: %v", err)
	}
	count := 0
	for _, entry := range entries {
		link, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && link == target {
			count++
		}
	}
	return count
}

func closeExternalTestFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
