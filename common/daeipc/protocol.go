//go:build linux && !android

// SPDX-License-Identifier: GPL-3.0-or-later

// Package daeipc implements the versioned Unix-domain control protocol used
// between dae's Linux datapath and the sing-box dae inbound.
package daeipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

const (
	ProtocolName = "dae-sing-box"
	Version      = uint16(1)

	TypeRegister       = "register"
	TypeRegisterAck    = "register_ack"
	TypeLookup         = "lookup"
	TypeLookupResponse = "lookup_response"
	TypePing           = "ping"
	TypePong           = "pong"

	ListenerTCP4 = "tcp4"
	ListenerTCP6 = "tcp6"
	ListenerUDP4 = "udp4"
	ListenerUDP6 = "udp6"

	NetworkTCP = "tcp"
	NetworkUDP = "udp"

	maxMessageSize = 64 << 10
	maxFiles       = 8
)

var (
	ErrMessageTooLarge = errors.New("dae IPC message is too large")
	ErrTruncated       = errors.New("dae IPC message or control data was truncated")
)

// Message is intentionally additive and JSON encoded. New optional fields can
// be introduced without changing the file-descriptor transport or breaking an
// older peer that understands the same major protocol version.
type Message struct {
	Protocol string `json:"protocol"`
	Version  uint16 `json:"version"`
	Type     string `json:"type"`

	RequestID  uint64 `json:"request_id,omitempty"`
	Generation uint64 `json:"generation,omitempty"`

	TProxyPort uint16   `json:"tproxy_port,omitempty"`
	OutputMark uint32   `json:"output_mark,omitempty"`
	Listeners  []string `json:"listeners,omitempty"`

	Network     string `json:"network,omitempty"`
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`

	Found       bool   `json:"found,omitempty"`
	PID         uint32 `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
	UserID      int32  `json:"user_id,omitempty"`
	HasUserID   bool   `json:"has_user_id,omitempty"`
	SourceMAC   string `json:"source_mac,omitempty"`
	DSCP        uint8  `json:"dscp,omitempty"`

	Error string `json:"error,omitempty"`
}

func NewMessage(messageType string) Message {
	return Message{
		Protocol: ProtocolName,
		Version:  Version,
		Type:     messageType,
	}
}

func (m Message) ValidateEnvelope() error {
	if m.Protocol != ProtocolName {
		return fmt.Errorf("unexpected protocol %q", m.Protocol)
	}
	if m.Version != Version {
		return fmt.Errorf("unsupported protocol version %d", m.Version)
	}
	if m.Type == "" {
		return errors.New("missing message type")
	}
	return nil
}

// Write sends exactly one sequence-packet message and, optionally, file
// descriptors. The caller retains ownership of all files.
func Write(conn *net.UnixConn, message Message, files ...*os.File) error {
	if conn == nil {
		return errors.New("nil Unix connection")
	}
	if message.Protocol == "" {
		message.Protocol = ProtocolName
	}
	if message.Version == 0 {
		message.Version = Version
	}
	if err := message.ValidateEnvelope(); err != nil {
		return err
	}
	if len(files) > maxFiles {
		return fmt.Errorf("too many file descriptors: %d > %d", len(files), maxFiles)
	}
	payload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("encode dae IPC message: %w", err)
	}
	if len(payload) > maxMessageSize {
		return ErrMessageTooLarge
	}

	var oob []byte
	if len(files) > 0 {
		fds := make([]int, 0, len(files))
		for _, file := range files {
			if file == nil {
				return errors.New("nil file descriptor")
			}
			fds = append(fds, int(file.Fd()))
		}
		oob = unix.UnixRights(fds...)
	}

	n, oobN, err := conn.WriteMsgUnix(payload, oob, nil)
	if err != nil {
		return fmt.Errorf("write dae IPC message: %w", err)
	}
	if n != len(payload) || oobN != len(oob) {
		return fmt.Errorf("short dae IPC write: payload %d/%d, control %d/%d", n, len(payload), oobN, len(oob))
	}
	return nil
}

// Read receives one sequence-packet message. The caller owns every returned
// file and must close it. Any descriptors received with a malformed message are
// closed before Read returns an error.
func Read(conn *net.UnixConn) (Message, []*os.File, error) {
	if conn == nil {
		return Message{}, nil, errors.New("nil Unix connection")
	}
	payload := make([]byte, maxMessageSize)
	oob := make([]byte, unix.CmsgSpace(maxFiles*4))
	n, oobN, flags, _, err := conn.ReadMsgUnix(payload, oob)
	if err != nil {
		return Message{}, nil, err
	}
	files, parseErr := parseFiles(oob[:oobN])
	if parseErr != nil {
		return Message{}, nil, parseErr
	}
	closeFiles := func() {
		for _, file := range files {
			_ = file.Close()
		}
	}
	if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
		closeFiles()
		return Message{}, nil, ErrTruncated
	}

	var message Message
	if err := json.Unmarshal(payload[:n], &message); err != nil {
		closeFiles()
		return Message{}, nil, fmt.Errorf("decode dae IPC message: %w", err)
	}
	if err := message.ValidateEnvelope(); err != nil {
		closeFiles()
		return Message{}, nil, err
	}
	return message, files, nil
}

func parseFiles(oob []byte) ([]*os.File, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parse dae IPC control message: %w", err)
	}
	var files []*os.File
	closeFiles := func() {
		for _, file := range files {
			_ = file.Close()
		}
	}
	for _, controlMessage := range messages {
		fds, parseErr := unix.ParseUnixRights(&controlMessage)
		if parseErr != nil {
			closeFiles()
			return nil, fmt.Errorf("parse dae IPC file descriptors: %w", parseErr)
		}
		for _, fd := range fds {
			unix.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), "dae-ipc-fd"))
		}
	}
	if len(files) > maxFiles {
		closeFiles()
		return nil, fmt.Errorf("too many received file descriptors: %d > %d", len(files), maxFiles)
	}
	return files, nil
}

func PeerCredentials(conn *net.UnixConn) (*unix.Ucred, error) {
	if conn == nil {
		return nil, errors.New("nil Unix connection")
	}
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get Unix syscall connection: %w", err)
	}
	var (
		credentials *unix.Ucred
		optionErr   error
	)
	if err := rawConn.Control(func(fd uintptr) {
		credentials, optionErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, fmt.Errorf("read Unix peer credentials: %w", err)
	}
	if optionErr != nil {
		return nil, fmt.Errorf("read Unix peer credentials: %w", optionErr)
	}
	return credentials, nil
}
