//go:build with_utls

package tls

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	utls "github.com/metacubex/utls"
	"github.com/stretchr/testify/require"
)

// Check the actual Reality ClientHello. Removing the browser's hybrid key
// share causes Xray 26.9.8+ to reject authentication before TLS completes.
func TestRealityClientPreservesChromeKeyShares(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	config, err := NewRealityClient(context.Background(), log.NewNOPFactory().Logger(), "example.com", option.OutboundTLSOptions{
		ServerName: "example.com",
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
		Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: "01"},
	})
	require.NoError(t, err)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	require.NoError(t, server.SetReadDeadline(time.Now().Add(5*time.Second)))
	done := make(chan error, 1)
	go func() {
		_, handshakeErr := config.(*RealityClientConfig).ClientHandshake(context.Background(), client)
		done <- handshakeErr
	}()
	header := make([]byte, 5)
	_, err = io.ReadFull(server, header)
	require.NoError(t, err)
	require.Equal(t, byte(22), header[0])
	hello := make([]byte, binary.BigEndian.Uint16(header[3:]))
	_, err = io.ReadFull(server, hello)
	require.NoError(t, err)
	require.NoError(t, server.Close())
	require.Error(t, <-done) // The capture peer deliberately stops after ClientHello.
	require.GreaterOrEqual(t, len(hello), 39)
	require.Equal(t, byte(1), hello[0])
	offset := 38
	offset += 1 + int(hello[offset]) // session ID
	require.GreaterOrEqual(t, len(hello), offset+2)
	offset += 2 + int(binary.BigEndian.Uint16(hello[offset:])) // cipher suites
	require.Greater(t, len(hello), offset)
	offset += 1 + int(hello[offset]) // compression methods
	require.GreaterOrEqual(t, len(hello), offset+2)
	extensionsSize := int(binary.BigEndian.Uint16(hello[offset:]))
	offset += 2
	require.Equal(t, len(hello), offset+extensionsSize)
	var curves, shares []uint16
	for offset < len(hello) {
		require.GreaterOrEqual(t, len(hello), offset+4)
		kind := binary.BigEndian.Uint16(hello[offset:])
		size := int(binary.BigEndian.Uint16(hello[offset+2:]))
		offset += 4
		require.GreaterOrEqual(t, len(hello), offset+size)
		data := hello[offset : offset+size]
		offset += size
		if kind == 10 {
			require.GreaterOrEqual(t, len(data), 2)
			require.Equal(t, len(data)-2, int(binary.BigEndian.Uint16(data)))
			for i := 2; i+2 <= len(data); i += 2 {
				curves = append(curves, binary.BigEndian.Uint16(data[i:]))
			}
		}
		if kind == 51 {
			require.GreaterOrEqual(t, len(data), 2)
			require.Equal(t, len(data)-2, int(binary.BigEndian.Uint16(data)))
			for i := 2; i < len(data); {
				require.GreaterOrEqual(t, len(data), i+4)
				group := binary.BigEndian.Uint16(data[i:])
				keySize := int(binary.BigEndian.Uint16(data[i+2:]))
				i += 4
				require.GreaterOrEqual(t, len(data), i+keySize)
				if group == uint16(utls.X25519MLKEM768) {
					require.Equal(t, 1216, keySize)
				}
				shares = append(shares, group)
				i += keySize
			}
		}
	}
	require.Contains(t, curves, uint16(utls.X25519MLKEM768))
	require.Contains(t, shares, uint16(utls.X25519MLKEM768))
	require.Contains(t, shares, uint16(utls.X25519))
	require.Less(t, slices.Index(shares, uint16(utls.X25519MLKEM768)), slices.Index(shares, uint16(utls.X25519)))
}
