//go:build linux && !android

package dae

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/common/redir"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type packetWriter struct {
	ctx         context.Context
	outputMark  uint32
	source      netip.AddrPort
	destination M.Socksaddr

	access sync.Mutex
	conn   *net.UDPConn
}

func (w *packetWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	w.access.Lock()
	defer w.access.Unlock()

	conn := w.conn
	if w.destination == destination && conn != nil {
		_, err := conn.WriteToUDPAddrPort(buffer.Bytes(), w.source)
		if err == nil {
			return nil
		}
		_ = conn.Close()
		w.conn = nil
	}

	var listenConfig net.ListenConfig
	listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	listenConfig.Control = control.Append(listenConfig.Control, control.RoutingMark(w.outputMark))
	listenConfig.Control = control.Append(listenConfig.Control, redir.TProxyWriteBack())
	packetConn, err := listenConfig.ListenPacket(w.ctx, "udp", destination.String())
	if err != nil {
		return err
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return E.New("unexpected UDP packet connection type")
	}
	if w.destination == destination {
		w.conn = udpConn
	} else {
		defer udpConn.Close()
	}
	return common.Error(udpConn.WriteToUDPAddrPort(buffer.Bytes(), w.source))
}

func (w *packetWriter) Close() error {
	w.access.Lock()
	defer w.access.Unlock()
	if w.conn == nil {
		return nil
	}
	err := w.conn.Close()
	w.conn = nil
	return err
}
