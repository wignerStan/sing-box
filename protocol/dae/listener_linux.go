//go:build linux && !android

package dae

import (
	"context"
	stderrors "errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/common/redir"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

type listenerSet struct {
	inbound   *Inbound
	session   *controlSession
	ctx       context.Context
	cancel    context.CancelFunc
	tcp4      net.Listener
	tcp6      net.Listener
	udp       *net.UDPConn
	closeOnce sync.Once
	waiter    sync.WaitGroup
}

func newListenerSet(parent context.Context, inbound *Inbound, session *controlSession, tcp4 net.Listener, tcp6 net.Listener, udp *net.UDPConn) *listenerSet {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	return &listenerSet{
		inbound: inbound,
		session: session,
		ctx:     ctx,
		cancel:  cancel,
		tcp4:    tcp4,
		tcp6:    tcp6,
		udp:     udp,
	}
}

func (s *listenerSet) Start() error {
	if s == nil {
		return E.New("nil dae listener set")
	}
	if s.tcp4 == nil || s.tcp6 == nil || s.udp == nil {
		return E.New("incomplete dae listener set")
	}
	s.waiter.Add(3)
	go s.acceptLoop(s.tcp4)
	go s.acceptLoop(s.tcp6)
	go s.udpLoop()
	return nil
}

func (s *listenerSet) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		var errs []error
		if s.tcp4 != nil {
			errs = append(errs, s.tcp4.Close())
		}
		if s.tcp6 != nil {
			errs = append(errs, s.tcp6.Close())
		}
		if s.udp != nil {
			errs = append(errs, s.udp.Close())
		}
		closeErr = E.Errors(errs...)
		s.waiter.Wait()
	})
	return closeErr
}

func (s *listenerSet) acceptLoop(listener net.Listener) {
	defer s.waiter.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.ctx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				s.inbound.logger.Error("accept dae TCP connection: ", err)
			}
			return
		}
		go s.inbound.handleTCP(s.session, conn)
	}
}

func (s *listenerSet) udpLoop() {
	defer s.waiter.Done()
	payload := make([]byte, udpReadBufferSize)
	oob := make([]byte, udpOOBBufferSize)
	for {
		n, oobN, flags, source, err := s.udp.ReadMsgUDPAddrPort(payload, oob)
		if err != nil {
			if s.ctx.Err() == nil && !stderrors.Is(err, net.ErrClosed) {
				s.inbound.logger.Error("read dae UDP packet: ", err)
			}
			return
		}
		if flags&unix.MSG_TRUNC != 0 {
			s.inbound.logger.Warn("drop truncated dae UDP packet from ", source)
			continue
		}
		destination, err := redir.GetOriginalDestinationFromOOB(oob[:oobN])
		if err != nil {
			s.inbound.logger.Warn("read dae UDP original destination: ", err)
			continue
		}
		if n == len(payload) {
			s.inbound.logger.Warn("drop oversized dae UDP packet from ", source)
			continue
		}
		s.inbound.udpNat.NewPacket(
			[][]byte{payload[:n]},
			M.SocksaddrFromNetIP(source).Unwrap(),
			M.SocksaddrFromNetIP(destination).Unwrap(),
			s.session,
		)
	}
}
