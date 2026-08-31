//go:build linux && !android

package dae

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/daeipc"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

type controlSession struct {
	inbound    *Inbound
	conn       *net.UnixConn
	generation uint64

	writeAccess   sync.Mutex
	pendingAccess sync.Mutex
	pending       map[uint64]chan lookupResult
	requestID     atomic.Uint64
	closeOnce     sync.Once
	closed        chan struct{}
}

type lookupResult struct {
	message daeipc.Message
	err     error
}

func newControlSession(inbound *Inbound, conn *net.UnixConn) *controlSession {
	return &controlSession{
		inbound: inbound,
		conn:    conn,
		pending: make(map[uint64]chan lookupResult),
		closed:  make(chan struct{}),
	}
}

func (s *controlSession) register() {
	if err := s.conn.SetDeadline(time.Now().Add(registrationTimeout)); err != nil {
		s.close(E.Cause(err, "set dae registration deadline"))
		return
	}
	message, files, err := daeipc.Read(s.conn)
	if clearErr := s.conn.SetDeadline(time.Time{}); clearErr != nil && err == nil {
		err = clearErr
	}
	if err != nil {
		s.close(E.Cause(err, "read dae registration"))
		return
	}
	if message.Type != daeipc.TypeRegister {
		closeFiles(files)
		s.close(E.New("expected dae registration, got ", message.Type))
		return
	}
	s.generation = message.Generation

	set, err := s.adoptListeners(message, files)
	ack := daeipc.NewMessage(daeipc.TypeRegisterAck)
	ack.Generation = message.Generation
	if err != nil {
		ack.Error = err.Error()
		_ = s.write(ack)
		s.close(err)
		return
	}
	if err := s.write(ack); err != nil {
		_ = set.Close()
		s.close(err)
		return
	}

	go s.readLoop()
	if err := s.inbound.activateListenerSet(set); err != nil {
		s.close(err)
		return
	}
}

func (s *controlSession) adoptListeners(message daeipc.Message, files []*os.File) (*listenerSet, error) {
	defer closeFiles(files)
	if message.Generation == 0 {
		return nil, E.New("missing dae generation")
	}
	if message.OutputMark != s.inbound.outputMark {
		return nil, E.New("dae output mark mismatch: received ", message.OutputMark, ", configured ", s.inbound.outputMark)
	}
	if message.TProxyPort == 0 {
		return nil, E.New("invalid dae tproxy port")
	}
	if len(message.Listeners) != len(files) {
		return nil, E.New("dae listener descriptor count mismatch")
	}

	var (
		tcp4 net.Listener
		tcp6 net.Listener
		udp  *net.UDPConn
	)
	closeAdopted := func() {
		if tcp4 != nil {
			_ = tcp4.Close()
		}
		if tcp6 != nil {
			_ = tcp6.Close()
		}
		if udp != nil {
			_ = udp.Close()
		}
	}
	for index, kind := range message.Listeners {
		file := files[index]
		switch kind {
		case daeipc.ListenerTCP4:
			if tcp4 != nil {
				closeAdopted()
				return nil, E.New("duplicate TCP4 listener")
			}
			listener, err := net.FileListener(file)
			if err != nil {
				closeAdopted()
				return nil, E.Cause(err, "adopt dae TCP4 listener")
			}
			if !daeListenerFamilyMatches(kind, listener.Addr()) {
				_ = listener.Close()
				closeAdopted()
				return nil, E.New("dae TCP4 listener has the wrong address family")
			}
			tcp4 = listener
		case daeipc.ListenerTCP6:
			if tcp6 != nil {
				closeAdopted()
				return nil, E.New("duplicate TCP6 listener")
			}
			listener, err := net.FileListener(file)
			if err != nil {
				closeAdopted()
				return nil, E.Cause(err, "adopt dae TCP6 listener")
			}
			if !daeListenerFamilyMatches(kind, listener.Addr()) {
				_ = listener.Close()
				closeAdopted()
				return nil, E.New("dae TCP6 listener has the wrong address family")
			}
			tcp6 = listener
		case daeipc.ListenerUDP4, daeipc.ListenerUDP6:
			if udp != nil {
				closeAdopted()
				return nil, E.New("duplicate UDP listener")
			}
			packetConn, err := net.FilePacketConn(file)
			if err != nil {
				closeAdopted()
				return nil, E.Cause(err, "adopt dae UDP listener")
			}
			udpConn, ok := packetConn.(*net.UDPConn)
			if !ok {
				_ = packetConn.Close()
				closeAdopted()
				return nil, E.New("unexpected dae UDP listener type")
			}
			if !daeListenerFamilyMatches(kind, udpConn.LocalAddr()) {
				_ = udpConn.Close()
				closeAdopted()
				return nil, E.New("dae UDP listener has the wrong address family")
			}
			udp = udpConn
		default:
			closeAdopted()
			return nil, E.New("unsupported dae listener kind: ", kind)
		}
	}
	if tcp4 == nil || tcp6 == nil || udp == nil {
		closeAdopted()
		return nil, E.New("dae registration requires TCP4, TCP6, and UDP listeners")
	}
	for _, address := range []net.Addr{tcp4.Addr(), tcp6.Addr(), udp.LocalAddr()} {
		if M.SocksaddrFromNet(address).Port != message.TProxyPort {
			closeAdopted()
			return nil, E.New("dae listener port mismatch")
		}
	}
	return newListenerSet(s.inbound.ctx, s.inbound, s, tcp4, tcp6, udp), nil
}

// daeListenerFamilyMatches keeps the descriptor kind and the actual socket
// family coupled. A malformed or stale registration must not silently turn a
// TCP4/UDP4 handoff into a dual-stack socket (or vice versa), because that can
// make one generation consume traffic intended for another listener.
func daeListenerFamilyMatches(kind string, address net.Addr) bool {
	switch kind {
	case daeipc.ListenerTCP4, daeipc.ListenerTCP6:
		tcpAddress, ok := address.(*net.TCPAddr)
		if !ok {
			return false
		}
		isIPv4 := tcpAddress.IP.To4() != nil
		if kind == daeipc.ListenerTCP4 {
			return isIPv4
		}
		return !isIPv4 && tcpAddress.IP.To16() != nil
	case daeipc.ListenerUDP4, daeipc.ListenerUDP6:
		udpAddress, ok := address.(*net.UDPAddr)
		if !ok {
			return false
		}
		isIPv4 := udpAddress.IP.To4() != nil
		if kind == daeipc.ListenerUDP4 {
			return isIPv4
		}
		return !isIPv4 && udpAddress.IP.To16() != nil
	default:
		return false
	}
}

func (s *controlSession) write(message daeipc.Message) error {
	s.writeAccess.Lock()
	defer s.writeAccess.Unlock()
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	return daeipc.Write(s.conn, message)
}

func (s *controlSession) readLoop() {
	for {
		message, files, err := daeipc.Read(s.conn)
		closeFiles(files)
		if err != nil {
			s.close(err)
			return
		}
		if len(files) != 0 {
			s.close(E.New("unexpected file descriptors in dae response"))
			return
		}
		switch message.Type {
		case daeipc.TypeLookupResponse:
			s.pendingAccess.Lock()
			responseChannel := s.pending[message.RequestID]
			delete(s.pending, message.RequestID)
			s.pendingAccess.Unlock()
			if responseChannel != nil {
				responseChannel <- lookupResult{message: message}
			}
		case daeipc.TypePong:
		default:
			s.close(E.New("unsupported dae response type: ", message.Type))
			return
		}
	}
}

func (s *controlSession) lookup(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (daeipc.Message, error) {
	if s == nil || s.conn == nil {
		return daeipc.Message{}, net.ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	requestID := s.requestID.Add(1)
	if requestID == 0 {
		requestID = s.requestID.Add(1)
	}
	responseChannel := make(chan lookupResult, 1)
	s.pendingAccess.Lock()
	s.pending[requestID] = responseChannel
	s.pendingAccess.Unlock()

	request := daeipc.NewMessage(daeipc.TypeLookup)
	request.RequestID = requestID
	request.Generation = s.generation
	request.Network = network
	request.Source = source.String()
	request.Destination = destination.String()
	if err := s.write(request); err != nil {
		s.removePending(requestID)
		return daeipc.Message{}, err
	}

	select {
	case result := <-responseChannel:
		if result.err != nil {
			return daeipc.Message{}, result.err
		}
		if result.message.Generation != 0 && result.message.Generation != s.generation {
			return daeipc.Message{}, E.New("dae metadata generation mismatch")
		}
		return result.message, nil
	case <-ctx.Done():
		s.removePending(requestID)
		return daeipc.Message{}, ctx.Err()
	case <-s.closed:
		s.removePending(requestID)
		return daeipc.Message{}, net.ErrClosed
	}
}

func (s *controlSession) removePending(requestID uint64) {
	s.pendingAccess.Lock()
	delete(s.pending, requestID)
	s.pendingAccess.Unlock()
}

func (s *controlSession) close(reason error) {
	s.closeOnce.Do(func() {
		_ = s.conn.Close()
		close(s.closed)
		s.pendingAccess.Lock()
		pending := s.pending
		s.pending = make(map[uint64]chan lookupResult)
		s.pendingAccess.Unlock()
		for _, responseChannel := range pending {
			responseChannel <- lookupResult{err: reason}
		}
		s.inbound.sessionClosed(s)
	})
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		if file != nil {
			_ = file.Close()
		}
	}
}
