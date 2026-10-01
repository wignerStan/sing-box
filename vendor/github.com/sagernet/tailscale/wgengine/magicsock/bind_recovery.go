// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import "time"

const (
	bindRetryInitial = time.Second
	bindRetryMaximum = 30 * time.Second
)

// These methods require RebindingUDPConn.mu. Failure state belongs to the
// socket, not the network snapshot: the physical-interface binder and netmon
// may become ready in a different order, even on the very same network.
func (ruc *RebindingUDPConn) clearBindFailureLocked() {
	ruc.bindErr = nil
	ruc.bindRetryDelay = 0
	ruc.bindRetryAfter = time.Time{}
}

func (ruc *RebindingUDPConn) noteBindFailureLocked(err error, now time.Time) {
	ruc.bindErr = err
	if ruc.bindRetryDelay == 0 {
		ruc.bindRetryDelay = bindRetryInitial
	} else {
		ruc.bindRetryDelay = min(2*ruc.bindRetryDelay, bindRetryMaximum)
	}
	ruc.bindRetryAfter = now.Add(ruc.bindRetryDelay)
}

// retryUnboundSockets uses the existing minor-link/periodic discovery lifecycle.
// There is no independent timer, goroutine, or unbound fallback dialer. The
// original physical-interface ListenPacket hook remains authoritative.
func (c *Conn) retryUnboundSockets() {
	if c.closing.Load() || c.networkDown() || c.onlyTCP443.Load() {
		return
	}
	now := time.Now()
	v6 := c.retryUnboundSocket(&c.pconn6, "udp6", now)
	v4 := c.retryUnboundSocket(&c.pconn4, "udp4", now)
	if v4 && c.portMapper != nil {
		c.portMapper.SetLocalPort(c.LocalPort())
	}
	if v4 || v6 {
		c.UpdatePMTUD()
		c.resetEndpointStates()
	}
}

func (c *Conn) retryUnboundSocket(ruc *RebindingUDPConn, network string, now time.Time) bool {
	ruc.mu.Lock()
	defer ruc.mu.Unlock()
	if c.closing.Load() || ruc.bindErr == nil || now.Before(ruc.bindRetryAfter) {
		return false
	}
	if err := c.bindSocketLocked(ruc, network, keepCurrentPort); err != nil {
		return false
	}
	c.logf("magicsock: recovered %s socket after bind failure", network)
	return true
}
