package proxy

import (
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// receiveACK forwards an ACK that belongs to no transaction: the ACK for a 2xx,
// which is end to end (RFC 3261 §13.2.2.4, RFC 6026 §7.1). It is forwarded
// statelessly (§16.11) on a goroutine of its own, since the send can block; at
// MaxContexts ACKs in flight it is dropped, and the UAS's retransmitted 2xx
// draws another from the UAC (§13.3.1.4).
func (p *Proxy) receiveACK(req *sip.Request, src transport.Source) {
	p.mu.Lock()
	if p.closed || p.acks >= p.maxCtx {
		p.mu.Unlock()
		p.stats.acksDropped.Add(1)
		return
	}
	p.acks++
	p.mu.Unlock()
	p.spawn(func() {
		defer func() {
			p.mu.Lock()
			p.acks--
			p.mu.Unlock()
		}()
		if p.forwardACK(req, src) {
			p.stats.acksForwarded.Add(1)
		} else {
			p.stats.acksDropped.Add(1)
		}
	})
}

// forwardACK processes an ACK as §16.11 says: the checks and routing of a
// stateful request, the first target only, and a branch ID computed from the
// ACK so its retransmissions carry the same one. Nothing can be answered, so an
// ACK that fails a check is dropped.
func (p *Proxy) forwardACK(req *sip.Request, src transport.Source) bool {
	if p.validate(req, "") != nil {
		return false
	}
	in, err := p.preprocess(req, src)
	if err != nil {
		return false
	}
	dec := p.router.Route(p.ctx, in)
	if dec.Response != nil || dec.Status != 0 || len(dec.Targets) == 0 {
		return false
	}
	fwd, dst, err := p.buildBranch(p.ctx, in, &dec, dec.Targets[0], false)
	if err != nil {
		return false
	}
	if err := addVia(fwd, dst, p.statelessBranch(req)); err != nil {
		return false
	}
	_, err = p.sender.SendRequest(fwd, dst)
	return err == nil
}
