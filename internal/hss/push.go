package hss

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// Notifier sends the HSS-initiated Cx requests: RTR (TS 29.228 §6.1.3) and
// PPR (§6.2.2). *Pusher is the Diameter implementation; tests record calls.
type Notifier interface {
	Deregister(ctx context.Context, r *cx.RTR) error
	PushProfile(ctx context.Context, r *cx.PPR) error
}

// ErrNoSCSCF means no S-CSCF peer was connected and available.
var ErrNoSCSCF = errors.New("hss: no S-CSCF peer is available")

// Pusher sends RTR and PPR on the Diameter connections S-CSCFs opened to
// this task. Under ADR 0005 any S-CSCF instance can act on any registration
// because its state is in DynamoDB, so a request goes by Destination-Realm
// to any connected S-CSCF peer, with Destination-Host naming the peer chosen
// (TS 29.229 §5.5 requires the AVP on HSS-initiated requests), not to the
// Origin-Host recorded at SAR time, whose task may be gone. When a peer
// fails, the next one is tried with the same End-to-End Identifier and the T
// flag (RFC 6733 §5.5.4).
type Pusher struct {
	node     *diameter.Node
	isSCSCF  func(host string) bool
	shuffle  func([]*diameter.Peer)
	timeout  time.Duration
	metrics  Metrics
	attempts int
}

// PusherOptions configures a Pusher.
type PusherOptions struct {
	// SCSCFHostPattern selects the S-CSCF peers among the connected ones
	// (icscf peers speak Cx too): a host name in which '*' matches within
	// one label, as diameter.PeerRule.HostPattern.
	SCSCFHostPattern string
	// Timeout bounds each attempt; the node's request timeout when zero.
	Timeout time.Duration
	// Shuffle orders the candidate peers; nil keeps the node's order.
	Shuffle func([]*diameter.Peer)
	// Metrics counts the outcomes; callers log the failures they get.
	Metrics Metrics
}

// MaxPushAttempts bounds the peers one request is offered to.
const MaxPushAttempts = 3

// NewPusher returns a Pusher sending through node.
func NewPusher(node *diameter.Node, o PusherOptions) *Pusher {
	p := &Pusher{
		node: node, isSCSCF: hostMatcher(o.SCSCFHostPattern), shuffle: o.Shuffle,
		timeout: o.Timeout, metrics: o.Metrics, attempts: MaxPushAttempts,
	}
	if p.metrics == nil {
		p.metrics = noMetrics{}
	}
	return p
}

// hostMatcher matches a DiameterIdentity against a pattern in which '*'
// matches any run of characters within one label, never a dot, compared
// without regard to case: the same rule as diameter.PeerRule.HostPattern,
// which keeps its matcher unexported.
func hostMatcher(pattern string) func(string) bool {
	want := strings.Split(strings.ToLower(pattern), ".")
	return func(host string) bool {
		got := strings.Split(strings.ToLower(host), ".")
		if len(got) != len(want) {
			return false
		}
		for i := range want {
			if !labelMatch(want[i], got[i]) {
				return false
			}
		}
		return true
	}
}

func labelMatch(pattern, label string) bool {
	prefix, suffix, wild := strings.Cut(pattern, "*")
	if !wild {
		return pattern == label
	}
	if strings.Contains(suffix, "*") {
		return false // one wildcard per label, as PeerRule allows
	}
	return len(label) >= len(prefix)+len(suffix) && strings.HasPrefix(label, prefix) && strings.HasSuffix(label, suffix)
}

// peers returns the available S-CSCF peers that negotiated Cx.
func (p *Pusher) peers() []*diameter.Peer {
	var out []*diameter.Peer
	for _, peer := range p.node.Peers() {
		if peer.Available() && p.isSCSCF(peer.Host()) && slices.Contains(peer.Applications(), cx.ApplicationID) {
			out = append(out, peer)
		}
	}
	if p.shuffle != nil {
		p.shuffle(out)
	}
	return out
}

// send builds a request for each peer tried and returns the first answer.
func (p *Pusher) send(ctx context.Context, name string, build func(dest cx.Request) (*diameter.Message, error)) (*diameter.Message, error) {
	sessionID := p.node.NewSessionID("")
	var endToEnd uint32
	retransmit := false
	lastErr := ErrNoSCSCF
	for i, peer := range p.peers() {
		if i == p.attempts {
			break
		}
		// Peer.Send may still deliver a request whose context has ended;
		// one the caller has given up on must not reach an S-CSCF.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		msg, err := build(cx.Request{SessionID: sessionID, DestinationHost: peer.Host(), DestinationRealm: peer.Realm()})
		if err != nil {
			return nil, err
		}
		if retransmit {
			msg.EndToEnd = endToEnd
			msg.Flags |= diameter.FlagRetransmit
		}
		actx, cancel := ctx, context.CancelFunc(func() {})
		if p.timeout > 0 {
			actx, cancel = context.WithTimeout(ctx, p.timeout)
		}
		ans, err := peer.Send(actx, msg)
		cancel()
		if err == nil {
			if rc, ok := ans.ResultCode(); ok && diameter.IsProtocolError(rc) {
				// Unable to deliver, too busy: the next peer may do better.
				lastErr = fmt.Errorf("hss: %s answered with protocol error %d", name, rc)
				endToEnd, retransmit = msg.EndToEnd, true
				continue
			}
			return ans, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		lastErr = err
		// The request may have been processed if the connection closed or
		// the answer was late; a retry must say so.
		endToEnd = msg.EndToEnd
		retransmit = retransmit || errors.Is(err, diameter.ErrConnectionClosed) || errors.Is(err, diameter.ErrTimeout)
	}
	return nil, lastErr
}

// Deregister implements Notifier. r.Request is filled in per peer.
func (p *Pusher) Deregister(ctx context.Context, r *cx.RTR) error {
	ans, err := p.send(ctx, "RTR", func(dest cx.Request) (*diameter.Message, error) {
		req := *r
		req.Request = dest
		return req.Message(p.node)
	})
	return p.outcome("rtr", ans, err, func(m *diameter.Message) (cx.Result, error) {
		rta, err := cx.ParseRTA(m)
		if err != nil {
			return cx.Result{}, err
		}
		return rta.Result, nil
	})
}

// PushProfile implements Notifier. r.Request is filled in per peer.
func (p *Pusher) PushProfile(ctx context.Context, r *cx.PPR) error {
	ans, err := p.send(ctx, "PPR", func(dest cx.Request) (*diameter.Message, error) {
		req := *r
		req.Request = dest
		return req.Message(p.node)
	})
	return p.outcome("ppr", ans, err, func(m *diameter.Message) (cx.Result, error) {
		ppa, err := cx.ParsePPA(m)
		if err != nil {
			return cx.Result{}, err
		}
		return ppa.Result, nil
	})
}

// RejectedError is an RTA or PPA with a result other than success.
type RejectedError struct {
	Command string // "RTR" or "PPR"
	Result  cx.Result
}

func (e *RejectedError) Error() string { return "hss: " + e.Command + " answered " + e.Result.String() }

func (p *Pusher) outcome(name string, ans *diameter.Message, err error, parse func(*diameter.Message) (cx.Result, error)) error {
	if errors.Is(err, ErrNoSCSCF) {
		// Counted apart from failures: it means no S-CSCF holds a
		// connection to this task, which is a deployment fault (docs/hss.md,
		// HSS-initiated requests), not an S-CSCF refusing.
		p.metrics.Count("push."+name+".no_peer", 1)
		return err
	}
	if err != nil {
		p.metrics.Count("push."+name+".failed", 1)
		return err
	}
	result, err := parse(ans)
	if err != nil {
		p.metrics.Count("push."+name+".failed", 1)
		return fmt.Errorf("hss: malformed %s answer: %w", strings.ToUpper(name)[:2]+"A", err)
	}
	if !result.IsSuccess() {
		p.metrics.Count("push."+name+".rejected", 1)
		return &RejectedError{Command: strings.ToUpper(name), Result: result}
	}
	p.metrics.Count("push."+name+".sent", 1)
	return nil
}
