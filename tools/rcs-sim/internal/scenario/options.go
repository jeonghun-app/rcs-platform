package scenario

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// options is the options scenario (#14 PR F2): both clients register, and
// the client sends the peer two OPTIONS through the network, which answers
// neither itself.
//   - tel-uri: to the peer's tel URI (RFC 3966), with no feature tags. The
//     peer's SIP and tel URIs are one implicit registration set, so the tel
//     form reaches the peer's flow as the SIP form does (#282).
//   - capabilities: to the peer's SIP URI with the client's feature tags in
//     Contact, a capability query (RCC.07). The default profile sends it to
//     rcs-as in both session cases, SESSION_CONTINUED: with rcs-as there it
//     passes through it, and without it the chain goes on.
//
// Each must reach the peer, whose 200 comes back; the second's Contact
// names the peer's feature tags.
func options(r *run) error {
	switch {
	case r.cfg.SIP == nil:
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoSIP })
	case r.cfg.SIPPeer == nil:
		return r.step("register", func(context.Context) (map[string]int64, error) { return nil, errNoPeer })
	}
	var a, b *sipClient
	if err := r.step("register", func(ctx context.Context) (map[string]int64, error) {
		var err error
		if a, err = r.newSIPClient(ctx, *r.cfg.SIP, r.cfg.Self); err != nil {
			return nil, sipError(err)
		}
		if b, err = r.newSIPClient(ctx, *r.cfg.SIPPeer, r.cfg.Peer); err != nil {
			return nil, fmt.Errorf("peer: %w", sipError(err))
		}
		return nil, nil
	}); err != nil {
		return err
	}
	tel, ok := telOf(r.cfg.SIPPeer.IMPU)
	if !ok {
		return r.step("tel-uri", func(context.Context) (map[string]int64, error) {
			return nil, errors.New("the peer's IMPU has no global number for a tel URI")
		})
	}
	if err := r.step("tel-uri", func(ctx context.Context) (map[string]int64, error) {
		req, err := a.ua.NewRequest("OPTIONS", tel)
		if err != nil {
			return nil, err
		}
		_, detail, err := a.query(ctx, b, req)
		return detail, err
	}); err != nil {
		return err
	}
	return r.step("capabilities", func(ctx context.Context) (map[string]int64, error) {
		req, err := a.ua.NewOptions(r.cfg.SIPPeer.IMPU)
		if err != nil {
			return nil, err
		}
		res, detail, err := a.query(ctx, b, req)
		if err != nil {
			return detail, err
		}
		if !hasICSI(res.Header.Get("Contact")) {
			return detail, errors.New("the answer's Contact lost the peer's feature tags")
		}
		return detail, nil
	})
}

// query sends req from c to peer and waits for both ends: the OPTIONS on
// the peer's flow, its Call-ID the one sent, and the peer's 200 back. A
// capability query must keep the client's feature tags on the way.
func (c *sipClient) query(ctx context.Context, peer *sipClient, req *sip.Request) (*sip.Response, map[string]int64, error) {
	res, err := c.ua.Send(ctx, req)
	if err != nil {
		return nil, nil, sipError(err)
	}
	detail := map[string]int64{"status": int64(res.StatusCode)}
	if res.StatusCode != 200 {
		return nil, detail, fmt.Errorf("OPTIONS answered %d", res.StatusCode)
	}
	callID := req.Header.Get("Call-ID")
	for skipped := 0; ; skipped++ {
		select {
		case got := <-peer.options:
			if got.Header.Get("Call-ID") != callID {
				// An earlier step's, answered late; not this one.
				detail["skipped"] = int64(skipped + 1)
				continue
			}
			if hasICSI(req.Header.Get("Contact")) && !hasICSI(got.Header.Get("Contact")) {
				return nil, detail, errors.New("the query lost the client's feature tags on the way")
			}
			return res, detail, nil
		case <-peer.ua.Done():
			return nil, detail, sipError(peer.ua.Err())
		case <-ctx.Done():
			return nil, detail, errors.New("the 200 came back, but the peer saw no OPTIONS")
		}
	}
}

// hasICSI reports whether a Contact value carries an RCS service's ICSI.
func hasICSI(contact string) bool {
	return strings.Contains(contact, "+g.3gpp.icsi-ref") && strings.Contains(contact, "3gpp-service.ims.icsi.oma.cpm")
}

// telOf is the tel URI of a SIP IMPU whose user part is a global number,
// the form an implicit set holds next to it.
func telOf(u sip.URI) (sip.URI, bool) {
	n := u.User
	if !strings.HasPrefix(n, "+") || len(n) < 2 || strings.Trim(n[1:], "0123456789") != "" {
		return sip.URI{}, false
	}
	return sip.URI{Scheme: "tel", User: n}, true
}
