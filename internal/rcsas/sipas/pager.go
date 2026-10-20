package sipas

import (
	"context"
	"errors"
	"fmt"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// messagingService is the OMA CPM ICSI of standalone messaging (RCC.07
// §2.6.1), which a pager-mode MESSAGE and its notifications carry: in
// Accept-Contact, so that scscf forks it to the contacts that take it
// (RFC 3841), and asserted, since rcs-as is the network.
const (
	messagingICSI      = "urn:urn-7:3gpp-service.ims.icsi.oma.cpm.msg"
	messagingAcceptTag = `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.oma.cpm.msg"`
)

// viaPlaceholderHost is the sent-by of the Via rcs-as writes, which the
// transport replaces with its listener's (RFC 6761 §6.4: it never
// resolves).
const viaPlaceholderHost = "invalid"

// Pager implements messaging.Deliverer: it sends d as a pager-mode MESSAGE
// and returns once it is answered. It goes to Config.Core, or through
// d.Route, which the engine took from the trusted routes, as a terminating
// request for d.Recipient: no orig, and P-Served-User, so that scscf sends
// it to the recipient's contacts instead of to rcs-as again (docs/hss.md).
//
// The answer says what became of it: a 2xx delivered it; 404 or 604, a
// recipient that does not exist (messaging.ErrUndeliverable); 408, 430, 480,
// 503 or a request that could not be sent, one not reachable now
// (messaging.ErrOffline). Any other failure is one the engine tries again
// later.
func (s *Server) Pager(ctx context.Context, d messaging.Delivery) error {
	next := s.cfg.Core
	if d.Route != "" {
		u, err := sip.ParseURI(d.Route)
		if err != nil || !u.IsSIP() {
			return fmt.Errorf("sipas: route: %w", messaging.ErrUndeliverable)
		}
		next = u
	}
	req, err := s.pagerRequest(d, next)
	if err != nil {
		return err
	}
	dst, err := s.cfg.Resolver.Resolve(ctx, next)
	if err != nil {
		s.cfg.Metrics.Count("sip.pager.unresolved", 1)
		return fmt.Errorf("sipas: next hop: %w", messaging.ErrOffline)
	}
	dst.Listener = s.cfg.Listener
	branch, err := s.ids.Branch()
	if err != nil {
		return err
	}
	v := sip.Via{Transport: string(networkOf(dst)), Host: viaPlaceholderHost}
	v.Params.Set("branch", branch)
	if err := req.Header.Prepend("Via", v.String()); err != nil {
		return err
	}
	type result struct {
		res *sip.Response
		err error
	}
	answered := make(chan result, 1)
	tx, err := s.layer.Request(req, dst, func(res *sip.Response, err error) {
		if err != nil || res.StatusCode >= 200 {
			select {
			case answered <- result{res, err}:
			default:
			}
		}
	})
	if err != nil {
		s.cfg.Metrics.Count("sip.pager.unsent", 1)
		return fmt.Errorf("sipas: send: %w", messaging.ErrOffline)
	}
	select {
	case r := <-answered:
		if r.err != nil {
			s.cfg.Metrics.Count("sip.pager.timeout", 1)
			return fmt.Errorf("sipas: %w", messaging.ErrOffline)
		}
		s.cfg.Metrics.Count(fmt.Sprintf("sip.pager.%d", r.res.StatusCode), 1)
		return pagerOutcome(r.res.StatusCode)
	case <-ctx.Done():
		tx.Terminate()
		return ctx.Err()
	}
}

func networkOf(dst transport.Destination) transport.Network {
	if dst.Network == "" {
		return transport.TCP
	}
	return dst.Network
}

// pagerOutcome is what a pager MESSAGE's final status says to the engine.
func pagerOutcome(code int) error {
	switch {
	case code < 300:
		return nil
	case code == 404 || code == 604:
		return fmt.Errorf("sipas: %d: %w", code, messaging.ErrUndeliverable)
	case code == 408 || code == 430 || code == 480 || code == 503:
		return fmt.Errorf("sipas: %d: %w", code, messaging.ErrOffline)
	}
	return fmt.Errorf("sipas: MESSAGE answered %d", code)
}

// pagerRequest builds d's MESSAGE, without its Via (RFC 3428 §4, RFC 3261
// §8.1.1). The sender's chosen name is the display name of From only, never
// of P-Asserted-Identity, which the network vouches for. The engine has
// escaped its control characters (messaging.EscapeDisplayName), and its
// backslashes are escaped again as the quoted string needs.
func (s *Server) pagerRequest(d messaging.Delivery, next sip.URI) (*sip.Request, error) {
	recipient, err := sip.ParseURI(d.Recipient)
	if err != nil {
		return nil, fmt.Errorf("sipas: recipient: %w", messaging.ErrUndeliverable)
	}
	sender, err := sip.ParseURI(d.Sender)
	if err != nil {
		return nil, fmt.Errorf("sipas: sender: %w", messaging.ErrUndeliverable)
	}
	tag, err := s.ids.Tag()
	if err != nil {
		return nil, err
	}
	callID, err := s.ids.CallID(s.cfg.Host)
	if err != nil {
		return nil, err
	}
	// Written as a quoted string with its own escapes (RFC 3261 §25.1):
	// the engine's \uXXXX escapes stand as text, not as quoted pairs.
	from := sip.Address{DisplayName: d.SenderName, URI: sender}
	from.Params.Set("tag", tag)
	req := &sip.Request{Method: "MESSAGE", URI: recipient, Body: d.CPIM}
	fields := [][2]string{
		{"Max-Forwards", "70"},
		{"Route", "<" + next.String() + ">"},
		{"From", from.String()},
		{"To", "<" + d.Recipient + ">"},
		{"Call-ID", callID},
		{"CSeq", "1 MESSAGE"},
		{"P-Asserted-Identity", "<" + d.Sender + ">"},
		{"P-Served-User", "<" + d.Recipient + ">;sescase=term"},
		{"P-Asserted-Service", messagingICSI},
		{"Accept-Contact", messagingAcceptTag},
	}
	for _, h := range [][2]string{{"Conversation-ID", d.Conversation.ID}, {"Contribution-ID", d.Conversation.Contribution},
		{"InReplyTo-Contribution-ID", d.Conversation.InReplyTo}} {
		if h[1] != "" {
			fields = append(fields, h)
		}
	}
	fields = append(fields, [2]string{"Content-Type", cpim.ContentType})
	for _, f := range fields {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			return nil, fmt.Errorf("sipas: %s: %w", f[0], errors.Join(err, messaging.ErrUndeliverable))
		}
	}
	return req, nil
}
