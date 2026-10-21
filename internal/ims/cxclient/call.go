package cxclient

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
)

// ErrNoPeer means no HSS task was connected and available.
var ErrNoPeer = errors.New("cxclient: no HSS peer is available")

// SentError is the error of a request whose last attempt never left this
// node, though an earlier one did: it may have reached an HSS task, which
// may have served it. It wraps the last attempt's error, which Is and As
// still find, so the outcome is classified as before; NeverSent tells the
// two apart.
type SentError struct{ Err error }

func (e *SentError) Error() string { return e.Err.Error() }
func (e *SentError) Unwrap() error { return e.Err }

// NeverSent reports whether err is from a request that certainly reached no
// HSS task: none was connected (ErrNoPeer), or every attempt found its task
// unavailable, or not speaking Cx, before the send (unsent). A request one
// attempt of which was sent (SentError), or that failed any other way, a
// timeout or a closed connection included, may have been served.
func NeverSent(err error) bool {
	var se *SentError
	if errors.As(err, &se) {
		return false
	}
	return errors.Is(err, ErrNoPeer) || unsent(err)
}

// ProtocolError is an answer with a protocol error (3xxx, RFC 6733 §7.1.3),
// whose generic format carries none of the command's fields.
type ProtocolError struct {
	Command string
	Result  cx.Result
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("cxclient: %s answered with protocol error %d", e.Command, e.Result.Code)
}

// UAR sends a User-Authorization-Request (TS 29.228 §6.1.1). Destination-Realm
// defaults to Config.DestinationRealm. Any well-formed answer is returned,
// whatever its result: read it with Classify.
func (c *Client) UAR(ctx context.Context, r *cx.UAR) (*cx.UAA, error) {
	req := *r
	return call(ctx, c, "UAR", &req.Request, req.Message, cx.ParseUAA, func(a *cx.UAA) cx.Result { return a.Result })
}

// LIR sends a Location-Info-Request (TS 29.228 §6.1.4).
func (c *Client) LIR(ctx context.Context, r *cx.LIR) (*cx.LIA, error) {
	req := *r
	return call(ctx, c, "LIR", &req.Request, req.Message, cx.ParseLIA, func(a *cx.LIA) cx.Result { return a.Result })
}

// MAR sends a Multimedia-Auth-Request (TS 29.228 §6.3). Server-Name defaults
// to Config.ServerName. Authenticate adds the choice of scheme on top.
func (c *Client) MAR(ctx context.Context, r *cx.MAR) (*cx.MAA, error) {
	req := *r
	if req.ServerName == "" {
		req.ServerName = c.cfg.ServerName
	}
	return call(ctx, c, "MAR", &req.Request, req.Message, cx.ParseMAA, func(a *cx.MAA) cx.Result { return a.Result })
}

// SAR sends a Server-Assignment-Request (TS 29.228 §6.1.2). Server-Name
// defaults to Config.ServerName.
func (c *Client) SAR(ctx context.Context, r *cx.SAR) (*cx.SAA, error) {
	req := *r
	if req.ServerName == "" {
		req.ServerName = c.cfg.ServerName
	}
	return call(ctx, c, "SAR", &req.Request, req.Message, cx.ParseSAA, func(a *cx.SAA) cx.Result { return a.Result })
}

// call sends one request, retrying it once on another HSS task when the first
// is busy or unreachable. The retry keeps the Session-Id and the End-to-End
// Identifier and sets the T flag (RFC 6733 §5.5.4), so the HSS can tell it
// from a new request; every HSS task works on the same shared subscriber
// state, so any of them can answer it.
func call[A any](ctx context.Context, c *Client, cmd string, common *cx.Request, build func(*diameter.Node) (*diameter.Message, error), parse func(*diameter.Message) (A, error), result func(A) cx.Result) (A, error) {
	var zero A
	start := c.clock.Now()
	defer func() { c.metrics.Timing("cxclient."+cmd+".latency", c.clock.Now().Sub(start)) }()
	if common.DestinationRealm == "" {
		common.DestinationRealm = c.cfg.DestinationRealm
	}
	if common.SessionID == "" {
		common.SessionID = c.sessions.Next("")
	}
	first := c.pick()
	if first == nil {
		c.metrics.Count("cxclient."+cmd+".error.no_peer", 1)
		return zero, ErrNoPeer
	}
	msg, ans, err := c.attempt(ctx, first, build, nil)
	sent := left(msg, err)
	if timedOut(ctx, err) {
		c.exclude(first)
	}
	if retryable(ctx, ans, err) {
		if second := c.pickAfter(first); second != nil {
			c.metrics.Count("cxclient."+cmd+".retry", 1)
			if msg != nil {
				_, ans, err = c.attempt(ctx, second, build, msg)
			}
		}
	}
	if err != nil {
		c.metrics.Count("cxclient."+cmd+".error."+errorKind(err), 1)
		err = fmt.Errorf("cxclient: %s: %w", cmd, err)
		if sent && NeverSent(err) {
			// The retry found no task, but the first attempt left (#261).
			err = &SentError{Err: err}
		}
		return zero, err
	}
	if rc, ok := ans.ResultCode(); ok && diameter.IsProtocolError(rc) {
		res := cx.ResultCode(rc)
		c.metrics.Count("cxclient."+cmd+"."+resultName(res), 1)
		return zero, &ProtocolError{Command: cmd, Result: res}
	}
	a, err := parse(ans)
	if err != nil {
		c.metrics.Count("cxclient."+cmd+".error.malformed", 1)
		return zero, fmt.Errorf("cxclient: %s answer: %w", cmd, err)
	}
	c.metrics.Count("cxclient."+cmd+"."+resultName(result(a)), 1)
	return a, nil
}

// attempt sends the request built for one peer's node. prev, when set, is the
// first attempt, whose End-to-End Identifier a retry keeps.
func (c *Client) attempt(ctx context.Context, p *hssPeer, build func(*diameter.Node) (*diameter.Message, error), prev *diameter.Message) (*diameter.Message, *diameter.Message, error) {
	msg, err := build(p.node)
	if err != nil {
		return nil, nil, err
	}
	if prev != nil && prev.EndToEnd != 0 {
		// The first attempt may have reached its task; one that never left
		// has no End-to-End Identifier and needs no T flag.
		msg.EndToEnd = prev.EndToEnd
		msg.Flags |= diameter.FlagRetransmit
	}
	actx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()
	ans, err := c.send(actx, p.peer, msg)
	return msg, ans, err
}

// left reports whether an attempt that built msg and ended with err left
// for its task: all but one the peer refused before the send (unsent).
func left(msg *diameter.Message, err error) bool { return msg != nil && !unsent(err) }

// unsent reports an error the peer returns before it sends anything: no
// open connection, or no Cx on it.
func unsent(err error) bool {
	return errors.Is(err, diameter.ErrPeerUnavailable) || errors.Is(err, diameter.ErrApplicationNotNegotiated)
}

// retryable reports whether a failed attempt may be repeated on another HSS
// task: the task was busy (DIAMETER_TOO_BUSY) or shutting down
// (DIAMETER_UNABLE_TO_DELIVER, which a node answers while it drains), or the
// request did not get through, as long as the caller still waits.
func retryable(ctx context.Context, ans *diameter.Message, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		return errors.Is(err, diameter.ErrPeerUnavailable) || errors.Is(err, diameter.ErrConnectionClosed) ||
			errors.Is(err, diameter.ErrTimeout) || errors.Is(err, context.DeadlineExceeded) ||
			errors.Is(err, diameter.ErrApplicationNotNegotiated)
	}
	rc, ok := ans.ResultCode()
	return ok && (rc == diameter.ResultTooBusy || rc == diameter.ResultUnableToDeliver)
}

// timedOut reports an attempt that ran out of RequestTimeout while the caller
// still waits: the task may have stopped answering without closing its
// connection.
func timedOut(ctx context.Context, err error) bool {
	return ctx.Err() == nil && (errors.Is(err, diameter.ErrTimeout) || errors.Is(err, context.DeadlineExceeded))
}

// errorKind names an error in a metric.
func errorKind(err error) string {
	switch {
	case errors.Is(err, diameter.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, diameter.ErrPeerUnavailable), errors.Is(err, diameter.ErrConnectionClosed),
		errors.Is(err, diameter.ErrNodeClosed), errors.Is(err, diameter.ErrApplicationNotNegotiated):
		return "transport"
	}
	return "other"
}

// Outcome is what a Cx result means to the CSCF that asked, independent of the
// command; the CSCF turns it into its SIP response (TS 24.229 §5.3, §5.4).
type Outcome int

// The outcomes. Success covers every 2xxx result, the Cx ones included
// (DIAMETER_FIRST_REGISTRATION and the other §6.2.1 codes); read the result
// itself where the difference matters.
const (
	Success Outcome = iota
	// UserUnknown: the identity is not provisioned (5001).
	UserUnknown
	// IdentitiesDontMatch: the IMPI and IMPU do not belong together (5002).
	IdentitiesDontMatch
	// NotRegistered: the public identity is not registered (5003).
	NotRegistered
	// RoamingNotAllowed: the visited network may not serve the user (5004).
	RoamingNotAllowed
	// ServedElsewhere: another S-CSCF serves the user (5005); the answer
	// names it.
	ServedElsewhere
	// SchemeNotSupported: the user has no credentials of the scheme asked
	// for (5006); Authenticate falls back on it.
	SchemeNotSupported
	// Rejected: the HSS refused the request (DIAMETER_AUTHORIZATION_REJECTED,
	// DIAMETER_AUTHENTICATION_REJECTED, or a Cx error not listed above).
	Rejected
	// Unavailable: the HSS could not answer now (protocol errors such as
	// TOO_BUSY, transient failures); the request may succeed later.
	Unavailable
	// Failure: anything else, such as DIAMETER_UNABLE_TO_COMPLY.
	Failure
)

var outcomeNames = [...]string{"Success", "UserUnknown", "IdentitiesDontMatch", "NotRegistered",
	"RoamingNotAllowed", "ServedElsewhere", "SchemeNotSupported", "Rejected", "Unavailable", "Failure"}

func (o Outcome) String() string {
	if int(o) < len(outcomeNames) {
		return outcomeNames[o]
	}
	return "Outcome(" + strconv.Itoa(int(o)) + ")"
}

// Classify maps a result to its Outcome (TS 29.229 §6.2, RFC 6733 §7.1).
func Classify(r cx.Result) Outcome {
	if r.IsSuccess() {
		return Success
	}
	if r.Vendor == cx.Vendor3GPP {
		switch r.Code {
		case cx.ErrorUserUnknown:
			return UserUnknown
		case cx.ErrorIdentitiesDontMatch:
			return IdentitiesDontMatch
		case cx.ErrorIdentityNotRegistered:
			return NotRegistered
		case cx.ErrorRoamingNotAllowed:
			return RoamingNotAllowed
		case cx.ErrorIdentityAlreadyRegistered:
			return ServedElsewhere
		case cx.ErrorAuthSchemeNotSupported:
			return SchemeNotSupported
		}
		return Rejected
	}
	switch {
	case r.Code == diameter.ResultAuthorizationRejected, r.Code == diameter.ResultAuthenticationRejected:
		return Rejected
	case diameter.IsProtocolError(r.Code), r.Code/1000 == 4:
		return Unavailable
	}
	return Failure
}

// ErrorOutcome is the Outcome of an error a call returned: Unavailable for a
// protocol error, a missing peer or a transport failure, which a CSCF answers
// like an HSS it cannot reach, and Failure otherwise.
func ErrorOutcome(err error) Outcome {
	var pe *ProtocolError
	switch {
	case errors.As(err, &pe):
		return Classify(pe.Result)
	case errors.Is(err, ErrNoPeer), errorKind(err) == "transport", errorKind(err) == "timeout":
		return Unavailable
	}
	return Failure
}
