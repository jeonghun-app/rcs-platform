// Package sipua is the SIP side of a simulated RCS client. It keeps one TCP
// or TLS connection to the P-CSCF, as a device behind NAT does, and registers
// over it with SIP outbound (RFC 5626), so that terminating requests come
// back over the same connection.
//
// The SIP work is the platform's own: framing and the keep-alive are
// internal/sip/transport's, retransmission and matching
// internal/sip/transaction's, and the Digest and AKA computations are
// internal/sip/digest's and internal/milenage's. What is here is what a UA
// adds on top: the registration with its +sip.instance and reg-id (RFC 5626
// §4.2) and its challenges (RFC 3310, RFC 7616, TS 24.229 §5.1.1.2), the
// route set every later request is sent with (RFC 3608, TS 24.229
// §5.1.2A.1.1), the timing of the keep-alive pongs (RFC 5626 §4.4.1), and
// both sides of an INVITE dialog (RFC 3261 §12–15): as the caller, ACK,
// CANCEL and BYE; as the called party, 180 and 200 with the SDP answer,
// the 2xx sent again until its ACK, CANCEL answered 487; and refusing a
// re-INVITE either way.
//
// A failed flow is not recovered: the UA reports it and stops, and a
// scenario that wants to go on dials a new one.
//
// Nothing here logs, and errors carry methods, status codes and fixed
// reasons, never an identity, an address, a Call-ID, a nonce or a
// credential.
package sipua

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/safeerr"
)

// Defaults.
const (
	// DefaultExpires is the registration expiry a UE asks for (TS 24.229
	// §5.1.1.2.1); the registrar decides what it grants.
	DefaultExpires = 600000 * time.Second
	// DefaultFlowTimer is the keep-alive interval RFC 5626 §4.4.1 gives a
	// connection-oriented flow when the registrar sends no Flow-Timer.
	DefaultFlowTimer = 120 * time.Second
	// DefaultPongTimeout is how long RFC 5626 §4.4.1 lets a pong take
	// before the flow counts as failed.
	DefaultPongTimeout = 10 * time.Second
)

// Errors.
var (
	// ErrFlowFailed means the connection to the P-CSCF has closed, or a ping
	// went unanswered (RFC 5626 §4.4.1). The UA is then finished.
	ErrFlowFailed = errors.New("sipua: the flow to the P-CSCF has failed")
	// ErrClosed means Close has been called.
	ErrClosed = errors.New("sipua: closed")
	// ErrNotRegistered refuses a request before registration: a UE sends
	// none but REGISTER until it has a Service-Route (TS 24.229 §5.1.2A.1.1).
	ErrNotRegistered = errors.New("sipua: not registered")
	// ErrNoBinding means the registrar's 2xx lists no contact for this
	// instance and reg-id.
	ErrNoBinding = errors.New("sipua: the registrar lists no binding for this flow")
)

// StatusError is a final response that is not a success. Err, when set,
// says more: ErrNetworkNotAuthenticated, which the UA had reported in the
// request, or ErrNoUsableChallenge, for a 401 or 407 it could not answer.
type StatusError struct {
	Method string
	Code   int
	Err    error
}

func (e *StatusError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%v; %s answered %d", e.Err, e.Method, e.Code)
	}
	return fmt.Sprintf("sipua: %s answered %d", e.Method, e.Code)
}

func (e *StatusError) Unwrap() error { return e.Err }

// Config configures a UA.
type Config struct {
	// Network is transport.TCP or transport.TLS.
	Network transport.Network
	// Proxy is the P-CSCF's address.
	Proxy netip.AddrPort
	// ServerName is the name the P-CSCF's certificate is verified for, and
	// the host of the P-CSCF URI that is the first Route of every request.
	// Empty is the Proxy address; TLS then needs TLS.ServerName.
	ServerName string
	// TLS is the client TLS configuration; nil verifies against the system
	// roots.
	TLS *tls.Config

	// Domain is the home network domain, the Request-URI of REGISTER (TS
	// 24.229 §5.1.1.2.1).
	Domain string
	// Realm is the S-CSCF's Digest realm: the only one whose challenges
	// are answered, and the realm of the unchallenged Authorization. Empty
	// is Domain, which it is unless the HSS's realm (HSS_IMS_REALM) was
	// set apart.
	Realm string
	// IMPU is the public user identity registered, and the From of every
	// request. It is a SIP URI: the From and To of REGISTER must be one (TS
	// 24.229 §5.1.1.2.1), and a tel URI comes only in the implicit set.
	IMPU sip.URI
	// InstanceID is the +sip.instance URN, such as "urn:uuid:...", without
	// angle brackets (RFC 5626 §4.1).
	InstanceID string
	// RegID is the reg-id of the flow; zero is 1 (RFC 5626 §4.2).
	RegID uint32
	// Expires is the registration expiry asked for; zero is DefaultExpires.
	Expires time.Duration
	// Credentials answer the registrar's challenge. The zero value answers
	// none, and the 401 is the result.
	Credentials Credentials

	// KeepAlive is the interval between pings, used as it is. Zero draws
	// each interval anew between 80% and 100% of the registrar's
	// Flow-Timer, or of DefaultFlowTimer without one (RFC 5626 §4.4.1).
	// Either way the UA pings only while the registrar's 2xx carries
	// Require: outbound (§4.2.1).
	KeepAlive time.Duration
	// PongTimeout is how long a ping waits for its pong; zero is
	// DefaultPongTimeout.
	PongTimeout time.Duration

	// OnInvite receives each INVITE the network sends outside a dialog, a
	// chat for this UA as the called party, to Ring, Accept or Reject. It
	// runs on the connection's reading goroutine, so it must not block;
	// the answers may come from any goroutine. Nil leaves INVITEs to
	// OnRequest.
	OnInvite func(*IncomingCall)

	// OnRequest receives each request the network sends over the flow, a
	// MESSAGE or a NOTIFY say, and answers it with tx.Respond. It runs on
	// the connection's reading goroutine, so it must not block (see
	// transaction.TU). Nil answers every request 501.
	OnRequest func(tx *transaction.ServerTransaction)

	// Rand supplies tags, Call-IDs, branches and the keep-alive jitter, from
	// more than one goroutine; crypto/rand when nil.
	Rand io.Reader
	// Clock runs the keep-alive and transaction timers; nil is the system
	// clock.
	Clock transaction.Clock
}

// Registration is what a 2xx to REGISTER said.
type Registration struct {
	// Response is the 2xx itself, for the checks a scenario makes on it.
	Response *sip.Response
	// Expires is what the registrar granted this flow's contact; zero after
	// Unregister.
	Expires time.Duration
	// ServiceRoute is the route set later requests are sent with, after the
	// P-CSCF (RFC 3608).
	ServiceRoute []sip.Address
	// AssociatedURIs is P-Associated-URI, the implicit registration set (RFC
	// 7315 §4.1).
	AssociatedURIs []sip.Address
	// FlowTimer is the registrar's Flow-Timer, zero without one (RFC 5626
	// §4.4.1).
	FlowTimer time.Duration
	// Outbound reports "outbound" in Require: the registrar used the reg-id
	// (RFC 5626 §6).
	Outbound bool
	// Challenges counts the 401 and 407 answers before this one, and
	// Resynchronised reports that the card answered one with AUTS (RFC 3310
	// §3.4).
	Challenges     int
	Resynchronised bool
}

// UA is a registered or registering client on one flow. Its methods are safe
// for concurrent use. Register and Unregister run one at a time, so a
// REGISTER is never sent before the previous one has its final response
// (RFC 3261 §10.2).
type UA struct {
	cfg     Config
	tr      *transport.Transport
	layer   *transaction.Layer
	ids     sip.IDGenerator
	dialer  *oneConn
	local   netip.AddrPort
	contact sip.Contact
	// proxy is the P-CSCF URI with lr, the first Route of every request.
	proxy sip.Address
	dst   transport.Destination

	pings, pongs atomic.Int64

	// regMu is held for the whole of Register and Unregister, the wait for
	// the response included; mu only for the state.
	regMu sync.Mutex

	mu sync.Mutex
	// flow is the connection's FlowID, known from the first message that
	// arrives over it.
	flow transport.FlowID
	// regCallID, regTag and regCSeq keep every REGISTER of this UA in one
	// Call-ID with a rising CSeq (RFC 3261 §10.2.4).
	regCallID, regTag string
	regCSeq           uint32
	serviceRoute      []sip.Address
	registered        bool
	// keepAliveBase is what each interval is drawn from when
	// Config.KeepAlive is zero: the Flow-Timer, or DefaultFlowTimer.
	keepAliveBase time.Duration
	keepAlive     transaction.Timer
	pongDue       transaction.Timer
	// keepAliveGen and pongGen name the one live timer of each kind. A
	// timer that fires as it is being replaced or stopped finds the
	// generation moved on and does nothing, so a refresh never leaves a
	// second chain of pings running.
	keepAliveGen, pongGen uint64
	err                   error
	done                  chan struct{}
	closeOnce             sync.Once
	// dialogs are the INVITE dialogs in progress, by dialogKey, and calls
	// the incoming INVITEs not yet answered, by their transaction.
	dialogs map[string]*Dialog
	calls   map[*transaction.ServerTransaction]*IncomingCall
	// invites are the INVITEs sent in the last 64*T1, by Call-ID and From
	// tag, for 2xx that arrive after their transaction.
	invites map[string]*invite
}

// Dial opens the connection to the P-CSCF and returns a UA that has not yet
// registered. The connection is the only one the UA ever uses: should it
// close, the UA fails rather than opening another, since a new connection is
// a new flow the registrar knows nothing of.
//
// ctx bounds the TCP connect. A TLS handshake happens with the first request,
// within the transport's dial timeout.
func Dial(ctx context.Context, cfg Config) (*UA, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.RegID == 0 {
		cfg.RegID = 1
	}
	if cfg.Expires <= 0 {
		cfg.Expires = DefaultExpires
	}
	if cfg.Realm == "" {
		cfg.Realm = cfg.Domain
	}
	if cfg.PongTimeout <= 0 {
		cfg.PongTimeout = DefaultPongTimeout
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Clock == nil {
		cfg.Clock = transaction.SystemClock
	}

	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", cfg.Proxy.String())
	if err != nil {
		return nil, fmt.Errorf("sipua: connecting: %w", safeerr.Reason(err))
	}
	ua := &UA{
		cfg:     cfg,
		ids:     sip.IDGenerator{Rand: cfg.Rand},
		dialer:  &oneConn{c: c},
		done:    make(chan struct{}),
		dialogs: map[string]*Dialog{},
		calls:   map[*transaction.ServerTransaction]*IncomingCall{},
		invites: map[string]*invite{},
		dst:     transport.Destination{Network: cfg.Network, Addr: cfg.Proxy, ServerName: cfg.ServerName},
	}
	if la, ok := c.LocalAddr().(*net.TCPAddr); ok {
		ap := la.AddrPort()
		ua.local = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	if err := ua.buildAddresses(); err != nil {
		c.Close()
		return nil, err
	}
	if ua.regCallID, err = ua.ids.CallID(""); err == nil {
		ua.regTag, err = ua.ids.Tag()
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	ua.tr, err = transport.New(transport.Config{
		TLSClient:            cfg.TLS,
		MaxDialedConnections: 1,
		Dialer:               ua.dialer,
		OnFlowClosed:         func(transport.FlowID, transport.FlowInfo) { ua.fail(ErrFlowFailed) },
		OnPong:               ua.pong,
	}, ua.receive)
	if err != nil {
		c.Close()
		return nil, err
	}
	ua.layer = transaction.New(ua.tr, tu{ua}, transaction.Config{Clock: cfg.Clock})
	return ua, nil
}

// Validate reports what Dial would refuse in c, without dialing.
func (c Config) Validate() error { return c.validate() }

func (c Config) validate() error {
	switch {
	case c.Network != transport.TCP && c.Network != transport.TLS:
		return errors.New("sipua: Network must be TCP or TLS")
	case !c.Proxy.IsValid():
		return errors.New("sipua: no P-CSCF address")
	case !isHost(c.Domain):
		return errors.New("sipua: the home domain is not a host")
	case !c.IMPU.IsSIP():
		return errors.New("sipua: the IMPU is not a SIP URI")
	case !strings.HasPrefix(c.InstanceID, "urn:"):
		return errors.New("sipua: the instance ID is not a URN")
	case c.RegID >= 1<<31:
		return errors.New("sipua: reg-id above 2^31-1")
	case c.ServerName != "" && !isHost(c.ServerName):
		return errors.New("sipua: the P-CSCF server name is not a host")
	case c.Network == transport.TLS && c.ServerName == "" && (c.TLS == nil || c.TLS.ServerName == ""):
		return errors.New("sipua: TLS needs a server name to verify")
	}
	return nil
}

// buildAddresses makes the Contact and the P-CSCF Route.
func (ua *UA) buildAddresses() error {
	if !ua.local.IsValid() {
		return errors.New("sipua: the connection has no local address")
	}
	tp := strings.ToLower(string(ua.cfg.Network))
	// The Contact names the connection's own address; with outbound the
	// network reaches the UA by the flow, not by this address (RFC 5626
	// §4.2), so it needs no user part either, and carries no identity.
	ua.contact.URI = sip.URI{Scheme: "sip", Host: hostOf(ua.local.Addr()), Port: int(ua.local.Port())}
	ua.contact.URI.Params.Set("transport", tp)
	ua.contact.Params.Set("+sip.instance", "<"+ua.cfg.InstanceID+">")
	ua.contact.Params.Set("reg-id", strconv.FormatUint(uint64(ua.cfg.RegID), 10))
	// The RCS services the client registers for (RCC.07, TS 24.229
	// §5.1.1.2.1): 1-to-1 chat, standalone messaging, file transfer over
	// HTTP.
	ua.contact.Params.Set("+g.3gpp.icsi-ref", strings.Join([]string{ICSIChat, ICSIStandalone, ICSIStandaloneLarge}, ","))
	ua.contact.Params.Set("+g.3gpp.iari-ref", IARIFileTransfer)

	// TS 24.229 §5.1.2A.1.1 puts the P-CSCF's IP address in this Route, and
	// its NOTE 15 has a UE resolve an FQDN from discovery first. Clients
	// reach pcscf through the NLB's host name, whose addresses are the
	// NLB's and change, so the Route keeps the name the client was given;
	// pcscf recognises its own Route by name or by address.
	host := ua.cfg.ServerName
	if host == "" {
		host = hostOf(ua.cfg.Proxy.Addr())
	}
	ua.proxy.URI = sip.URI{Scheme: "sip", Host: host, Port: int(ua.cfg.Proxy.Port())}
	ua.proxy.URI.Params.Set("transport", tp)
	ua.proxy.URI.Params.SetFlag("lr")
	if _, err := sip.ParseAddress(ua.contact.String()); err != nil {
		return fmt.Errorf("sipua: building the Contact: %w", err)
	}
	return nil
}

func isHost(s string) bool {
	u, err := sip.ParseURI("sip:" + s)
	return err == nil && u.Host == s && u.User == "" && u.Port == 0 && len(u.Params) == 0 && len(u.Headers) == 0
}

func hostOf(a netip.Addr) string {
	a = a.Unmap()
	if a.Is6() {
		return "[" + a.String() + "]"
	}
	return a.String()
}

// Done is closed when the UA has failed or been closed; Err then says which.
func (ua *UA) Done() <-chan struct{} { return ua.done }

// Err returns ErrFlowFailed or ErrClosed once Done is closed, and nil before.
func (ua *UA) Err() error {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	return ua.err
}

// KeepAlives returns how many pings the UA has sent and pongs it has read.
func (ua *UA) KeepAlives() (pings, pongs int64) { return ua.pings.Load(), ua.pongs.Load() }

// Close ends the UA and its connection, without unregistering.
func (ua *UA) Close() error {
	ua.fail(ErrClosed)
	ua.closeOnce.Do(func() {
		ua.layer.Close()
		ua.tr.Close()
		ua.dialer.close()
	})
	return nil
}

// fail finishes the UA with err, once.
func (ua *UA) fail(err error) {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	if ua.err != nil {
		return
	}
	ua.err = err
	ua.stopKeepAliveLocked()
	close(ua.done)
}

// Register sends REGISTER and returns the registration it got. A later call
// refreshes the registration, in the same Call-ID (RFC 3261 §10.2.4), and
// takes the Service-Route of the new response.
func (ua *UA) Register(ctx context.Context) (*Registration, error) {
	ua.regMu.Lock()
	defer ua.regMu.Unlock()
	reg, err := ua.register(ctx, ua.cfg.Expires)
	if err != nil {
		return nil, err
	}
	if reg.Expires == 0 {
		return nil, ErrNoBinding
	}
	ua.mu.Lock()
	defer ua.mu.Unlock()
	ua.serviceRoute = reg.ServiceRoute
	ua.registered = true
	ua.keepAliveBase = orDefault(reg.FlowTimer, DefaultFlowTimer)
	switch {
	case ua.err != nil:
	case reg.Outbound:
		// A refresh starts the interval again but leaves a pong that is
		// due alone: the flow must still answer it.
		ua.armKeepAliveLocked()
	default:
		// Keep-alives start only once outbound registration has succeeded,
		// which Require: outbound shows (RFC 5626 §4.2.1); a first hop
		// that did not use outbound need not answer them (§4.4).
		ua.stopKeepAliveLocked()
	}
	return reg, nil
}

// Unregister removes this flow's binding (Expires: 0) and stops the
// keep-alive. The connection stays open, for what the network still sends
// over it, a NOTIFY of the registration's end say.
func (ua *UA) Unregister(ctx context.Context) (*Registration, error) {
	ua.regMu.Lock()
	defer ua.regMu.Unlock()
	reg, err := ua.register(ctx, 0)
	if err != nil {
		return nil, err
	}
	ua.mu.Lock()
	ua.registered = false
	ua.serviceRoute = nil
	ua.stopKeepAliveLocked()
	ua.mu.Unlock()
	return reg, nil
}

// maxChallenges bounds the 401s and 407s one registration answers: the
// first, one after a resynchronisation (RFC 3310 §3.4), and one with a
// stale nonce (RFC 7616 §3.3).
const maxChallenges = 3

// register sends REGISTER and answers its challenges. Answered credentials
// that are refused again end it: a second 401 to the same challenge's
// answer is a wrong password or RES, not something to try again.
func (ua *UA) register(ctx context.Context, expires time.Duration) (*Registration, error) {
	domain := sip.URI{Scheme: "sip", Host: ua.cfg.Domain}
	uri := domain.String()
	creds := ua.cfg.Credentials
	// auth holds the credentials sent, by field. A 407 and a 401 are
	// answered side by side: what one hop's challenge asked for goes in
	// every later REGISTER of the Call-ID (RFC 3261 §22.3), and the
	// Authorization with the IMPI stays even while a proxy challenges
	// (TS 24.229 §5.1.1.2.2).
	auth := map[string]func() (string, error){}
	if creds.set() {
		auth["Authorization"] = fixed(ua.initialAuthorization(uri))
	}
	answered := map[int]bool{}
	challenges, resynced, lastResync, reportedFailure := 0, false, false, false
	for {
		res, err := ua.sendRegister(ctx, domain, expires, auth)
		if err != nil {
			return nil, err
		}
		if reportedFailure && res.StatusCode >= 200 {
			return nil, &StatusError{Method: "REGISTER", Code: res.StatusCode, Err: ErrNetworkNotAuthenticated}
		}
		if res.StatusCode == 401 || res.StatusCode == 407 {
			// Each kind of challenge is answered once. Another only after
			// AUTS, when the network challenges again with a fresh vector,
			// or when it says the nonce had gone stale; otherwise a
			// challenge to these credentials is final.
			answer := !answered[res.StatusCode] || lastResync || staleChallenge(res)
			if !creds.set() || !answer || challenges == maxChallenges {
				return nil, &StatusError{Method: "REGISTER", Code: res.StatusCode}
			}
			challenges++
			answered[res.StatusCode] = true
			a, err := ua.authorize(res, uri)
			if err != nil {
				return nil, err
			}
			auth[a.field] = a.next
			lastResync, reportedFailure = a.resync, a.failure
			resynced = resynced || a.resync
			continue
		}
		if res.StatusCode >= 300 {
			return nil, &StatusError{Method: "REGISTER", Code: res.StatusCode}
		}
		reg, err := ua.registration(res)
		if err != nil {
			return nil, err
		}
		reg.Challenges, reg.Resynchronised = challenges, resynced
		return reg, nil
	}
}

// staleChallenge reports a 401 or 407 whose challenge says only the nonce
// had expired (RFC 7616 §3.3): the credentials were right.
func staleChallenge(res *sip.Response) bool {
	for _, name := range []string{"WWW-Authenticate", "Proxy-Authenticate"} {
		for _, v := range res.Header.Values(name) {
			if ch, err := digest.ParseChallenge(v); err == nil && ch.Stale {
				return true
			}
		}
	}
	return false
}

// sendRegister sends one REGISTER, in the registration's Call-ID with the
// next CSeq, and returns its final response.
func (ua *UA) sendRegister(ctx context.Context, domain sip.URI, expires time.Duration, auth map[string]func() (string, error)) (*sip.Response, error) {
	ua.mu.Lock()
	ua.regCSeq++
	cseq := ua.regCSeq
	ua.mu.Unlock()

	req, err := ua.request("REGISTER", domain, ua.regCallID, ua.regTag, cseq, ua.cfg.IMPU)
	if err != nil {
		return nil, err
	}
	// Every REGISTER, refreshes included, goes to the P-CSCF alone: the
	// Service-Route is for the other requests (RFC 3608).
	add(req, &err, "Route", ua.proxy.String())
	add(req, &err, "Supported", "path, outbound")
	add(req, &err, "Contact", ua.contact.String())
	add(req, &err, "Expires", strconv.FormatInt(int64(expires/time.Second), 10))
	for _, field := range []string{"Authorization", "Proxy-Authorization"} {
		if next, ok := auth[field]; ok && err == nil {
			var v string
			if v, err = next(); err == nil {
				add(req, &err, field, v)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	return ua.Send(ctx, req)
}

// registration reads a 2xx to REGISTER. A field that does not parse fails
// the registration: a scenario must not go on with a route set it guessed.
func (ua *UA) registration(res *sip.Response) (*Registration, error) {
	reg := &Registration{Response: res}
	var err error
	if reg.ServiceRoute, err = res.Header.ServiceRoute(); err != nil {
		return nil, errors.New("sipua: Service-Route of the REGISTER response is malformed")
	}
	if reg.AssociatedURIs, err = res.Header.PAssociatedURI(); err != nil {
		return nil, errors.New("sipua: P-Associated-URI of the REGISTER response is malformed")
	}
	if v := res.Header.Get("Flow-Timer"); v != "" {
		n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 31)
		if err != nil || n == 0 {
			return nil, errors.New("sipua: Flow-Timer of the REGISTER response is malformed")
		}
		reg.FlowTimer = time.Duration(n) * time.Second
	}
	require, err := res.Header.Require()
	if err != nil {
		return nil, errors.New("sipua: Require of the REGISTER response is malformed")
	}
	reg.Outbound = slices.ContainsFunc(require, func(s string) bool { return strings.EqualFold(s, "outbound") })

	contacts, err := res.Header.Contact()
	if err != nil {
		return nil, errors.New("sipua: Contact of the REGISTER response is malformed")
	}
	for _, c := range contacts {
		if !ua.isOurs(c) {
			continue
		}
		secs, present, err := c.Expires()
		if !present {
			secs, err = res.Header.Expires()
		}
		if err != nil {
			return nil, errors.New("sipua: the expiry of the REGISTER response is malformed")
		}
		reg.Expires = time.Duration(secs) * time.Second
	}
	return reg, nil
}

// isOurs reports whether a contact in a REGISTER response is this flow's
// binding: the same instance and reg-id (RFC 5626 §6).
func (ua *UA) isOurs(c sip.Contact) bool {
	inst, ok := c.Instance()
	if !ok || inst != "<"+ua.cfg.InstanceID+">" {
		return false
	}
	id, present, err := c.RegID()
	return present && err == nil && id == ua.cfg.RegID
}

// NewRequest returns a request outside any dialog, from the IMPU to target,
// with the route set of TS 24.229 §5.1.2A.1.1: the P-CSCF, then the
// Service-Route, and the IMPU as P-Preferred-Identity (§5.1.2A.1.1, RFC
// 3325 §9.2), which the P-CSCF checks against the registered set before
// asserting it. The caller adds what the method needs and sends it with
// Send, or for INVITE uses NewInvite and Invite.
func (ua *UA) NewRequest(method string, target sip.URI) (*sip.Request, error) {
	ua.mu.Lock()
	registered, route := ua.registered, ua.serviceRoute
	ua.mu.Unlock()
	if !registered {
		return nil, ErrNotRegistered
	}
	callID, err := ua.ids.CallID("")
	if err != nil {
		return nil, err
	}
	tag, err := ua.ids.Tag()
	if err != nil {
		return nil, err
	}
	req, err := ua.request(method, target, callID, tag, 1, target)
	if err != nil {
		return nil, err
	}
	add(req, &err, "Route", ua.proxy.String())
	for _, r := range route {
		add(req, &err, "Route", r.String())
	}
	add(req, &err, "P-Preferred-Identity", sip.Address{URI: ua.cfg.IMPU}.String())
	if err != nil {
		return nil, err
	}
	return req, nil
}

// request builds the fields every request has (RFC 3261 §8.1.1).
func (ua *UA) request(method string, uri sip.URI, callID, tag string, cseq uint32, to sip.URI) (*sip.Request, error) {
	branch, err := ua.ids.Branch()
	if err != nil {
		return nil, err
	}
	req := &sip.Request{Method: method, URI: uri}
	from := sip.Address{URI: ua.cfg.IMPU}
	from.Params.Set("tag", tag)
	// The transport writes the sent-by it uses; the branch is ours.
	add(req, &err, "Via", "SIP/2.0/"+string(ua.cfg.Network)+" "+ua.local.String()+";branch="+branch)
	add(req, &err, "Max-Forwards", "70")
	add(req, &err, "From", from.String())
	add(req, &err, "To", sip.Address{URI: to}.String())
	add(req, &err, "Call-ID", callID)
	add(req, &err, "CSeq", strconv.FormatUint(uint64(cseq), 10)+" "+method)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// add appends a header field unless an earlier one failed. A field value
// never reaches the error: it may carry an identity.
func add(req *sip.Request, err *error, name, value string) {
	if *err != nil {
		return
	}
	if e := req.Header.Add(name, value); e != nil {
		*err = fmt.Errorf("sipua: the %s field: %w", name, errInvalidField)
	}
}

var errInvalidField = errors.New("invalid value")

// Send sends a request built by NewRequest, or by the UA itself, in a client
// transaction and returns its final response, whatever the status.
// Provisional responses are passed over. An INVITE goes through Invite,
// which keeps its dialog, and an ACK is never a transaction.
func (ua *UA) Send(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	if req.Method == "INVITE" || req.Method == "ACK" {
		return nil, errors.New("sipua: an INVITE is sent with Invite, an ACK by the dialog")
	}
	if err := ua.Err(); err != nil {
		return nil, err
	}
	dst := ua.destination()

	final := make(chan result, 1)
	tx, err := ua.layer.Request(req, dst, func(res *sip.Response, err error) {
		if err == nil && res.StatusCode < 200 {
			return
		}
		select {
		case final <- result{res, err}:
		default:
		}
	})
	if err != nil {
		return nil, ua.sendError(err)
	}
	select {
	case r := <-final:
		if r.err != nil {
			return nil, ua.sendError(r.err)
		}
		return r.res, nil
	case <-ctx.Done():
		tx.Terminate()
		return nil, ctx.Err()
	case <-ua.done:
		tx.Terminate()
		return nil, ua.Err()
	}
}

type result struct {
	res *sip.Response
	err error
}

// destination is where every request goes: the flow once it is known, the
// P-CSCF's address before (the one connection either way).
func (ua *UA) destination() transport.Destination {
	ua.mu.Lock()
	defer ua.mu.Unlock()
	if ua.flow != "" {
		return transport.Destination{Flow: ua.flow}
	}
	return ua.dst
}

// sendError reduces what the transport and transaction layers report. A
// failed TLS handshake may name the certificate's hosts, and the flow's end
// shows up as several errors that all mean the UA is finished.
func (ua *UA) sendError(err error) error {
	if errors.Is(err, ErrFlowFailed) || errors.Is(err, transport.ErrNoFlow) {
		ua.fail(ErrFlowFailed)
	}
	// Once the UA has finished, that is why the send failed.
	if e := ua.Err(); e != nil {
		return e
	}
	// The one connection can be gone without a flow ever having opened: a
	// failed TLS handshake closes it before the transport has a flow to
	// report closed. The UA is finished then too, and the reason, which
	// says why, is what the caller gets.
	if ua.dialer.taken() && ua.tr.Stats().OpenOutbound == 0 {
		ua.fail(ErrFlowFailed)
	}
	return safeerr.Reason(err)
}

// receive takes everything the transport reads. The UA opens one connection
// and listens on nothing, so every message comes over its flow.
func (ua *UA) receive(in transport.Inbound) {
	ua.mu.Lock()
	if ua.flow == "" {
		ua.flow = in.Source.Flow
	}
	ua.mu.Unlock()
	ua.layer.Receive(in)
}

// armKeepAliveLocked replaces the keep-alive timer with one for the next
// interval, drawn anew each time (RFC 5626 §4.4.1: "the random number will
// be different for each keep-alive ping").
func (ua *UA) armKeepAliveLocked() {
	d := ua.cfg.KeepAlive
	if d <= 0 {
		d = ua.jitter(ua.keepAliveBase)
	}
	// Stopping the timer this one replaces is not enough when it has
	// already fired: its ping may be waiting for the lock. The generation
	// turns that ping away.
	if ua.keepAlive != nil {
		ua.keepAlive.Stop()
	}
	ua.keepAliveGen++
	gen := ua.keepAliveGen
	ua.keepAlive = ua.cfg.Clock.AfterFunc(d, func() { ua.ping(gen) })
}

// ping sends a keep-alive and arms the timers for its pong and the next one.
// The pong timer is armed before the ping is written, so a pong that comes
// back at once finds it to stop.
func (ua *UA) ping(gen uint64) {
	ua.mu.Lock()
	if ua.err != nil || !ua.registered || gen != ua.keepAliveGen {
		ua.mu.Unlock()
		return
	}
	flow := ua.flow
	// A pong still outstanding keeps its deadline: a later ping must not
	// extend the life of a flow that has stopped answering.
	if ua.pongDue == nil {
		ua.pongGen++
		pg := ua.pongGen
		ua.pongDue = ua.cfg.Clock.AfterFunc(ua.cfg.PongTimeout, func() { ua.pongMissed(pg) })
	}
	ua.armKeepAliveLocked()
	ua.mu.Unlock()

	ua.pings.Add(1)
	if err := ua.tr.Ping(flow); err != nil {
		ua.fail(ErrFlowFailed)
	}
}

// pong is the transport's report of a CRLF read on the flow.
func (ua *UA) pong(transport.FlowID) {
	ua.pongs.Add(1)
	ua.mu.Lock()
	defer ua.mu.Unlock()
	if ua.pongDue != nil {
		ua.pongDue.Stop()
		ua.pongDue = nil
		ua.pongGen++
	}
}

// pongMissed fails the flow and closes it (RFC 5626 §4.4.1).
func (ua *UA) pongMissed(gen uint64) {
	ua.mu.Lock()
	if gen != ua.pongGen {
		// The pong came as the timer fired.
		ua.mu.Unlock()
		return
	}
	flow := ua.flow
	ua.pongDue = nil
	ua.mu.Unlock()
	ua.fail(ErrFlowFailed)
	ua.tr.CloseFlow(flow)
}

func (ua *UA) stopKeepAliveLocked() {
	for _, t := range []*transaction.Timer{&ua.keepAlive, &ua.pongDue} {
		if *t != nil {
			(*t).Stop()
			*t = nil
		}
	}
	ua.keepAliveGen++
	ua.pongGen++
}

// jitter returns a random duration between 80% and 100% of d (RFC 5626
// §4.4.1), so that clients started together do not ping together.
func (ua *UA) jitter(d time.Duration) time.Duration {
	var b [2]byte
	if _, err := io.ReadFull(ua.cfg.Rand, b[:]); err != nil {
		return d
	}
	frac := float64(binary.BigEndian.Uint16(b[:])) / 65535
	return d - time.Duration(frac*0.2*float64(d))
}

func orDefault(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

// tu is the UA as the transaction layer's TU, kept apart so that its methods
// are not the UA's.
type tu struct{ ua *UA }

func (t tu) Request(tx *transaction.ServerTransaction) {
	req := tx.Request()
	if d := t.ua.dialogOf(req); d != nil {
		d.receive(tx)
		return
	}
	if unsupported := unsupportedExtensions(req); len(unsupported) > 0 {
		// RFC 3261 §8.2.2.3: this UA supports no extension a request may
		// require, 100rel and precondition among them.
		if res, err := sip.NewResponse(req, 420, "", "rcs-sim"); err == nil {
			if res.Header.Add("Unsupported", strings.Join(unsupported, ", ")) == nil {
				_ = tx.Respond(res)
			}
		}
		return
	}
	if req.Method == "CANCEL" && t.ua.cfg.OnInvite != nil {
		t.ua.cancel(tx)
		return
	}
	if to, err := req.Header.To(); req.Method == "INVITE" && err == nil && to.Tag() == "" && t.ua.cfg.OnInvite != nil {
		t.ua.incoming(tx)
		return
	}
	if t.ua.cfg.OnRequest != nil {
		t.ua.cfg.OnRequest(tx)
		return
	}
	// A request with a To tag belongs to a dialog; one this UA does not
	// know, or no longer, is 481 (RFC 3261 §12.2.2). Anything else it
	// does not handle is 501.
	code := 501
	if to, err := tx.Request().Header.To(); err == nil && to.Tag() != "" {
		code = 481
	}
	if tag, err := t.ua.ids.Tag(); err == nil {
		if res, err := sip.NewResponse(tx.Request(), code, "", tag); err == nil {
			tx.Respond(res)
		}
	}
}

// Stray takes what matches no transaction. A 2xx to an INVITE whose
// transaction has ended is a retransmission whose ACK was lost, and is
// ACKed again (RFC 3261 §13.2.2.4). An ACK confirms the dialog of the 2xx
// it acknowledges. Anything else is dropped.
func (t tu) Stray(in transport.Inbound) {
	switch m := in.Message.(type) {
	case *sip.Response:
		t.ua.strayResponse(m)
	case *sip.Request:
		// The ACK of a 2xx this UA sent (§13.3.1.4).
		if d := t.ua.dialogOf(m); m.Method == "ACK" && d != nil {
			d.confirm()
		}
	}
}

// ServerFailed forgets an incoming INVITE whose transaction failed: it can
// no longer be answered.
func (t tu) ServerFailed(tx *transaction.ServerTransaction, _ error) { t.ua.forgetCall(tx) }

// unsupportedExtensions returns the option tags req requires, none of
// which this UA supports. ACK and CANCEL cannot be refused (§8.2.2.3).
func unsupportedExtensions(req *sip.Request) []string {
	if req.Method == "ACK" || req.Method == "CANCEL" {
		return nil
	}
	tags, err := req.Header.Require()
	if err != nil {
		return nil
	}
	return tags
}

// oneConn is the transport's Dialer. It hands over the connection Dial
// opened, once, and refuses every later dial, so a closed flow is never
// silently replaced by a new one.
type oneConn struct {
	mu sync.Mutex
	c  net.Conn
}

func (d *oneConn) DialContext(context.Context, string, string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	c := d.c
	d.c = nil
	if c == nil {
		return nil, ErrFlowFailed
	}
	return c, nil
}

// taken reports whether the transport has taken the connection.
func (d *oneConn) taken() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.c == nil
}

// close closes the connection if the transport never took it.
func (d *oneConn) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c != nil {
		d.c.Close()
		d.c = nil
	}
}
