package bridge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/cpim"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// SIPConfig configures NewSIP.
type SIPConfig struct {
	// Proxy is pcscf's client listener, host:port, over plain TCP. A name
	// is resolved anew for each registration, and is the host of the
	// P-CSCF Route, as the name a device is given (sipua.Config).
	Proxy string
	// Domain is the home network domain.
	Domain string
	// Rand supplies tags, Call-IDs and branches; nil is crypto/rand.
	Rand io.Reader
	// Clock runs the SIP timers; nil is the system clock.
	Clock transaction.Clock
	// Resolve looks a host name up; nil is the system resolver.
	Resolve func(ctx context.Context, host string) (netip.Addr, error)
}

// NewSIP returns the SIP side of the bridge: each Line is a sipua UA, on a
// TCP flow of its own to pcscf, registered with SIP outbound (RFC 5626)
// and the subscriber's credentials, as rcs-sim's clients are.
func NewSIP(c SIPConfig) (SIP, error) {
	host, port, err := net.SplitHostPort(c.Proxy)
	if err != nil {
		return nil, errors.New("bridge: the P-CSCF address is not host:port")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 || host == "" {
		return nil, errors.New("bridge: the P-CSCF address has no valid port")
	}
	if c.Resolve == nil {
		c.Resolve = resolve
	}
	return &sipNetwork{cfg: c, host: host, port: uint16(p)}, nil
}

type sipNetwork struct {
	cfg  SIPConfig
	host string
	port uint16
}

// resolve returns host's first address. The error does not name it.
func resolve(ctx context.Context, host string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, errors.New("bridge: the P-CSCF's name does not resolve")
	}
	return addrs[0].Unmap(), nil
}

func (n *sipNetwork) Register(ctx context.Context, s Subscriber, receive func(Incoming) int) (Line, time.Duration, error) {
	addr, err := netip.ParseAddr(n.host)
	serverName := ""
	if err != nil {
		serverName = n.host
		if addr, err = n.cfg.Resolve(ctx, n.host); err != nil {
			return nil, 0, err
		}
	}
	l := &sipLine{ids: sip.IDGenerator{Rand: n.cfg.Rand}, receive: receive}
	ua, err := sipua.Dial(ctx, sipua.Config{
		Network:     transport.TCP,
		Proxy:       netip.AddrPortFrom(addr, n.port),
		ServerName:  serverName,
		Domain:      n.cfg.Domain,
		IMPU:        s.IMPU,
		InstanceID:  s.InstanceID,
		Credentials: s.Credentials,
		OnRequest:   l.answer,
		Rand:        n.cfg.Rand,
		Clock:       n.cfg.Clock,
	})
	if err != nil {
		return nil, 0, err
	}
	l.mu.Lock()
	l.ua, l.contact = ua, ua.Contact()
	l.mu.Unlock()
	reg, err := ua.Register(ctx)
	if err != nil {
		ua.Close()
		return nil, 0, err
	}
	return l, reg.Expires, nil
}

// sipLine is one endpoint's UA.
type sipLine struct {
	ids     sip.IDGenerator
	receive func(Incoming) int

	mu      sync.Mutex
	ua      *sipua.UA
	contact sip.Contact
}

func (l *sipLine) agent() *sipua.UA {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ua
}

func (l *sipLine) Refresh(ctx context.Context) (time.Duration, error) {
	reg, err := l.agent().Register(ctx)
	if err != nil {
		return 0, err
	}
	return reg.Expires, nil
}

func (l *sipLine) Send(ctx context.Context, target sip.URI, body []byte) (int, error) {
	ua := l.agent()
	req, err := ua.NewMessage(target, cpim.ContentType, body)
	if err != nil {
		return 0, err
	}
	return finalStatus(ua.Send(ctx, req))
}

// finalStatus is a request's final status: its response's, or 408 for a
// transaction that timed out (RFC 3261 §8.1.3.1). Any other error is a
// failure without one.
func finalStatus(res *sip.Response, err error) (int, error) {
	switch {
	case errors.Is(err, transaction.ErrTimeout):
		return 408, nil
	case err != nil:
		return 0, err
	}
	return res.StatusCode, nil
}

func (l *sipLine) Unregister(ctx context.Context) error {
	ua := l.agent()
	defer ua.Close()
	_, err := ua.Unregister(ctx)
	return err
}

func (l *sipLine) Close()                { l.agent().Close() }
func (l *sipLine) Done() <-chan struct{} { return l.agent().Done() }

// answer answers what the network sends outside a dialog, on the reading
// goroutine: a MESSAGE as the bridge's receive says; an OPTIONS with 200
// and the UA's Contact, whose feature tags name what it takes (RCC.07
// capability discovery); one with a To tag, in a dialog the UA does not
// have, with 481 (RFC 3261 §12.2.2); any other with 405 and Allow
// (§8.2.1). An INVITE, a chat, is one of those: the bridge does pager mode
// only, and rcs-as delivers a standalone message in pager mode.
func (l *sipLine) answer(tx *transaction.ServerTransaction) {
	req := tx.Request()
	var extra [][2]string
	code := 405
	to, err := req.Header.To()
	switch {
	case err != nil:
		code = 400
	case to.Tag() != "":
		code = 481
	case req.Method == "MESSAGE":
		code = l.message(req)
		if code == 415 {
			extra = append(extra, [2]string{"Accept", cpim.ContentType})
		}
	case req.Method == "OPTIONS":
		code = 200
		l.mu.Lock()
		extra = append(extra, [2]string{"Contact", l.contact.String()})
		l.mu.Unlock()
	default:
		extra = append(extra, [2]string{"Allow", "MESSAGE, OPTIONS"})
	}
	tag, err := l.ids.Tag()
	if err != nil {
		return
	}
	res, err := sip.NewResponse(req, code, "", tag)
	if err != nil {
		return
	}
	for _, h := range extra {
		if res.Header.Add(h[0], h[1]) != nil {
			return
		}
	}
	_ = tx.Respond(res)
}

func (l *sipLine) message(req *sip.Request) int {
	from, err := req.Header.From()
	if err != nil {
		return 400
	}
	ct, err := req.Header.ContentType()
	if err != nil {
		return 415
	}
	return l.receive(Incoming{
		From:        from.URI,
		ContentType: strings.ToLower(ct.Type + "/" + ct.Subtype),
		Body:        slices.Clone([]byte(req.Body)),
		Line:        l,
	})
}
