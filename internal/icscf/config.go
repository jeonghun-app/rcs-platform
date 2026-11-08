package icscf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

const (
	// DefaultRetryAfter is the Retry-After of the 480 sent when the HSS
	// cannot be asked (TS 24.229 §5.3.1.3): long enough for a restarted HSS
	// task to come back, short enough that a client retries within a
	// registration refresh.
	DefaultRetryAfter = 10 * time.Second
	// MaxRetryAfter bounds RetryAfter, as transaction.MaxRetryAfter does for
	// the 503 of a full transaction layer.
	MaxRetryAfter = time.Hour
	// DefaultRegisterTimeout bounds a REGISTER's wait for the S-CSCF: half of
	// the client's 64*T1 at the default T1 of 500 ms, which leaves the other
	// half for the UAR before it and for the 504 to travel back (TS 24.229
	// §5.3.1.3, RFC 3261 §17.1.2.2). It is above what the S-CSCF needs for
	// one Cx request and its retry on another HSS task.
	DefaultRegisterTimeout = 16 * time.Second
	// MaxRegisterTimeout is the client's 64*T1 at the default T1: a REGISTER
	// waiting longer gets its 504 after the client has given up.
	MaxRegisterTimeout = 32 * time.Second
	// MaxSCSCFs bounds the configured S-CSCF list, which every selection by
	// capability walks.
	MaxSCSCFs = 64
	// MaxASRoutes bounds ICSCF_AS_ROUTES, which every chatbot request walks.
	MaxASRoutes = 64
)

// HSS is the part of *cxclient.Client the I-CSCF uses (TS 29.228 §6.1.1,
// §6.1.4).
type HSS interface {
	UAR(ctx context.Context, r *cx.UAR) (*cx.UAA, error)
	LIR(ctx context.Context, r *cx.LIR) (*cx.LIA, error)
}

// AllResolver finds every destination of a URI in the order to try them;
// *proxy.DNSResolver implements it.
type AllResolver interface {
	ResolveAll(ctx context.Context, u sip.URI) ([]transport.Destination, error)
}

// Metrics receives the counters listed in the package documentation;
// *runtime.Metrics implements it.
type Metrics interface {
	Count(name string, n int64)
}

// SCSCF is an S-CSCF the I-CSCF may choose when the HSS answers with
// capabilities instead of a name (TS 24.229 §5.3.1.2, TS 29.228 §6.7). The
// meaning of a capability number is the operator's.
type SCSCF struct {
	URI       sip.URI
	Mandatory []uint32
	Optional  []uint32
}

// ParseSCSCFs reads the ICSCF_SCSCF setting: a JSON array of objects with a
// "uri" and optional "mandatory" and "optional" arrays of capability numbers,
// such as
//
//	[{"uri":"sip:scscf.rcs.local:5060;transport=tcp","mandatory":[1],"optional":[2,3]}]
//
// The list must name one to MaxSCSCFs S-CSCFs, each a SIP or SIPS URI with a
// host and no user part, none twice. A capability an entry lists as both
// mandatory and optional counts once.
func ParseSCSCFs(data []byte) ([]SCSCF, error) {
	var entries []struct {
		URI       *string  `json:"uri"`
		Mandatory []uint32 `json:"mandatory"`
		Optional  []uint32 `json:"optional"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("icscf: S-CSCF list: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("icscf: S-CSCF list: trailing data after the array")
	}
	if len(entries) == 0 || len(entries) > MaxSCSCFs {
		return nil, fmt.Errorf("icscf: S-CSCF list has %d entries, want 1..%d", len(entries), MaxSCSCFs)
	}
	out := make([]SCSCF, 0, len(entries))
	for i, e := range entries {
		if e.URI == nil {
			return nil, fmt.Errorf("icscf: S-CSCF %d has no uri", i)
		}
		u, err := sip.ParseURI(*e.URI)
		if err != nil {
			return nil, fmt.Errorf("icscf: S-CSCF %d: %w", i, err)
		}
		s := SCSCF{URI: u, Mandatory: e.Mandatory, Optional: e.Optional}
		if err := s.validate(); err != nil {
			return nil, fmt.Errorf("icscf: S-CSCF %d: %w", i, err)
		}
		out = append(out, s)
	}
	if err := checkDistinct(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (s SCSCF) validate() error {
	if !serverURI(s.URI) {
		return errors.New("uri must be a SIP or SIPS URI with a host and no user part or headers")
	}
	return nil
}

func checkDistinct(list []SCSCF) error {
	for i := range list {
		for j := range i {
			if list[i].URI.Equal(list[j].URI) {
				return fmt.Errorf("icscf: S-CSCF %d repeats S-CSCF %d", i, j)
			}
		}
	}
	return nil
}

// ASRoute is an application server icscf may route a chatbot URI to
// (ICSCF_AS_ROUTES, ADR 0009 §3, memo H6): Name is the Server-Name the HSS
// gives for it in an LIA, URI where icscf sends the request. The name is
// only compared, never resolved, so an HSS answer cannot send a request
// anywhere the operator did not list.
type ASRoute struct {
	Name sip.URI
	URI  sip.URI
}

// ParseASRoutes reads the ICSCF_AS_ROUTES setting: a JSON array of objects
// with a "name" and a "uri", such as
//
//	[{"name":"sip:rcs-as.rcs.local;transport=tcp","uri":"sip:rcs-as.rcs.local:5060;transport=tcp"}]
//
// The keys are exact: a key in another case, or twice in an entry, is
// refused, as are unknown keys and data after the array. An empty value,
// or an empty array, is no route. The list holds at most
// MaxASRoutes entries; each name and URI is a SIP or SIPS URI with a host
// and no user part or headers, the URI without maddr, and no name twice.
func ParseASRoutes(data []byte) ([]ASRoute, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var entries []struct {
		Name *string `json:"name"`
		URI  *string `json:"uri"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("icscf: AS routes: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("icscf: AS routes: trailing data after the array")
	}
	if entries == nil {
		return nil, errors.New("icscf: AS routes: not an array")
	}
	if err := exactKeys(data); err != nil {
		return nil, err
	}
	out := make([]ASRoute, 0, len(entries))
	for i, e := range entries {
		if e.Name == nil || e.URI == nil {
			return nil, fmt.Errorf("icscf: AS route %d needs a name and a uri", i)
		}
		name, err := sip.ParseURI(*e.Name)
		if err != nil {
			return nil, fmt.Errorf("icscf: AS route %d: name: %w", i, err)
		}
		u, err := sip.ParseURI(*e.URI)
		if err != nil {
			return nil, fmt.Errorf("icscf: AS route %d: uri: %w", i, err)
		}
		out = append(out, ASRoute{Name: name, URI: u})
	}
	if err := checkASRoutes(out); err != nil {
		return nil, err
	}
	return out, nil
}

// exactKeys refuses what encoding/json takes quietly in data, which decodes
// as ParseASRoutes's list: a key twice in an entry, of which it keeps the
// last, and a key written in another case, which it matches anyway. Either
// lets a value other than the one an operator reads win (review of #690).
// Every value is a string or null, so keys and values alternate in each
// object.
func exactKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var seen map[string]bool
	key := false
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil // the end: Decode has checked the rest
		}
		switch tok {
		case json.Delim('{'):
			seen, key = map[string]bool{}, true
			continue
		case json.Delim('}'):
			seen = nil
			continue
		}
		if seen == nil {
			continue
		}
		if key {
			k, _ := tok.(string)
			switch {
			case k != "name" && k != "uri":
				return errors.New(`icscf: AS routes: a key other than "name" and "uri", in lower case`)
			case seen[k]:
				return errors.New("icscf: AS routes: a key twice in one entry")
			}
			seen[k] = true
		}
		key = !key
	}
}

// checkASRoutes refuses a list ParseASRoutes would not give.
func checkASRoutes(list []ASRoute) error {
	if len(list) > MaxASRoutes {
		return fmt.Errorf("icscf: %d AS routes, want at most %d", len(list), MaxASRoutes)
	}
	for i, a := range list {
		if !serverURI(a.Name) || !serverURI(a.URI) {
			return fmt.Errorf("icscf: AS route %d: name and uri must be SIP or SIPS URIs with a host and no user part or headers", i)
		}
		// RFC 3263 §4 would send the request to the maddr instead of the
		// host the operator listed.
		if _, ok := a.URI.Param("maddr"); ok {
			return fmt.Errorf("icscf: AS route %d: uri has a maddr", i)
		}
		for j := range i {
			if a.Name.Equal(list[j].Name) {
				return fmt.Errorf("icscf: AS route %d repeats the name of AS route %d", i, j)
			}
		}
	}
	return nil
}

// serverURI reports whether u names a server: a SIP or SIPS URI with a host
// and no user part or headers.
func serverURI(u sip.URI) bool {
	return u.IsSIP() && u.Host != "" && u.User == "" && len(u.Headers) == 0
}

// Config configures a Router.
type Config struct {
	// HSS answers UAR and LIR: a *cxclient.Client.
	HSS HSS
	// SCSCFs are the S-CSCFs to choose from by capability, in order of
	// preference among equals (ParseSCSCFs).
	SCSCFs []SCSCF
	// HomeDomain is the home network's domain name, sent as the
	// Visited-Network-Identifier of a REGISTER that carries no
	// P-Visited-Network-ID, as one from a P-CSCF in the home network may
	// not (TS 24.229 §5.2.2, TS 29.228 §6.1.1).
	HomeDomain string
	// RetryAfter is sent with the 480 that answers a request when the HSS
	// cannot be asked; DefaultRetryAfter when 0, else 1s..MaxRetryAfter in
	// whole seconds.
	RetryAfter time.Duration
	// RegisterTimeout bounds a REGISTER's wait for the S-CSCF, after which
	// it is answered 504 (TS 24.229 §5.3.1.3); DefaultRegisterTimeout when
	// 0, else at most MaxRegisterTimeout.
	RegisterTimeout time.Duration
	// Resolver, if set, finds every address of the S-CSCF: a request goes
	// to the first, and to the next when it cannot be sent to one (a task
	// gone, its connection refused). proxy.DNSResolver has it; without one
	// the proxy's own Resolver picks a single next hop.
	Resolver AllResolver
	// IDs makes the To tags of the I-CSCF's own responses that carry a
	// header field (the 480 with Retry-After); its zero value uses
	// crypto/rand.
	IDs sip.IDGenerator
	// Metrics, if set, receives the counters.
	Metrics Metrics
	// Logger, if set, receives warnings about answers the HSS should not
	// have sent. Nothing logged names a user.
	Logger *slog.Logger
	// Self are the URIs that name this I-CSCF, the proxy's Self: a request
	// whose Route names it again is refused as a loop.
	Self []sip.URI
	// Now, if set, is the clock behind the 30 s an address that failed
	// stays at the back of the list, and behind the rate of a warning;
	// nil is time.Now.
	Now func() time.Time
	// ChatbotDomain is RCS_CHATBOT_DOMAIN. A terminating request whose
	// Request-URI is at it is for a chatbot: normalised before the LIR and
	// sent to the AS the answer names, if that is on ASRoutes (ADR 0009
	// §2, §3). The zero Domain leaves every request as it was.
	ChatbotDomain chatbot.Domain
	// ASRoutes are the application servers a chatbot request may go to
	// (ParseASRoutes).
	ASRoutes []ASRoute
}

func (c *Config) setDefaults() {
	if c.RetryAfter == 0 {
		c.RetryAfter = DefaultRetryAfter
	}
	if c.RegisterTimeout == 0 {
		c.RegisterTimeout = DefaultRegisterTimeout
	}
	if c.Metrics == nil {
		c.Metrics = discardMetrics{}
	}
	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

func (c *Config) validate() error {
	switch {
	case c.HSS == nil:
		return errors.New("icscf: Config.HSS is not set")
	case len(c.SCSCFs) == 0 || len(c.SCSCFs) > MaxSCSCFs:
		return fmt.Errorf("icscf: Config.SCSCFs has %d entries, want 1..%d", len(c.SCSCFs), MaxSCSCFs)
	case !identity.IsDomainName(c.HomeDomain):
		return errors.New("icscf: Config.HomeDomain is not a domain name")
	case c.RetryAfter < time.Second || c.RetryAfter > MaxRetryAfter || c.RetryAfter%time.Second != 0:
		return fmt.Errorf("icscf: Config.RetryAfter %v is not 0 (the default) or whole seconds in 1s..%v", c.RetryAfter, MaxRetryAfter)
	case c.RegisterTimeout < 0 || c.RegisterTimeout > MaxRegisterTimeout:
		return fmt.Errorf("icscf: Config.RegisterTimeout %v is not 0 (the default) or up to %v", c.RegisterTimeout, MaxRegisterTimeout)
	}
	for i, s := range c.SCSCFs {
		if err := s.validate(); err != nil {
			return fmt.Errorf("icscf: Config.SCSCFs[%d]: %w", i, err)
		}
	}
	if err := checkASRoutes(c.ASRoutes); err != nil {
		return err
	}
	return checkDistinct(c.SCSCFs)
}

type discardMetrics struct{}

func (discardMetrics) Count(string, int64) {}
