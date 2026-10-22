package msrprelay

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	secretkey "github.com/jeonghun-app/rcs-platform/internal/secret"
)

// Defaults of the RELAY_ settings; docs/msrp-relay.md has the full table.
const (
	DefaultListenAddr  = ":2855"
	DefaultControlAddr = ":8082"
	// DefaultPublicPort is the NLB's MSRP TLS listener (ADR 0003), and
	// DefaultPlainPublicPort its TCP listener, the default with
	// RELAY_PUBLIC_TLS=false so that a plain msrp: URI never names the TLS
	// port.
	DefaultPublicPort      = 2856
	DefaultPlainPublicPort = 2855
	// DefaultCorePort is the MSRP port (RFC 4975 §15.4), the one rcs-as
	// listens on.
	DefaultCorePort = 2855
	// DefaultFailedLookupsPerSource is generous: clients behind one
	// carrier-grade NAT address share it, though a client naming only
	// sessions pcscf handed out almost never fails a lookup.
	DefaultFailedLookupsPerSource = 120
	DefaultTable                  = "msrp-bindings"
	// DefaultStoreTimeout bounds one DynamoDB call, retries included. A
	// client's first SEND waits for it, so it is short.
	DefaultStoreTimeout = 2 * time.Second
	// DefaultMaxExpiresIn is the longest expires_in pcscf may ask for. It is
	// above the usual SIP session timer (RFC 4028 §4, 1800 s), which pcscf
	// follows with PATCH on every refresh.
	DefaultMaxExpiresIn = 2 * time.Hour
	// DefaultMaxConnections bounds client connections per task, each of
	// which costs two goroutines and buffers.
	DefaultMaxConnections = 10000
	// DefaultMaxConnectionsPerSource is generous because mobile operators put
	// many subscribers behind one carrier-grade NAT address.
	DefaultMaxConnectionsPerSource = 256
	// DefaultMaxConcurrentBinds bounds binds in their store calls (lookup and
	// claim), so a burst of connections cannot turn into a burst of DynamoDB
	// calls and goroutines waiting on them.
	DefaultMaxConcurrentBinds = 64
	// DefaultPathWait covers the race in ADR 0004's second row: the client
	// connects as soon as it has sent its answer, while pcscf is still
	// recording the client's path from that answer.
	DefaultPathWait           = 2 * time.Second
	DefaultCoreConnectTimeout = 5 * time.Second
	// DefaultKeepAlive and DefaultIdleTimeout follow ADR 0003: an empty SEND
	// after 240 s of quiet, and a connection silent for 300 s is closed, both
	// inside the NLB TLS listener's fixed 350 s.
	DefaultKeepAlive   = msrp.DefaultKeepAliveInterval
	DefaultIdleTimeout = 300 * time.Second
	// DefaultDrainTimeout is shorter than runtime.DefaultShutdownTimeout, which
	// bounds the whole stop.
	DefaultDrainTimeout = 15 * time.Second
	// DefaultUserTimeout gives up on a client that has left data
	// unacknowledged for a minute: one gone without a FIN, with traffic
	// toward it that nobody answers (see setUserTimeout).
	DefaultUserTimeout     = time.Minute
	DefaultMetricsInterval = time.Minute
)

// The RELAY_STORE values.
const (
	StoreDynamoDB = "dynamodb"
	StoreMemory   = "memory"
)

// minTokenLength is the shortest token accepted in staging and prod: 32
// random bytes in base64 (43 characters) is the shortest encoding of the 256
// bits ADR 0007 §4 requires.
const minTokenLength = 43

// privateRanges are the networks ADR 0007 §5 calls private: RFC 1918 and
// IPv6 unique local addresses.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// Config is msrp-relay's configuration, read by Configure. Tokens print as
// "[redacted]".
type Config struct {
	// ListenAddr is the public MSRP listener, behind the NLB.
	ListenAddr string
	// ControlAddr is the control API listener, which only pcscf's security
	// group reaches (ADR 0007 §2).
	ControlAddr string
	// Public is the authority of every client_path: the NLB name or an
	// operator FQDN, the NLB listener port, and msrps when TLS ends at the
	// NLB.
	Public msrp.URI
	// CoreHost is the address in every core_path_local: this task's private
	// IP (ADR 0005).
	CoreHost netip.Addr
	// CoreNetworks are where the relay may connect: core_path hosts must be
	// in them, and so must every address a host name resolves to.
	CoreNetworks []netip.Prefix
	// CorePorts are the only ports the relay connects to (RELAY_CORE_PORTS),
	// checked like CoreNetworks.
	CorePorts []uint16
	// Namespace is RCS_SERVICE_NAMESPACE; names in it may appear in
	// core_path.
	Namespace string
	// ProxyProtocol is RCS_PROXY_PROTOCOL: every public connection must
	// start with a PROXY v2 header (ADR 0003).
	ProxyProtocol bool

	Store            string
	Table            string
	DynamoDBEndpoint string
	StoreTimeout     time.Duration

	// Tokens are pcscf's current and next control API tokens.
	Tokens []secretkey.Key

	MaxExpiresIn            time.Duration
	MaxConnections          int
	MaxConnectionsPerSource int
	MaxConcurrentBinds      int
	FailedLookupsPerSource  int
	MaxUnknownSessions      int
	PathWait                time.Duration
	CoreConnectTimeout      time.Duration
	KeepAlive               time.Duration
	IdleTimeout             time.Duration
	DrainTimeout            time.Duration
	MetricsInterval         time.Duration
	UserTimeout             time.Duration
}

// interfaceAddrs finds this task's addresses; tests replace it.
var interfaceAddrs = net.InterfaceAddrs

// Configure reads the RELAY_ settings (docs/msrp-relay.md) and refuses, in
// staging and prod, those that would expose the relay or break it across
// tasks.
func Configure(s *runtime.Settings) Config {
	e := s.Env
	c := Config{
		ListenAddr:              e.String("LISTEN_ADDR", DefaultListenAddr),
		ControlAddr:             e.String("CONTROL_ADDR", DefaultControlAddr),
		CoreNetworks:            e.CIDRs("CORE_NETWORKS", slices.Clone(privateRanges)),
		Namespace:               s.ServiceNamespace(),
		ProxyProtocol:           s.Shared.Bool("PROXY_PROTOCOL", false),
		Store:                   e.String("STORE", StoreDynamoDB),
		Table:                   e.String("DYNAMODB_TABLE", DefaultTable),
		DynamoDBEndpoint:        e.String("DYNAMODB_ENDPOINT", ""),
		StoreTimeout:            e.Duration("STORE_TIMEOUT", DefaultStoreTimeout),
		MaxExpiresIn:            e.Duration("MAX_EXPIRES_IN", DefaultMaxExpiresIn),
		MaxConnections:          e.Int("MAX_CONNECTIONS", DefaultMaxConnections),
		MaxConnectionsPerSource: e.Int("MAX_CONNECTIONS_PER_SOURCE", DefaultMaxConnectionsPerSource),
		MaxConcurrentBinds:      e.Int("MAX_CONCURRENT_BINDS", DefaultMaxConcurrentBinds),
		FailedLookupsPerSource:  e.Int("FAILED_LOOKUPS_PER_SOURCE", DefaultFailedLookupsPerSource),
		MaxUnknownSessions:      e.Int("MAX_UNKNOWN_SESSIONS", msrp.DefaultMaxFailedBinds),
		PathWait:                e.Duration("PATH_WAIT", DefaultPathWait),
		CoreConnectTimeout:      e.Duration("CORE_CONNECT_TIMEOUT", DefaultCoreConnectTimeout),
		KeepAlive:               e.Duration("KEEPALIVE_INTERVAL", DefaultKeepAlive),
		IdleTimeout:             e.Duration("IDLE_TIMEOUT", DefaultIdleTimeout),
		DrainTimeout:            e.Duration("DRAIN_TIMEOUT", DefaultDrainTimeout),
		MetricsInterval:         e.Duration("METRICS_INTERVAL", DefaultMetricsInterval),
		UserTimeout:             e.Duration("TCP_USER_TIMEOUT", DefaultUserTimeout),
	}
	for _, a := range []struct{ name, v string }{{"LISTEN_ADDR", c.ListenAddr}, {"CONTROL_ADDR", c.ControlAddr}} {
		if _, _, err := net.SplitHostPort(a.v); err != nil {
			e.Invalid(a.name, "not host:port")
		}
	}
	c.Public = publicURI(s)
	c.CorePorts = corePorts(e)
	c.CoreHost = coreHost(e)
	s.ForbidInProduction(!c.ProxyProtocol,
		"RCS_PROXY_PROTOCOL is false: every client would appear as the load balancer, so per-source limits could not work (ADR 0003)")
	for _, p := range c.CoreNetworks {
		s.ForbidInProduction(!privatePrefix(p),
			"RELAY_CORE_NETWORKS includes "+p.String()+", which is not an RFC 1918 or unique local network: a compromised pcscf could make the relay connect outside the VPC (ADR 0007 §5)")
	}

	switch c.Store {
	case StoreMemory:
		s.ForbidInProduction(true, "RELAY_STORE=memory keeps bindings in one task, so a client reaching another task is refused")
	case StoreDynamoDB:
	default:
		e.Invalid("STORE", "not one of dynamodb, memory")
	}

	c.Tokens = tokens(s)

	for _, d := range []struct {
		name string
		v    time.Duration
	}{
		{"STORE_TIMEOUT", c.StoreTimeout}, {"MAX_EXPIRES_IN", c.MaxExpiresIn}, {"PATH_WAIT", c.PathWait},
		{"CORE_CONNECT_TIMEOUT", c.CoreConnectTimeout}, {"KEEPALIVE_INTERVAL", c.KeepAlive},
		{"IDLE_TIMEOUT", c.IdleTimeout}, {"DRAIN_TIMEOUT", c.DrainTimeout}, {"METRICS_INTERVAL", c.MetricsInterval},
		{"TCP_USER_TIMEOUT", c.UserTimeout},
	} {
		if d.v == 0 {
			e.Invalid(d.name, "must be greater than zero")
		}
	}
	if c.MaxExpiresIn%time.Second != 0 {
		e.Invalid("MAX_EXPIRES_IN", "must be whole seconds, like expires_in")
	}
	// ADR 0003: an endpoint keeping to the keep-alive interval is never cut
	// by the idle timeout.
	if c.KeepAlive >= c.IdleTimeout {
		e.Invalid("KEEPALIVE_INTERVAL", "must be shorter than RELAY_IDLE_TIMEOUT")
	}
	// Run must return inside the runtime's stop deadline, or the stop counts
	// as failed and the last metrics are lost. After the drain it waits up
	// to controlShutdownTimeout for control calls, then closes and flushes,
	// which stopMargin covers. The runtime itself reports a malformed value.
	stop, problem := runtime.DefaultShutdownTimeout, " ("+runtime.DefaultShutdownTimeout.String()+" by default)"
	if v := s.Shared.String("SHUTDOWN_TIMEOUT", ""); v != "" {
		stop, problem = 0, ""
		if d, err := time.ParseDuration(v); err == nil {
			stop = d
		}
	}
	if after := controlShutdownTimeout + stopMargin; stop > 0 && c.DrainTimeout+after > stop {
		e.Invalid("DRAIN_TIMEOUT", "plus "+after.String()+" must not exceed RCS_SHUTDOWN_TIMEOUT"+problem+
			": the control API and the last metrics need that long after the drain")
	}
	for _, n := range []struct {
		name string
		v    int
	}{
		{"MAX_CONNECTIONS", c.MaxConnections}, {"MAX_CONNECTIONS_PER_SOURCE", c.MaxConnectionsPerSource},
		{"MAX_CONCURRENT_BINDS", c.MaxConcurrentBinds}, {"MAX_UNKNOWN_SESSIONS", c.MaxUnknownSessions},
		{"FAILED_LOOKUPS_PER_SOURCE", c.FailedLookupsPerSource},
	} {
		if n.v <= 0 {
			e.Invalid(n.name, "must be positive")
		}
	}
	return c
}

// publicURI builds the authority of client_path from RELAY_PUBLIC_HOST,
// RELAY_PUBLIC_PORT and RELAY_PUBLIC_TLS.
func publicURI(s *runtime.Settings) msrp.URI {
	e := s.Env
	host := e.RequiredString("PUBLIC_HOST")
	secure := e.Bool("PUBLIC_TLS", true)
	port := DefaultPublicPort
	if !secure {
		port = DefaultPlainPublicPort
	}
	port = e.Int("PUBLIC_PORT", port)
	// Clients on the internet use TLS to the NLB; msrp:// would carry chat
	// in the clear (ADR 0003).
	s.ForbidInProduction(!secure, "RELAY_PUBLIC_TLS is false: clients would send chat content over the internet in the clear")
	if port < 1 || port > 65535 {
		e.Invalid("PUBLIC_PORT", "must be from 1 to 65535")
		return msrp.URI{}
	}
	if host == "" {
		return msrp.URI{}
	}
	// The host goes into URIs clients parse, so it must survive the MSRP URI
	// grammar (RFC 4975 §9) exactly.
	u := msrp.URI{Secure: secure, Host: host, Port: port, SessionID: "probe", Transport: "tcp"}
	if p, err := msrp.ParseURI(u.String()); err != nil || p.String() != u.String() {
		e.Invalid("PUBLIC_HOST", "not a host name or IP address usable in an MSRP URI")
		return msrp.URI{}
	}
	u.SessionID = ""
	return u
}

// stopMargin is the time Run needs after the control API has stopped.
const stopMargin = time.Second

// corePorts reads RELAY_CORE_PORTS. Security groups are the primary control
// on where the relay connects (ADR 0007 §2); this keeps a compromised pcscf
// from using the relay to probe other ports inside RELAY_CORE_NETWORKS even
// where a security group is too broad.
func corePorts(e *runtime.Env) []uint16 {
	items := e.List("CORE_PORTS", []string{strconv.Itoa(DefaultCorePort)})
	ports := make([]uint16, 0, len(items))
	for i, item := range items {
		n, err := strconv.ParseUint(item, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != item {
			e.Invalid("CORE_PORTS", "item "+strconv.Itoa(i+1)+" is not a port from 1 to 65535")
			return nil
		}
		ports = append(ports, uint16(n))
	}
	return ports
}

// coreHost reads RELAY_CORE_HOST, or finds this task's one private IPv4
// address: rcs-as and pcscf see the relay by it (ADR 0005).
func coreHost(e *runtime.Env) netip.Addr {
	return runtime.InstanceAddr(e, "CORE_HOST", interfaceAddrs)
}

// tokens reads pcscf's two tokens (ADR 0007 §4: current and next, so a token
// rotates without downtime).
func tokens(s *runtime.Settings) []secretkey.Key {
	e := s.Env
	current, next := e.String("PCSCF_TOKEN", ""), e.String("PCSCF_TOKEN_NEXT", "")
	switch {
	case current == "" && next != "":
		e.Invalid("PCSCF_TOKEN_NEXT", "set without RELAY_PCSCF_TOKEN")
		return nil
	case current != "" && current == next:
		e.Invalid("PCSCF_TOKEN_NEXT", "equal to RELAY_PCSCF_TOKEN")
		return nil
	}
	s.ForbidInProduction(current == "", "RELAY_PCSCF_TOKEN is unset: the control API would refuse every call")
	var out []secretkey.Key
	for _, t := range []struct{ name, v string }{{"PCSCF_TOKEN", current}, {"PCSCF_TOKEN_NEXT", next}} {
		if t.v == "" {
			continue
		}
		// A token the Authorization header cannot carry would never match.
		if _, ok := bearer([]string{"Bearer " + t.v}); !ok {
			e.Invalid(t.name, "not a bearer token: letters, digits and -._~+/ with optional trailing = (RFC 6750 §2.1), at most "+strconv.Itoa(maxTokenLength)+" characters")
			continue
		}
		s.ForbidInProduction(len(t.v) < minTokenLength, fmt.Sprintf(
			"RELAY_%s is shorter than %d characters (ADR 0007 §4: at least 256 random bits, e.g. 32 bytes in base64)", t.name, minTokenLength))
		out = append(out, secretkey.NewString(t.v))
	}
	return out
}

// privatePrefix reports whether every address in p is private (ADR 0007 §5).
func privatePrefix(p netip.Prefix) bool {
	for _, r := range privateRanges {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return true
		}
	}
	return false
}
