package pcscf

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// Client transports: what the client's connection to the NLB is, which
// decides the listener pcscf opens for it and the default public port.
const (
	// ClientTLS terminates TLS in pcscf, with PCSCF_TLS_CERT_FILE.
	ClientTLS = "tls"
	// ClientNLBTLS is a plain TCP listener behind an NLB TLS listener that
	// terminates TLS: the client used TLS, pcscf sees TCP (ADR 0003).
	ClientNLBTLS = "nlb-tls"
	// ClientTCP is plain TCP end to end, for dev and test.
	ClientTCP = "tcp"
)

// Defaults of the settings in docs/pcscf.md.
const (
	DefaultCoreAddr = "0.0.0.0:5070"
	// DefaultCorePort is DefaultCoreAddr's port, RCS_PCSCF_CORE_PORT's
	// default: scscf reads the same setting to know where a dialog's
	// requests may go to a P-CSCF (#14).
	DefaultCorePort = 5070
	// DefaultMaxRegistrations bounds the registrations one task keeps.
	DefaultMaxRegistrations = 100_000
	// DefaultRegisterRate and DefaultRegisterBurst bound the REGISTERs of one
	// client address a second, generous for the same reason as the flows
	// (#16 question 1).
	DefaultRegisterRate  = 50
	DefaultRegisterBurst = 200
	// DefaultInitialRate and DefaultInitialBurst bound a client's requests
	// outside a dialog likewise.
	DefaultInitialRate  = 50
	DefaultInitialBurst = 200
	// DefaultSCSCFPort is scscf's SIP port.
	DefaultSCSCFPort = 5060
	// DefaultMaxRegisterRate and DefaultMaxRegisterBurst bound the
	// REGISTERs of all clients of a task together, since each costs the
	// core a UAR and an authentication vector (security review of #198).
	DefaultMaxRegisterRate  = 2000
	DefaultMaxRegisterBurst = 4000
	// DefaultMaxPendingRegistersPerIP bounds the identities one client
	// address may have REGISTERs under way for at once (registry).
	DefaultMaxPendingRegistersPerIP = 64
	// DefaultMaxClientFlows and DefaultCoreConnections split the transport's
	// DefaultMaxConnections: client flows may take no more than their share,
	// so the core listener always has room for scscf (review of #188).
	DefaultMaxConnections  = 10_000
	DefaultMaxClientFlows  = 9_000
	DefaultCoreConnections = 256
	// DefaultMaxFlowsPerIP is generous because mobile clients share public
	// addresses behind carrier-grade NAT (#16 plan, question 1).
	DefaultMaxFlowsPerIP = 1024
	// DefaultClientIdleTimeout closes a client connection that has said
	// nothing for 340 s, just under the NLB TLS listener's fixed 350 s, so the
	// client sees a clean close rather than a later reset (ADR 0003).
	DefaultClientIdleTimeout = 340 * time.Second
	// DefaultMaxBindingsPerFlow and DefaultMaxBindings bound the msrp-relay
	// bindings one client flow and one task hold (#136 decision 4): a chat
	// and a few file transfers at once fit a flow's share.
	DefaultMaxBindingsPerFlow = 16
	DefaultMaxBindings        = 20_000
	// DefaultBindingsPerMinute bounds the bindings one client flow creates
	// in a minute, whatever it holds (#248 security review): a chat or a
	// file transfer every two seconds is far past what a person does.
	DefaultBindingsPerMinute = 32
	// rcs-as's offers toward a client flow have a share of their own, so
	// that offers coming in cannot keep a client from making its own (#315
	// code review 2, security review). A flow holds the bindings of as many
	// sessions as rcs-as lets come in for one user (its
	// RCSAS_MAX_INCOMING_SESSIONS_PER_USER, 32), one MSRP line each.
	DefaultMaxCoreOfferBindingsPerFlow = 32
	DefaultCoreOfferBindingsPerMinute  = 32
	// DefaultRelayTimeout bounds one call to msrp-relay's control API.
	DefaultRelayTimeout = 2 * time.Second
	// minRelayTokenLength is the shortest relay token accepted in staging
	// and prod, the relay's own rule: 256 random bits in base64 (ADR 0007
	// §4).
	minRelayTokenLength = 43
	// minServerTransactionBytes is icscf's room for the largest request its
	// transport reads (2 MiB), over the 80% of the bound that client-facing
	// requests may use (transaction.DefaultClientShare).
	minServerTransactionBytes = 5 << 19
	// minQueuedBytes is room for the largest message the transport writes.
	minQueuedBytes = 2 << 20
	// The bounds staging and prod keep the write timeout in: a shorter one
	// closes a slow mobile client's flow, or a core connection, with every
	// transaction on it, behind a burst; a longer one holds a sender for a
	// peer that has stopped reading.
	minProductionWriteTimeout = time.Second
	maxProductionWriteTimeout = time.Minute
	// stopMargin is what Run needs after the drain to close the proxy and
	// the transport and flush the last metrics, inside RCS_SHUTDOWN_TIMEOUT.
	stopMargin = 5 * time.Second
	// answersWait, a part of stopMargin, bounds the wait after the drain
	// for the requests still in progress: the 430 for a request on one of
	// the last flows closed goes out after the close (#234), and closing
	// the proxy first would drop it. A request still waiting on the core
	// holds it to the end.
	answersWait = 2 * time.Second
)

// Config is pcscf's configuration (docs/pcscf.md).
type Config struct {
	// PublicHost is the name clients dial, the NLB's or an operator FQDN,
	// PublicAddrs the NLB's public addresses it resolves to, and PublicPort
	// their port: pcscf recognises itself in Route by them.
	PublicHost  string
	PublicAddrs []netip.Addr
	PublicPort  int
	// ClientTransport is one of ClientTLS, ClientNLBTLS and ClientTCP, and
	// ClientAddr the address its listener binds.
	ClientTransport string
	ClientAddr      string
	// TLSCertFile and TLSKeyFile are the certificate of ClientTLS.
	TLSCertFile, TLSKeyFile string
	// ClientUDPAddr, if set, opens a UDP client listener (dev and test only,
	// ADR 0003).
	ClientUDPAddr string
	// CoreAddr is the core listener, which only scscf reaches (ADR 0007), and
	// CoreHost this task's address on it, which Path and the core-facing
	// Record-Route name (ADR 0005).
	CoreAddr string
	CoreHost netip.Addr
	// ProxyProtocol requires the PROXY protocol v2 header on the client
	// stream listener (RCS_PROXY_PROTOCOL, ADR 0003).
	ProxyProtocol bool
	// MaxFlowsPerIP bounds the client flows of one client address.
	MaxFlowsPerIP int
	// MaxConnections bounds the connections the transport accepts, and
	// MaxClientFlows the client flows among them; CoreConnections of the
	// rest are kept for the core listener.
	MaxConnections, MaxClientFlows, CoreConnections int
	// ClientIdleTimeout closes a quiet client connection.
	ClientIdleTimeout time.Duration
	// ICSCF is the only Route of a REGISTER: icscf, by its Cloud Map name
	// by default (sip:icscf.<namespace>;transport=tcp;lr). It is reached
	// over TCP through the core listener, so its URI must say tcp.
	ICSCF sip.URI
	// Namespace is RCS_SERVICE_NAMESPACE, the only names a core hop is
	// looked up in (ADR 0007 §5).
	Namespace string
	// SCSCFHost and SCSCFPort are scscf's service name, in lower case, and
	// SIP port: the only next hop of a client's request inside a dialog,
	// since scscf records its service name in every dialog pcscf is in (ADR
	// 0005).
	SCSCFHost string
	SCSCFPort int
	// HomeDomain is RCS_IMS_DOMAIN, the operator's IMS domain: the type 1
	// orig-ioi of P-Charging-Vector, naming the network that sends a
	// request (TS 24.229 §5.2.2.1 3), §5.2.6.3.3 7)), and the visited
	// network by default.
	HomeDomain string
	// VisitedNetworkID is the P-Visited-Network-ID of REGISTERs (TS 24.229
	// §5.2.2.1, RFC 7315 §4.3), HomeDomain by default: icscf takes the
	// Visited-Network-Identifier of its UAR from it.
	VisitedNetworkID string
	// AllowLoopback lets a core hop resolve to a loopback address, for a
	// stack on one host; it is false in staging and prod, where only
	// private addresses are reached (ADR 0007 §5).
	AllowLoopback bool
	// MaxRegistrations bounds the registrations kept; RegisterRate and
	// RegisterBurst the REGISTERs of one client address.
	MaxRegistrations            int
	RegisterRate, RegisterBurst int
	// InitialRate and InitialBurst bound a client's requests outside a
	// dialog.
	InitialRate, InitialBurst int
	// MaxRegisterRate and MaxRegisterBurst bound the REGISTERs of all
	// clients together.
	MaxRegisterRate, MaxRegisterBurst int
	// MaxPendingRegistersPerIP bounds the identities one client address may
	// have REGISTERs under way for at once.
	MaxPendingRegistersPerIP int
	// RelayURL is msrp-relay's control API, a private host (ADR 0007 §5),
	// and RelayToken pcscf's bearer token for it, which prints as
	// "[redacted]" under every verb (#538). Without a token no MSRP session
	// is anchored, and every offer of one is refused (#136 decision 5).
	RelayURL     *url.URL
	RelayToken   secret.Key
	RelayTimeout time.Duration
	// MaxBindingsPerFlow and MaxBindings bound the relay bindings of one
	// flow and of the task, and BindingsPerMinute those one flow creates
	// in a minute, for the client's offers; the CoreOffer two bound,
	// apart, those of rcs-as's offers toward it.
	MaxBindingsPerFlow, MaxBindings, BindingsPerMinute      int
	MaxCoreOfferBindingsPerFlow, CoreOfferBindingsPerMinute int
	// DrainTimeout is how long a stop spreads the closing of client flows
	// over (ADR 0003): by default RCS_SHUTDOWN_TIMEOUT less what the rest of
	// the stop needs.
	DrainTimeout time.Duration
	// MaxServerTransactions and MaxServerTransactionBytes bound the server
	// transactions pcscf holds, by count and by memory, and its proxy as
	// icscf's is (proxyLimits): a request past either is answered 503 with
	// Retry-After (#482).
	MaxServerTransactions     int
	MaxServerTransactionBytes int64
	// MaxQueuedBytes bounds the transport's send queues together, and
	// WriteTimeout writing each 32 KiB of a message and a send's wait for
	// room in a full queue (transport.Config).
	MaxQueuedBytes int
	WriteTimeout   time.Duration
}

// limits checks the transaction caps and the send-queue budget (#482): each
// must leave room for the largest message, and in staging and prod none may
// be a tenth of its default or less, as a value meant for a test is, nor
// the write timeout outside a second to a minute.
func limits(s *runtime.Settings, c Config) {
	e := s.Env
	if c.MaxServerTransactions < 1 || c.MaxServerTransactions > transaction.MaxMaxServerTransactions {
		e.Invalid("MAX_SERVER_TRANSACTIONS", "must be from 1 to "+strconv.Itoa(transaction.MaxMaxServerTransactions))
	}
	if c.MaxServerTransactionBytes < minServerTransactionBytes {
		e.Invalid("MAX_SERVER_TRANSACTION_BYTES", "must be at least "+strconv.Itoa(minServerTransactionBytes)+" (2.5 MiB), room for the largest request a client sends")
	}
	if c.MaxQueuedBytes < minQueuedBytes {
		e.Invalid("MAX_QUEUED_BYTES", "must be at least "+strconv.Itoa(minQueuedBytes)+" (2 MiB), room for the largest message")
	}
	if c.WriteTimeout <= 0 {
		e.Invalid("WRITE_TIMEOUT", "must be greater than zero")
	}
	s.ForbidInProduction(c.MaxServerTransactions <= transaction.DefaultMaxServerTransactions/10,
		"PCSCF_MAX_SERVER_TRANSACTIONS is a tenth of its default or less, a value for a test")
	s.ForbidInProduction(c.MaxServerTransactionBytes <= transaction.DefaultMaxServerTransactionBytes/10,
		"PCSCF_MAX_SERVER_TRANSACTION_BYTES is a tenth of its default or less, a value for a test")
	s.ForbidInProduction(c.MaxQueuedBytes <= transport.DefaultMaxQueuedBytes/10,
		"PCSCF_MAX_QUEUED_BYTES is a tenth of its default or less, a value for a test")
	s.ForbidInProduction(c.WriteTimeout > 0 && (c.WriteTimeout < minProductionWriteTimeout || c.WriteTimeout > maxProductionWriteTimeout),
		"PCSCF_WRITE_TIMEOUT is outside 1s to 1m")
}

// interfaceAddrs finds this task's addresses; tests replace it.
var interfaceAddrs = net.InterfaceAddrs

// Configure reads the PCSCF_ settings (docs/pcscf.md) and refuses, in staging
// and prod, those that would let clients past the edge's rules.
func Configure(s *runtime.Settings) Config {
	e := s.Env
	c := Config{
		PublicHost:               strings.TrimSuffix(strings.ToLower(e.RequiredString("PUBLIC_HOST")), "."),
		ClientTransport:          e.String("CLIENT_TRANSPORT", ClientTLS),
		TLSCertFile:              e.String("TLS_CERT_FILE", ""),
		TLSKeyFile:               e.String("TLS_KEY_FILE", ""),
		ClientUDPAddr:            e.String("CLIENT_UDP_ADDR", ""),
		CoreAddr:                 e.String("CORE_ADDR", "0.0.0.0:"+strconv.Itoa(s.Shared.Int("PCSCF_CORE_PORT", DefaultCorePort))),
		ProxyProtocol:            s.Shared.Bool("PROXY_PROTOCOL", false),
		MaxFlowsPerIP:            e.Int("MAX_FLOWS_PER_IP", DefaultMaxFlowsPerIP),
		MaxConnections:           e.Int("MAX_CONNECTIONS", DefaultMaxConnections),
		MaxClientFlows:           e.Int("MAX_CLIENT_FLOWS", DefaultMaxClientFlows),
		CoreConnections:          e.Int("CORE_CONNECTIONS", DefaultCoreConnections),
		ClientIdleTimeout:        e.Duration("CLIENT_IDLE_TIMEOUT", DefaultClientIdleTimeout),
		AllowLoopback:            !s.Environment.Production(),
		MaxRegistrations:         e.Int("MAX_REGISTRATIONS", DefaultMaxRegistrations),
		RegisterRate:             e.Int("REGISTER_RATE", DefaultRegisterRate),
		RegisterBurst:            e.Int("REGISTER_BURST", DefaultRegisterBurst),
		InitialRate:              e.Int("INITIAL_RATE", DefaultInitialRate),
		InitialBurst:             e.Int("INITIAL_BURST", DefaultInitialBurst),
		MaxRegisterRate:          e.Int("MAX_REGISTER_RATE", DefaultMaxRegisterRate),
		MaxRegisterBurst:         e.Int("MAX_REGISTER_BURST", DefaultMaxRegisterBurst),
		MaxPendingRegistersPerIP: e.Int("MAX_PENDING_REGISTERS_PER_IP", DefaultMaxPendingRegistersPerIP),
		Namespace:                s.ServiceNamespace(),
		HomeDomain:               strings.TrimSuffix(strings.ToLower(s.Shared.RequiredString("IMS_DOMAIN")), "."),
	}
	c.VisitedNetworkID = e.String("VISITED_NETWORK_ID", c.HomeDomain)
	c.RelayURL, c.RelayToken = relaySettings(s)
	c.RelayTimeout = e.Duration("RELAY_TIMEOUT", DefaultRelayTimeout)
	c.MaxBindingsPerFlow = e.Int("MAX_BINDINGS_PER_FLOW", DefaultMaxBindingsPerFlow)
	c.MaxBindings = e.Int("MAX_BINDINGS", DefaultMaxBindings)
	c.BindingsPerMinute = e.Int("BINDINGS_PER_MINUTE", DefaultBindingsPerMinute)
	c.MaxCoreOfferBindingsPerFlow = e.Int("MAX_CORE_OFFER_BINDINGS_PER_FLOW", DefaultMaxCoreOfferBindingsPerFlow)
	c.CoreOfferBindingsPerMinute = e.Int("CORE_OFFER_BINDINGS_PER_MINUTE", DefaultCoreOfferBindingsPerMinute)
	c.MaxServerTransactions = e.Int("MAX_SERVER_TRANSACTIONS", transaction.DefaultMaxServerTransactions)
	c.MaxServerTransactionBytes = int64(e.Int("MAX_SERVER_TRANSACTION_BYTES", transaction.DefaultMaxServerTransactionBytes))
	c.MaxQueuedBytes = e.Int("MAX_QUEUED_BYTES", transport.DefaultMaxQueuedBytes)
	c.WriteTimeout = e.Duration("WRITE_TIMEOUT", transport.DefaultWriteTimeout)
	limits(s, c)
	if c.RelayTimeout <= 0 {
		e.Invalid("RELAY_TIMEOUT", "must be greater than zero")
	}
	c.ICSCF = icscfURI(s)
	c.SCSCFHost, c.SCSCFPort = scscfService(s, c.PublicHost)
	if c.HomeDomain != "" && !validHostName(c.HomeDomain) {
		s.Shared.Invalid("IMS_DOMAIN", "not a host name")
	}
	if c.VisitedNetworkID != "" && !validVisitedNetwork(c.VisitedNetworkID) {
		e.Invalid("VISITED_NETWORK_ID", "not one network identifier (RFC 7315 §4.3)")
	}
	if c.PublicHost != "" && !validHostName(c.PublicHost) {
		e.Invalid("PUBLIC_HOST", "not a host name")
	}
	for i, v := range e.List("PUBLIC_ADDRS", nil) {
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" {
			e.Invalid("PUBLIC_ADDRS", "item "+strconv.Itoa(i+1)+" is not an IP address")
			continue
		}
		c.PublicAddrs = append(c.PublicAddrs, a.Unmap())
	}
	s.ForbidInProduction(len(c.PublicAddrs) == 0,
		"PCSCF_PUBLIC_ADDRS is unset: clients put the NLB's address in their first Route (TS 24.229 §5.1.2A.1.1), which pcscf would not take as its own")
	defaultPort := 5061
	switch c.ClientTransport {
	case ClientTLS:
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			e.Invalid("TLS_CERT_FILE", "PCSCF_TLS_CERT_FILE and PCSCF_TLS_KEY_FILE are required with PCSCF_CLIENT_TRANSPORT=tls")
		}
	case ClientNLBTLS:
	case ClientTCP:
		defaultPort = 5060
		s.ForbidInProduction(true, "PCSCF_CLIENT_TRANSPORT=tcp leaves client signalling unencrypted; use tls, or nlb-tls when the NLB terminates TLS (ADR 0003)")
	default:
		e.Invalid("CLIENT_TRANSPORT", "not one of tls, nlb-tls, tcp")
	}
	c.ClientAddr = e.String("CLIENT_ADDR", "0.0.0.0:"+strconv.Itoa(defaultPort))
	c.PublicPort = e.Int("PUBLIC_PORT", defaultPort)
	if c.PublicPort < 1 || c.PublicPort > 65535 {
		e.Invalid("PUBLIC_PORT", "not a port from 1 to 65535")
	}
	for _, a := range []struct{ name, v string }{{"CLIENT_ADDR", c.ClientAddr}, {"CORE_ADDR", c.CoreAddr}, {"CLIENT_UDP_ADDR", c.ClientUDPAddr}} {
		if a.v == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a.v); err != nil {
			e.Invalid(a.name, "not host:port")
		}
	}
	// scscf lets a dialog's requests go to RCS_PCSCF_CORE_PORT only: a core
	// listener on another port would get none of them.
	if want := s.Shared.String("PCSCF_CORE_PORT", ""); want != "" {
		if _, port, err := net.SplitHostPort(c.CoreAddr); err == nil && port != want {
			e.Invalid("CORE_ADDR", "its port is not RCS_PCSCF_CORE_PORT ("+want+"), where scscf sends requests inside a dialog")
		}
	}
	c.CoreHost = runtime.InstanceAddr(e, "CORE_HOST", interfaceAddrs)
	s.ForbidInProduction(c.ClientUDPAddr != "",
		"PCSCF_CLIENT_UDP_ADDR is set: the NLB's fixed 120 s UDP flow timeout would send a client's packets to another task (ADR 0003)")
	s.ForbidInProduction(!c.ProxyProtocol,
		"RCS_PROXY_PROTOCOL is false: every client would appear as the load balancer, so flows and per-client limits could not work (ADR 0003)")
	for _, n := range []struct {
		name string
		v    int
	}{
		{"MAX_REGISTRATIONS", c.MaxRegistrations},
		{"REGISTER_RATE", c.RegisterRate}, {"REGISTER_BURST", c.RegisterBurst},
		{"INITIAL_RATE", c.InitialRate}, {"INITIAL_BURST", c.InitialBurst},
		{"MAX_REGISTER_RATE", c.MaxRegisterRate}, {"MAX_REGISTER_BURST", c.MaxRegisterBurst},
		{"MAX_FLOWS_PER_IP", c.MaxFlowsPerIP}, {"MAX_CONNECTIONS", c.MaxConnections},
		{"MAX_CLIENT_FLOWS", c.MaxClientFlows}, {"CORE_CONNECTIONS", c.CoreConnections},
		{"MAX_BINDINGS_PER_FLOW", c.MaxBindingsPerFlow}, {"MAX_BINDINGS", c.MaxBindings},
		{"BINDINGS_PER_MINUTE", c.BindingsPerMinute},
		{"MAX_CORE_OFFER_BINDINGS_PER_FLOW", c.MaxCoreOfferBindingsPerFlow},
		{"CORE_OFFER_BINDINGS_PER_MINUTE", c.CoreOfferBindingsPerMinute},
	} {
		if n.v <= 0 {
			e.Invalid(n.name, "must be positive")
		}
	}
	if c.MaxPendingRegistersPerIP < 1 || c.MaxPendingRegistersPerIP > 1024 {
		e.Invalid("MAX_PENDING_REGISTERS_PER_IP", "not from 1 to 1024")
	}
	if c.MaxClientFlows+c.CoreConnections > c.MaxConnections {
		e.Invalid("MAX_CLIENT_FLOWS", "plus PCSCF_CORE_CONNECTIONS must not exceed PCSCF_MAX_CONNECTIONS")
	}
	if c.ClientIdleTimeout <= 0 {
		e.Invalid("CLIENT_IDLE_TIMEOUT", "must be greater than zero")
	}

	// Run must return inside the runtime's stop deadline. The runtime
	// reports a malformed RCS_SHUTDOWN_TIMEOUT itself, so the drain then
	// takes the default without a second, misleading problem.
	stop, known := runtime.DefaultShutdownTimeout, true
	if v := s.Shared.String("SHUTDOWN_TIMEOUT", ""); v != "" {
		d, err := time.ParseDuration(v)
		if known = err == nil; known {
			stop = d
		}
	}
	def := runtime.DefaultShutdownTimeout - stopMargin
	if known {
		def = max(stop-stopMargin, 0)
	}
	c.DrainTimeout = e.Duration("DRAIN_TIMEOUT", def)
	switch {
	case c.DrainTimeout <= 0:
		e.Invalid("DRAIN_TIMEOUT", "must be greater than zero, and RCS_SHUTDOWN_TIMEOUT longer than "+stopMargin.String())
	case known && c.DrainTimeout+stopMargin > stop:
		e.Invalid("DRAIN_TIMEOUT", "plus "+stopMargin.String()+" must not exceed RCS_SHUTDOWN_TIMEOUT ("+stop.String()+")")
	}
	return c
}

// relaySettings reads PCSCF_RELAY_URL, an http or https URL of a private
// host, msrp-relay's Cloud Map name on its control port by default, and
// PCSCF_RELAY_TOKEN, which staging and prod require, of at least
// minRelayTokenLength characters; in AWS it comes from Secrets Manager.
func relaySettings(s *runtime.Settings) (*url.URL, secret.Key) {
	e := s.Env
	def := ""
	if ns := s.ServiceNamespace(); ns != "" {
		def = "http://msrp-relay." + ns + ":8082"
	}
	var u *url.URL
	switch v := e.String("RELAY_URL", def); {
	case v == "":
		e.Invalid("RELAY_URL", "required when RCS_SERVICE_NAMESPACE is unset")
	default:
		parsed, err := url.Parse(v)
		if err != nil || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" ||
			!runtime.IsPrivateInternalURL(parsed, s.ServiceNamespace()) && !(!s.Environment.Production() && isLoopbackURL(parsed)) {
			e.Invalid("RELAY_URL", "not an http or https URL of a private host, without a path (ADR 0007 §5)")
		} else {
			u = parsed
		}
	}
	token := e.String("RELAY_TOKEN", "")
	s.ForbidInProduction(token == "", "PCSCF_RELAY_TOKEN is unset: every MSRP session would be refused")
	if token != "" {
		if !validBearerToken(token) {
			e.Invalid("RELAY_TOKEN", "not a bearer token: letters, digits and -._~+/ with optional trailing = (RFC 6750 §2.1)")
			token = ""
		} else {
			s.ForbidInProduction(len(token) < minRelayTokenLength, fmt.Sprintf(
				"PCSCF_RELAY_TOKEN is shorter than %d characters (ADR 0007 §4: at least 256 random bits)", minRelayTokenLength))
		}
	}
	if token == "" {
		return u, secret.Key{}
	}
	return u, secret.NewString(token)
}

// isLoopbackURL reports whether u names a loopback host, as a dev stack's
// relay on one host is.
func isLoopbackURL(u *url.URL) bool {
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if u.Hostname() == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(u.Hostname())
	return err == nil && a.IsLoopback()
}

// validBearerToken reports whether t is a b64token (RFC 6750 §2.1), which
// an Authorization header can carry as it is.
func validBearerToken(t string) bool {
	if t == "" || len(t) > 512 {
		return false
	}
	body := strings.TrimRight(t, "=")
	if body == "" {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~+/", c) >= 0) {
			return false
		}
	}
	return true
}

// icscfURI reads PCSCF_ICSCF_URI, a SIP URI with lr, or makes icscf's Cloud
// Map name in RCS_SERVICE_NAMESPACE.
func icscfURI(s *runtime.Settings) sip.URI {
	e := s.Env
	v := e.String("ICSCF_URI", "")
	if v == "" {
		ns := s.ServiceNamespace()
		if ns == "" {
			e.Invalid("ICSCF_URI", "required when RCS_SERVICE_NAMESPACE is unset")
			return sip.URI{}
		}
		v = "sip:icscf." + ns + ";transport=tcp;lr"
	}
	u, err := sip.ParseURI(v)
	network, _ := u.Param("transport")
	if err != nil || u.Scheme != "sip" || u.User != "" || !u.Params.Has("lr") || !strings.EqualFold(network, "tcp") {
		e.Invalid("ICSCF_URI", "not a sip URI of a host with transport=tcp and lr")
		return sip.URI{}
	}
	host := strings.TrimSuffix(strings.TrimPrefix(u.Host, "["), "]")
	if _, err := netip.ParseAddr(host); err != nil && !runtime.InServiceNamespace(host, s.ServiceNamespace()) {
		e.Invalid("ICSCF_URI", "a host name outside RCS_SERVICE_NAMESPACE, which pcscf does not look up (ADR 0007 §5)")
		return sip.URI{}
	}
	return u
}

// scscfService reads PCSCF_SCSCF_HOST and PCSCF_SCSCF_PORT: a name inside the
// namespace, scscf.<namespace> by default, that is not pcscf's own, so that
// an in-dialog request can never be sent back to pcscf.
func scscfService(s *runtime.Settings, publicHost string) (string, int) {
	e := s.Env
	ns := s.ServiceNamespace()
	def := ""
	if ns != "" {
		def = "scscf." + ns
	}
	host := strings.TrimSuffix(strings.ToLower(e.String("SCSCF_HOST", def)), ".")
	port := e.Int("SCSCF_PORT", DefaultSCSCFPort)
	switch {
	case host == "":
		e.Invalid("SCSCF_HOST", "required when RCS_SERVICE_NAMESPACE is unset")
	case !runtime.InServiceNamespace(host, ns):
		e.Invalid("SCSCF_HOST", "not a name inside RCS_SERVICE_NAMESPACE")
	case host == publicHost || host == "pcscf."+ns:
		e.Invalid("SCSCF_HOST", "names pcscf itself")
	}
	if port < 1 || port > 65535 {
		e.Invalid("SCSCF_PORT", "not a port from 1 to 65535")
	}
	return host, port
}

// validVisitedNetwork reports whether v is one P-Visited-Network-ID element,
// so that pcscf never writes a header the core cannot parse.
func validVisitedNetwork(v string) bool {
	var h sip.Header
	if h.Set("P-Visited-Network-ID", v) != nil {
		return false
	}
	ids, err := h.PVisitedNetworkID()
	return err == nil && len(ids) == 1
}

// validHostName reports whether h is a DNS name pcscf can be dialled by:
// dot-separated labels of letters, digits and inner hyphens.
func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for label := range strings.SplitSeq(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
