package icscf

import (
	"cmp"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// HSS discovery modes (ICSCF_HSS_DISCOVERY).
const (
	// DiscoveryCloudMap lists the HSS tasks with Cloud Map's
	// DiscoverInstances, which returns every one of them; a DNS answer
	// names at most eight (cxclient package documentation).
	DiscoveryCloudMap = "cloudmap"
	// DiscoveryDNS resolves hss.<namespace>, as the compose stack serves it.
	DiscoveryDNS = "dns"
)

// Defaults of the settings in docs/icscf.md.
const (
	DefaultCoreAddr  = "0.0.0.0:5060"
	DefaultNamespace = "rcs.local"
	// DefaultCxTimeout bounds one Cx attempt, cxclient's default: a REGISTER
	// waits for at most two, an attempt and its retry on another HSS task,
	// before the S-CSCF's RegisterTimeout starts.
	DefaultCxTimeout = cxclient.DefaultRequestTimeout
	// stopMargin is what Run needs after the drain to close the proxy, the
	// transport and the Cx client, inside RCS_SHUTDOWN_TIMEOUT.
	stopMargin = 5 * time.Second
)

// ServiceConfig is icscf's configuration (docs/icscf.md), read by Configure
// from ICSCF_ variables.
type ServiceConfig struct {
	// HomeDomain is RCS_IMS_DOMAIN, the home network; Namespace the Cloud Map
	// namespace the other services are found in.
	HomeDomain string
	Namespace  string
	// CoreAddr is the core listener, the only one: pcscf and scscf reach
	// icscf, clients never do (ADR 0007). CoreHost is this task's address
	// on it, which goes in the Via of what icscf forwards.
	CoreAddr string
	CoreHost netip.Addr
	// SCSCFs are the S-CSCFs to choose from (ICSCF_SCSCF, ParseSCSCFs).
	SCSCFs []SCSCF
	// RetryAfter and RegisterTimeout are Config's.
	RetryAfter      time.Duration
	RegisterTimeout time.Duration

	// OriginHost is this task's Diameter identity: ICSCF_DIAMETER_HOST, or
	// icscf-<random>.<namespace> chosen at start (ADR 0005). OriginRealm is
	// the IMS core's realm, HSSRealm the HSS's.
	OriginHost  string
	OriginRealm string
	HSSRealm    string
	// HSSDiscovery is DiscoveryCloudMap or DiscoveryDNS; HSSHostPattern the
	// Origin-Host every HSS task must have (threat model T1), never empty.
	HSSDiscovery   string
	HSSHostPattern string
	// CxTimeout bounds one Cx attempt.
	CxTimeout time.Duration
	// DrainTimeout bounds how long a stop waits for the requests in
	// progress to get their final responses: by default RCS_SHUTDOWN_TIMEOUT
	// less what the rest of the stop needs.
	DrainTimeout time.Duration
}

// drainTimeout reads ICSCF_DRAIN_TIMEOUT, by default RCS_SHUTDOWN_TIMEOUT
// less stopMargin, so Run returns inside the runtime's stop deadline. The
// runtime reports a malformed RCS_SHUTDOWN_TIMEOUT itself, so the drain then
// takes the default without a second, misleading problem.
func drainTimeout(s *runtime.Settings) time.Duration {
	e := s.Env
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
	d := e.Duration("DRAIN_TIMEOUT", def)
	switch {
	case d <= 0:
		e.Invalid("DRAIN_TIMEOUT", "must be greater than zero, and RCS_SHUTDOWN_TIMEOUT longer than "+stopMargin.String())
	case known && d+stopMargin > stop:
		e.Invalid("DRAIN_TIMEOUT", "plus "+stopMargin.String()+" must not exceed RCS_SHUTDOWN_TIMEOUT ("+stop.String()+")")
	}
	return d
}

// prefixWildcard reports whether pattern is one label ending in '*' after a
// prefix, followed by exactly the namespace, as hss-*.rcs.local is: the
// shape that names the HSS tasks and nothing else (review of #276).
func prefixWildcard(pattern, namespace string) bool {
	label, rest, ok := strings.Cut(pattern, ".")
	return ok && rest == namespace && strings.Count(pattern, "*") == 1 &&
		strings.HasSuffix(label, "*") && len(label) > 1
}

// interfaceAddrs finds this task's addresses; tests replace it.
var interfaceAddrs = net.InterfaceAddrs

// Configure reads the ICSCF_ settings (docs/icscf.md) and refuses, in staging
// and prod, the ones that are unsafe there.
func Configure(s *runtime.Settings) ServiceConfig {
	e := s.Env
	domain := s.Shared.RequiredString("IMS_DOMAIN")
	c := ServiceConfig{
		HomeDomain:      domain,
		Namespace:       e.String("NAMESPACE", cmp.Or(s.ServiceNamespace(), DefaultNamespace)),
		CoreAddr:        e.String("CORE_ADDR", DefaultCoreAddr),
		RetryAfter:      e.Duration("RETRY_AFTER", DefaultRetryAfter),
		RegisterTimeout: e.Duration("REGISTER_TIMEOUT", DefaultRegisterTimeout),
		OriginHost:      e.String("DIAMETER_HOST", ""),
		OriginRealm:     e.String("DIAMETER_REALM", domain),
		HSSDiscovery:    e.String("HSS_DISCOVERY", DiscoveryCloudMap),
		CxTimeout:       e.Duration("CX_TIMEOUT", DefaultCxTimeout),
	}
	c.HSSRealm = e.String("HSS_REALM", c.OriginRealm)
	c.HSSHostPattern = e.String("HSS_HOST_PATTERN", "hss-*."+c.Namespace)
	c.CoreHost = runtime.InstanceAddr(e, "CORE_HOST", interfaceAddrs)

	scscfs := e.String("SCSCF", `[{"uri":"sip:scscf.`+c.Namespace+`:5060;transport=tcp"}]`)
	if list, err := ParseSCSCFs([]byte(scscfs)); err != nil {
		e.Invalid("SCSCF", err.Error())
	} else {
		c.SCSCFs = list
	}

	if domain != "" && !identity.IsDomainName(domain) {
		s.Shared.Invalid("IMS_DOMAIN", "not a domain name")
	}
	if !identity.IsDomainName(c.Namespace) {
		e.Invalid("NAMESPACE", "not a domain name")
	}
	if _, port, err := net.SplitHostPort(c.CoreAddr); err != nil {
		e.Invalid("CORE_ADDR", "not host:port")
	} else if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		e.Invalid("CORE_ADDR", "the port is not a number from 0 to 65535")
	}
	for _, d := range []struct {
		name string
		v    string
	}{{"DIAMETER_HOST", c.OriginHost}, {"DIAMETER_REALM", c.OriginRealm}, {"HSS_REALM", c.HSSRealm}} {
		if d.v != "" && !identity.IsDomainName(d.v) {
			e.Invalid(d.name, "not a domain name")
		}
	}
	// A Diameter identity is a fully qualified name (RFC 6733 §4.3.1).
	if c.OriginHost != "" && !strings.Contains(c.OriginHost, ".") {
		e.Invalid("DIAMETER_HOST", "needs two or more labels")
	}
	if c.RetryAfter < time.Second || c.RetryAfter > MaxRetryAfter || c.RetryAfter%time.Second != 0 {
		e.Invalid("RETRY_AFTER", "must be whole seconds from 1s to 1h")
	}
	if c.RegisterTimeout <= 0 || c.RegisterTimeout > MaxRegisterTimeout {
		e.Invalid("REGISTER_TIMEOUT", "must be greater than zero and at most 32s, the client's Timer F")
	}
	if c.CxTimeout <= 0 {
		e.Invalid("CX_TIMEOUT", "must be greater than zero")
	}
	// A REGISTER waits for a UAR, an attempt and its retry on another HSS
	// task, and then for the S-CSCF: all of it must end before the client's
	// Timer F, 64*T1 = 32 s, or the 480 or 504 comes after it gave up
	// (review of #276).
	// One Cx attempt alone must fit first, so the sum below cannot
	// overflow and wrap below the limit (review of #276).
	switch {
	case c.CxTimeout >= MaxRegisterTimeout:
		e.Invalid("CX_TIMEOUT", "must be under 32s, the client's Timer F")
	case c.CxTimeout > 0 && c.RegisterTimeout > 0 && 2*c.CxTimeout+c.RegisterTimeout >= MaxRegisterTimeout:
		e.Invalid("REGISTER_TIMEOUT", "plus twice ICSCF_CX_TIMEOUT must be under 32s, the client's Timer F")
	}
	s.ForbidInProduction(c.OriginHost != "",
		"ICSCF_DIAMETER_HOST is set: every task would share one Origin-Host, and a task replacing a dead one would find the HSS holding its predecessor's connection in REOPEN (ADR 0005); leave it unset in ECS")
	switch c.HSSDiscovery {
	case DiscoveryCloudMap:
	case DiscoveryDNS:
		s.ForbidInProduction(true,
			"ICSCF_HSS_DISCOVERY=dns sees at most eight HSS tasks in an answer, so icscf would send all its Cx traffic to a subset of them; use cloudmap (decided on #15)")
	default:
		e.Invalid("HSS_DISCOVERY", "not one of cloudmap, dns")
	}
	// The pattern cannot be switched off: an empty value takes the default,
	// so a peer that claims another identity is never trusted as the HSS
	// (threat model T1).
	// "**" matches no host at all, so icscf would stay unready for no
	// reason it could tell (review of #276).
	if !identity.IsDomainName(strings.ReplaceAll(c.HSSHostPattern, "*", "x")) || strings.Contains(c.HSSHostPattern, "**") {
		e.Invalid("HSS_HOST_PATTERN", "not a domain name with one '*' at most in a label")
	}
	c.DrainTimeout = drainTimeout(s)
	s.ForbidInProduction(!prefixWildcard(c.HSSHostPattern, c.Namespace),
		"ICSCF_HSS_HOST_PATTERN is not <prefix>*.<namespace>: a wider pattern trusts as the HSS peers that are not HSS tasks (threat model T1)")
	return c
}
