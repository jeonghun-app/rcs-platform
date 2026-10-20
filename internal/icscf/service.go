package icscf

import (
	"cmp"
	"net"
	"net/netip"
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
	if _, _, err := net.SplitHostPort(c.CoreAddr); err != nil {
		e.Invalid("CORE_ADDR", "not host:port")
	}
	for _, d := range []struct {
		name string
		v    string
	}{{"DIAMETER_HOST", c.OriginHost}, {"DIAMETER_REALM", c.OriginRealm}, {"HSS_REALM", c.HSSRealm}} {
		if d.v != "" && !identity.IsDomainName(d.v) {
			e.Invalid(d.name, "not a domain name")
		}
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
	if !identity.IsDomainName(strings.ReplaceAll(c.HSSHostPattern, "*", "x")) {
		e.Invalid("HSS_HOST_PATTERN", "not a domain name with '*' in its labels")
	}
	return c
}
