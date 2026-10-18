package runtime

import (
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/pii"
)

// Environment is the deployment stage a process runs in, from RCS_ENV.
type Environment string

// The stages. Staging is treated like production for safety checks, because a
// staging stack is reachable from the internet and often holds copies of
// production configuration.
const (
	Dev     Environment = "dev"
	Test    Environment = "test"
	Staging Environment = "staging"
	Prod    Environment = "prod"
)

// Production reports whether production-unsafe settings are refused.
func (e Environment) Production() bool {
	return e == Staging || e == Prod
}

// Defaults for the shared settings.
const (
	DefaultAdminAddr        = ":8080"
	DefaultShutdownTimeout  = 20 * time.Second
	DefaultMetricsNamespace = "RCS"
)

// minPIIKeyLen follows RFC 2104 §3: an HMAC key shorter than the hash output
// (32 bytes for SHA-256) weakens it.
const minPIIKeyLen = 32

// shared holds the RCS_ settings every service reads.
type shared struct {
	environment      Environment
	logLevel         slog.Level
	admin            adminAddr
	shutdownTimeout  time.Duration
	metricsNamespace string
	// redactor carries RCS_PII_HMAC_KEY; the key itself is never stored where
	// fmt could print it (see pii.Redactor).
	redactor *pii.Redactor
}

// loadShared reads the RCS_ settings. RCS_ENV has no default: a task definition
// that forgets it must not start as "dev" and skip the production checks.
func loadShared(e *Env) shared {
	s := shared{
		logLevel:         slog.LevelInfo,
		metricsNamespace: DefaultMetricsNamespace,
		redactor:         pii.NewRedactor(nil),
	}

	switch v := Environment(e.RequiredString("ENV")); v {
	case Dev, Test, Staging, Prod:
		s.environment = v
	case "":
	default:
		e.Invalid("ENV", "not one of dev, test, staging, prod")
	}

	switch v := e.String("LOG_LEVEL", "info"); v {
	case "debug":
		s.logLevel = slog.LevelDebug
	case "info":
		s.logLevel = slog.LevelInfo
	case "warn":
		s.logLevel = slog.LevelWarn
	case "error":
		s.logLevel = slog.LevelError
	default:
		e.Invalid("LOG_LEVEL", "not one of debug, info, warn, error")
	}

	s.admin = loadAdminAddr(e)

	s.shutdownTimeout = e.Duration("SHUTDOWN_TIMEOUT", DefaultShutdownTimeout)
	if s.shutdownTimeout == 0 {
		e.Invalid("SHUTDOWN_TIMEOUT", "must be greater than zero")
		s.shutdownTimeout = DefaultShutdownTimeout
	}

	if v := e.String("METRICS_NAMESPACE", DefaultMetricsNamespace); validNamespace(v) {
		s.metricsNamespace = v
	} else {
		e.Invalid("METRICS_NAMESPACE", "not a CloudWatch namespace (1-255 of A-Z a-z 0-9 . - _ / # : space, not starting with AWS/)")
	}

	if key := e.String("PII_HMAC_KEY", ""); key != "" {
		if len(key) < minPIIKeyLen {
			e.Invalid("PII_HMAC_KEY", "shorter than "+strconv.Itoa(minPIIKeyLen)+" bytes")
		} else {
			s.redactor = pii.NewRedactor([]byte(key))
		}
	}
	return s
}

// adminAddr is where the admin server listens and where -healthcheck looks for
// it.
type adminAddr struct {
	listen   string
	probeURL string
}

// loadAdminAddr reads RCS_ADMIN_ADDR as host:port with an IP literal or empty
// host. A host name is refused because the listener and -healthcheck would each
// resolve it and could disagree; port 0 is refused because -healthcheck, which
// runs as a separate process, could not find the port.
func loadAdminAddr(e *Env) adminAddr {
	v := e.String("ADMIN_ADDR", DefaultAdminAddr)
	a, ok := parseAdminAddr(v)
	if !ok {
		e.Invalid("ADMIN_ADDR", "not host:port with an IP address or empty host and a port from 1 to 65535")
		a, _ = parseAdminAddr(DefaultAdminAddr)
	}
	return a
}

func parseAdminAddr(v string) (adminAddr, bool) {
	host, portText, err := net.SplitHostPort(v)
	if err != nil {
		return adminAddr{}, false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != portText {
		return adminAddr{}, false
	}
	probe := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return adminAddr{}, false
		}
		// An unspecified address listens on loopback too; a specific one has to
		// be probed where it listens.
		if !ip.IsUnspecified() {
			probe = ip
		}
	}
	return adminAddr{
		listen:   v,
		probeURL: "http://" + netip.AddrPortFrom(probe, uint16(port)).String() + "/healthz",
	}, true
}

// validNamespace follows the CloudWatch PutMetricData rules for Namespace.
func validNamespace(v string) bool {
	if len(v) == 0 || len(v) > 255 || strings.HasPrefix(v, "AWS/") {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !(isAlnum(c) || strings.IndexByte("._-/#: ", c) >= 0) {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
