package icscf

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

// devEnv is a minimal valid dev configuration.
var devEnv = map[string]string{
	"RCS_ENV":         "dev",
	"RCS_IMS_DOMAIN":  home,
	"ICSCF_CORE_HOST": "10.0.3.9",
}

// prodEnv is a valid production configuration, so every reason a test sees
// comes from the setting under test.
var prodEnv = with(devEnv,
	"RCS_ENV", "prod",
	"RCS_PII_HMAC_KEY", strings.Repeat("k", 32),
	"RCS_SERVICE_NAMESPACE", "rcs.local",
)

func with(base map[string]string, kv ...string) map[string]string {
	m := map[string]string{}
	for k, v := range base {
		m[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(m, kv[i])
		} else {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

// configure runs Configure the way runtime.Run does and returns the
// configuration, every problem, and the reasons refused in production.
func configure(env map[string]string) (ServiceConfig, error) {
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	c := Configure(&runtime.Settings{Env: shared.WithPrefix("ICSCF_"), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	return c, shared.Err()
}

func TestConfigureTakesTheDefaults(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.HomeDomain != home || c.Namespace != DefaultNamespace || c.CoreAddr != DefaultCoreAddr ||
		c.CoreHost != netip.MustParseAddr("10.0.3.9") || c.OriginRealm != home || c.HSSRealm != home ||
		c.HSSDiscovery != DiscoveryCloudMap || c.HSSHostPattern != "hss-*.rcs.local" ||
		c.RetryAfter != DefaultRetryAfter || c.RegisterTimeout != DefaultRegisterTimeout ||
		c.CxTimeout != DefaultCxTimeout || c.OriginHost != "" || c.DrainTimeout != 15*time.Second ||
		c.MaxServerTransactions != 20000 || c.MaxServerTransactionBytes != 256<<20 {
		t.Errorf("defaults = %+v", c)
	}
	if len(c.SCSCFs) != 1 || c.SCSCFs[0].URI.String() != "sip:scscf.rcs.local:5060;transport=tcp" {
		t.Errorf("default S-CSCF = %+v", c.SCSCFs)
	}
}

func TestConfigureReadsEverySetting(t *testing.T) {
	c, err := configure(with(devEnv,
		"ICSCF_NAMESPACE", "core.example.net",
		"ICSCF_CORE_ADDR", "0.0.0.0:5080",
		"ICSCF_SCSCF", `[{"uri":"sip:a.core.example.net","mandatory":[1]},{"uri":"sip:b.core.example.net"}]`,
		"ICSCF_RETRY_AFTER", "30s",
		"ICSCF_REGISTER_TIMEOUT", "8s",
		"ICSCF_DIAMETER_HOST", "icscf-a.core.example.net",
		"ICSCF_DIAMETER_REALM", "realm.example.net",
		"ICSCF_HSS_REALM", "hss.example.net",
		"ICSCF_HSS_DISCOVERY", "dns",
		"ICSCF_HSS_HOST_PATTERN", "hss-*.other.example.net",
		"ICSCF_CX_TIMEOUT", "3s",
		"ICSCF_MAX_SERVER_TRANSACTIONS", "500",
		"ICSCF_MAX_SERVER_TRANSACTION_BYTES", "2097152",
	))
	if err != nil {
		t.Fatal(err)
	}
	if c.Namespace != "core.example.net" || c.CoreAddr != "0.0.0.0:5080" || len(c.SCSCFs) != 2 ||
		c.RetryAfter != 30*time.Second || c.RegisterTimeout != 8*time.Second ||
		c.OriginHost != "icscf-a.core.example.net" || c.OriginRealm != "realm.example.net" ||
		c.HSSRealm != "hss.example.net" || c.HSSDiscovery != DiscoveryDNS ||
		c.HSSHostPattern != "hss-*.other.example.net" || c.CxTimeout != 3*time.Second ||
		c.MaxServerTransactions != 500 || c.MaxServerTransactionBytes != 2<<20 {
		t.Errorf("config = %+v", c)
	}
}

func TestConfigureRefusesWhatCannotWork(t *testing.T) {
	cases := map[string]map[string]string{
		"no IMS domain":            with(devEnv, "RCS_IMS_DOMAIN", ""),
		"IMS domain not a domain":  with(devEnv, "RCS_IMS_DOMAIN", "ims home"),
		"bad namespace":            with(devEnv, "ICSCF_NAMESPACE", "-x"),
		"core address not an addr": with(devEnv, "ICSCF_CORE_ADDR", "5060"),
		"bad S-CSCF list":          with(devEnv, "ICSCF_SCSCF", `[]`),
		"bad Diameter host":        with(devEnv, "ICSCF_DIAMETER_HOST", "not a host"),
		"bad Diameter realm":       with(devEnv, "ICSCF_DIAMETER_REALM", "a b"),
		"bad HSS realm":            with(devEnv, "ICSCF_HSS_REALM", "a b"),
		"Retry-After of 0":         with(devEnv, "ICSCF_RETRY_AFTER", "0s"),
		"fractional Retry-After":   with(devEnv, "ICSCF_RETRY_AFTER", "1500ms"),
		"Retry-After over an hour": with(devEnv, "ICSCF_RETRY_AFTER", "61m"),
		"register timeout of 0":    with(devEnv, "ICSCF_REGISTER_TIMEOUT", "0s"),
		"register past Timer F":    with(devEnv, "ICSCF_REGISTER_TIMEOUT", "33s"),
		"Cx timeout of 0":          with(devEnv, "ICSCF_CX_TIMEOUT", "0s"),
		"unknown discovery":        with(devEnv, "ICSCF_HSS_DISCOVERY", "consul"),
		"bad core host":            with(devEnv, "ICSCF_CORE_HOST", "here"),
		"bad HSS host pattern":     with(devEnv, "ICSCF_HSS_HOST_PATTERN", "hss *.x"),
		// 2 × 8 s + 16 s reaches the client's Timer F (review of #276).
		"Cx and register past Timer F": with(devEnv, "ICSCF_CX_TIMEOUT", "8s"),
		// 2 × 2562047h wraps int64 below zero; it must not pass for that.
		"a Cx timeout that overflows": with(devEnv, "ICSCF_CX_TIMEOUT", "2562047h"),
		// QA of #276: the guards of the last round, each with a row.
		"a pattern that matches nothing":  with(devEnv, "ICSCF_HSS_HOST_PATTERN", "hss-**.rcs.local"),
		"a one-label Diameter host":       with(devEnv, "ICSCF_DIAMETER_HOST", "x"),
		"a core port past 65535":          with(devEnv, "ICSCF_CORE_ADDR", ":70000"),
		"a drain past the stop deadline":  with(devEnv, "ICSCF_DRAIN_TIMEOUT", "16s"),
		"a stop deadline the margin eats": with(devEnv, "RCS_SHUTDOWN_TIMEOUT", "5s"),
		// 2 × 7 s + 2 s to connect + 16 s reaches Timer F.
		"Cx, connection and register past Timer F": with(devEnv, "ICSCF_CX_TIMEOUT", "7s"),
		// #37's caps.
		"no server transactions":        with(devEnv, "ICSCF_MAX_SERVER_TRANSACTIONS", "0"),
		"server transactions past 10^6": with(devEnv, "ICSCF_MAX_SERVER_TRANSACTIONS", "1000001"),
		"a count that is not a number":  with(devEnv, "ICSCF_MAX_SERVER_TRANSACTIONS", "many"),
		"no server transaction bytes":   with(devEnv, "ICSCF_MAX_SERVER_TRANSACTION_BYTES", "0"),
		// One byte short of the largest request icscf reads.
		"bytes below one request": with(devEnv, "ICSCF_MAX_SERVER_TRANSACTION_BYTES", "1064959"),
	}
	for name, env := range cases {
		if _, err := configure(env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Production refuses DNS discovery, which sees at most eight HSS tasks, and
// a fixed Origin-Host (review of #276); dev takes both. The HSS host pattern
// cannot be emptied: it keeps its default.
func TestProductionRefusesDNSDiscoveryAndAFixedOriginHost(t *testing.T) {
	for _, tt := range []struct {
		kv   []string
		want string
	}{
		{[]string{"ICSCF_HSS_DISCOVERY", "dns"}, "ICSCF_HSS_DISCOVERY=dns sees at most eight HSS tasks"},
		{[]string{"ICSCF_DIAMETER_HOST", "icscf-a.rcs.local"}, "ICSCF_DIAMETER_HOST is set"},
		// Review of #276: only <prefix>*.<namespace> names the HSS tasks.
		{[]string{"ICSCF_HSS_HOST_PATTERN", "*.rcs.local"}, "ICSCF_HSS_HOST_PATTERN is not <prefix>*.<namespace>"},
		{[]string{"ICSCF_HSS_HOST_PATTERN", "hss-*.*.local"}, "ICSCF_HSS_HOST_PATTERN is not <prefix>*.<namespace>"},
		{[]string{"ICSCF_HSS_HOST_PATTERN", "hss-*.other.example"}, "ICSCF_HSS_HOST_PATTERN is not <prefix>*.<namespace>"},
		{[]string{"ICSCF_HSS_HOST_PATTERN", "hss-*"}, "ICSCF_HSS_HOST_PATTERN is not <prefix>*.<namespace>"},
		{[]string{"ICSCF_HSS_HOST_PATTERN", "*hss.rcs.local"}, "ICSCF_HSS_HOST_PATTERN is not <prefix>*.<namespace>"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			status, out := startup(t, with(prodEnv, tt.kv...))
			if status != runtime.ExitFailure || !strings.Contains(out, tt.want) {
				t.Fatalf("status %d, want %q refused:\n%s", status, tt.want, out)
			}
		})
	}
	if _, err := configure(with(devEnv, "ICSCF_DIAMETER_HOST", "icscf-a.rcs.local", "ICSCF_HSS_HOST_PATTERN", "*.rcs.local")); err != nil {
		t.Fatalf("dev refused a fixed Origin-Host or a wide pattern: %v", err)
	}
	for _, p := range []string{"hss-*.rcs.local", "h*.rcs.local"} {
		if !prefixWildcard(p, "rcs.local") {
			t.Errorf("%q refused", p)
		}
	}
	if c, err := configure(with(devEnv, "ICSCF_HSS_HOST_PATTERN", "")); err != nil || c.HSSHostPattern != "hss-*.rcs.local" {
		t.Errorf("an empty pattern gave %q (%v), want the default", c.HSSHostPattern, err)
	}
	// The valid production configuration is refused for nothing of
	// icscf's: it fails only at the listener the test refuses to open.
	if _, out := startup(t, prodEnv); strings.Contains(out, "ICSCF_") {
		t.Errorf("a valid production configuration was refused:\n%s", out)
	}
	if _, err := configure(with(devEnv, "ICSCF_HSS_DISCOVERY", "dns")); err != nil {
		t.Fatalf("dev refused DNS discovery: %v", err)
	}
}

// startup runs icscf as its main function would, with a listener that must
// not open, and returns its exit status and output.
func startup(t *testing.T, env map[string]string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	status := runtime.Run(context.Background(), Service(), runtime.Process{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Stdout:    &out,
		Listen:    func(string, string) (net.Listener, error) { return nil, errors.New("must not start") },
	})
	return status, out.String()
}

// Just under Timer F, the connection setup counted, is accepted.
func TestABudgetJustUnderTimerFIsAccepted(t *testing.T) {
	if _, err := configure(with(devEnv, "ICSCF_CX_TIMEOUT", "6999ms")); err != nil {
		t.Fatalf("2 × 6.999 s + 2 s + 16 s refused: %v", err)
	}
}

// The largest transaction count the layer takes is accepted, and a byte
// bound of exactly one largest request (16 KiB of header, 1 MiB of body).
func TestTheTransactionCapBoundsAreAccepted(t *testing.T) {
	if _, err := configure(with(devEnv, "ICSCF_MAX_SERVER_TRANSACTIONS", "1000000", "ICSCF_MAX_SERVER_TRANSACTION_BYTES", "1064960")); err != nil {
		t.Fatalf("10^6 transactions and 1064960 bytes refused: %v", err)
	}
}

// The proxy allows as many contexts as the layer allows server transactions,
// so a burst meets the layer's cap first (code review of #311).
func TestTheProxyAllowsAsManyContextsAsServerTransactions(t *testing.T) {
	tcfg, contexts := proxyLimits(ServiceConfig{MaxServerTransactions: 30000, MaxServerTransactionBytes: 1 << 30})
	if tcfg.MaxServerTransactions != 30000 || tcfg.MaxServerTransactionBytes != 1<<30 || contexts != 30000 {
		t.Fatalf("limits = %+v, %d contexts", tcfg, contexts)
	}
}
