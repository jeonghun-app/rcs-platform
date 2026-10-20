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
		c.CxTimeout != DefaultCxTimeout || c.OriginHost != "" {
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
	))
	if err != nil {
		t.Fatal(err)
	}
	if c.Namespace != "core.example.net" || c.CoreAddr != "0.0.0.0:5080" || len(c.SCSCFs) != 2 ||
		c.RetryAfter != 30*time.Second || c.RegisterTimeout != 8*time.Second ||
		c.OriginHost != "icscf-a.core.example.net" || c.OriginRealm != "realm.example.net" ||
		c.HSSRealm != "hss.example.net" || c.HSSDiscovery != DiscoveryDNS ||
		c.HSSHostPattern != "hss-*.other.example.net" || c.CxTimeout != 3*time.Second {
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
	} {
		t.Run(tt.want, func(t *testing.T) {
			status, out := startup(t, with(prodEnv, tt.kv...))
			if status != runtime.ExitFailure || !strings.Contains(out, tt.want) {
				t.Fatalf("status %d, want %q refused:\n%s", status, tt.want, out)
			}
		})
	}
	if _, err := configure(with(devEnv, "ICSCF_DIAMETER_HOST", "icscf-a.rcs.local")); err != nil {
		t.Fatalf("dev refused a fixed Origin-Host: %v", err)
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
