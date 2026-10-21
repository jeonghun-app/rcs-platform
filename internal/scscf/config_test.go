package scscf

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/routing"
)

var (
	nonceKey     = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	dialogKey    = base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	challengeKey = base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz012345"))
)

// devEnv is a minimal valid dev configuration.
var devEnv = map[string]string{
	"RCS_ENV":              "dev",
	"RCS_IMS_DOMAIN":       realm,
	"SCSCF_CORE_HOST":      "10.0.4.9",
	"SCSCF_NONCE_KEY":      nonceKey,
	"SCSCF_DIALOG_KEYS":    "k1:" + dialogKey,
	"SCSCF_CHALLENGE_KEYS": "c1:" + challengeKey,
}

// prodEnv is a valid production configuration.
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

func configure(env map[string]string) (ServiceConfig, error) {
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	c := Configure(&runtime.Settings{Env: shared.WithPrefix("SCSCF_"), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	return c, shared.Err()
}

func TestConfigureTakesTheDefaults(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.HomeDomain != realm || c.Namespace != DefaultNamespace || c.CoreAddr != DefaultCoreAddr ||
		c.CoreHost != netip.MustParseAddr("10.0.4.9") || c.OriginRealm != realm || c.HSSRealm != realm ||
		c.HSSDiscovery != DiscoveryCloudMap || c.HSSHostPattern != "hss-*.rcs.local" || c.CxTimeout != DefaultCxTimeout ||
		c.Store != StoreDynamoDB || c.PCSCFCorePort != DefaultPCSCFCorePort ||
		c.ASTimeout != routing.DefaultASTimeout || c.ThirdPartyTimeout != routing.DefaultThirdPartyTimeout ||
		c.MaxThirdParty != routing.DefaultMaxThirdParty || c.SweepInterval != registrar.DefaultSweepInterval ||
		c.DrainTimeout != 15*time.Second {
		t.Errorf("defaults: namespace %s, core %s, store %s, discovery %s, P-CSCF port %d, drain %v",
			c.Namespace, c.CoreAddr, c.Store, c.HSSDiscovery, c.PCSCFCorePort, c.DrainTimeout)
	}
	if c.ICSCF.String() != "sip:icscf.rcs.local:5060;transport=tcp;lr" {
		t.Errorf("ICSCF %s", c.ICSCF.String())
	}
	if len(c.ApplicationServers) != 1 || c.ApplicationServers[0].String() != "sip:rcs-as.rcs.local:5060;transport=tcp" {
		t.Errorf("ApplicationServers %v", c.ApplicationServers)
	}
	if len(c.DialogKeys) != 1 || c.DialogKeys[0].ID != "k1" || len(c.ChallengeKeys) != 1 || c.ChallengeKeys[0].ID != "c1" || len(c.NonceKey) != 32 {
		t.Error("the keys were not read")
	}
}

// TestTheSharedCorePortReachesTheRouter: RCS_PCSCF_CORE_PORT, which pcscf
// listens on.
func TestTheSharedCorePortReachesTheRouter(t *testing.T) {
	c, err := configure(with(devEnv, "RCS_PCSCF_CORE_PORT", "5080"))
	if err != nil || c.PCSCFCorePort != 5080 {
		t.Errorf("PCSCFCorePort %d, %v", c.PCSCFCorePort, err)
	}
}

func TestConfigureRefusesWhatCannotRun(t *testing.T) {
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"no domain":              {with(devEnv, "RCS_IMS_DOMAIN", ""), "RCS_IMS_DOMAIN"},
		"bad core address":       {with(devEnv, "SCSCF_CORE_ADDR", "5060"), "SCSCF_CORE_ADDR"},
		"bad namespace":          {with(devEnv, "SCSCF_NAMESPACE", "not a name"), "SCSCF_NAMESPACE"},
		"one-label host":         {with(devEnv, "SCSCF_DIAMETER_HOST", "scscf"), "SCSCF_DIAMETER_HOST"},
		"unknown discovery":      {with(devEnv, "SCSCF_HSS_DISCOVERY", "static"), "SCSCF_HSS_DISCOVERY"},
		"bad host pattern":       {with(devEnv, "SCSCF_HSS_HOST_PATTERN", "hss-**.rcs.local"), "SCSCF_HSS_HOST_PATTERN"},
		"unknown store":          {with(devEnv, "SCSCF_STORE", "redis"), "SCSCF_STORE"},
		"no challenge keys":      {with(devEnv, "SCSCF_CHALLENGE_KEYS", ""), "SCSCF_CHALLENGE_KEYS"},
		"bad challenge keys":     {with(devEnv, "SCSCF_CHALLENGE_KEYS", "c1"), "SCSCF_CHALLENGE_KEYS"},
		"no nonce key":           {with(devEnv, "SCSCF_NONCE_KEY", ""), "SCSCF_NONCE_KEY"},
		"bad nonce key":          {with(devEnv, "SCSCF_NONCE_KEY", "%%%"), "SCSCF_NONCE_KEY"},
		"no dialog keys":         {with(devEnv, "SCSCF_DIALOG_KEYS", ""), "SCSCF_DIALOG_KEYS"},
		"bad dialog key":         {with(devEnv, "SCSCF_DIALOG_KEYS", "k1:%%%"), "SCSCF_DIALOG_KEYS"},
		"bad I-CSCF":             {with(devEnv, "SCSCF_ICSCF_URI", "tel:+15550100001"), "SCSCF_ICSCF_URI"},
		"bad core port":          {with(devEnv, "RCS_PCSCF_CORE_PORT", "70000"), "RCS_PCSCF_CORE_PORT"},
		"bad AS":                 {with(devEnv, "SCSCF_APPLICATION_SERVERS", "http://rcs-as"), "SCSCF_APPLICATION_SERVERS"},
		"no AS timeout":          {with(devEnv, "SCSCF_AS_TIMEOUT", "0s"), "SCSCF_AS_TIMEOUT"},
		"no third-party bound":   {with(devEnv, "SCSCF_MAX_THIRD_PARTY", "0"), "SCSCF_MAX_THIRD_PARTY"},
		"no sweep limit":         {with(devEnv, "SCSCF_SWEEP_LIMIT", "0"), "SCSCF_SWEEP_LIMIT"},
		"drain past the stop":    {with(devEnv, "RCS_SHUTDOWN_TIMEOUT", "10s", "SCSCF_DRAIN_TIMEOUT", "8s"), "SCSCF_DRAIN_TIMEOUT"},
		"no server transactions": {with(devEnv, "SCSCF_MAX_SERVER_TRANSACTIONS", "0"), "SCSCF_MAX_SERVER_TRANSACTIONS"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := configure(c.env); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %v, want one naming %s", err, c.want)
			}
		})
	}
	// The memory store needs no challenge keys: nothing is sealed.
	if _, err := configure(with(devEnv, "SCSCF_STORE", StoreMemory, "SCSCF_CHALLENGE_KEYS", "")); err != nil {
		t.Errorf("memory store without challenge keys: %v", err)
	}
}

func TestProductionRefusesWhatIsUnsafeThere(t *testing.T) {
	for _, tt := range []struct {
		kv   []string
		want string
	}{
		{[]string{"SCSCF_STORE", StoreMemory}, "SCSCF_STORE=memory"},
		{[]string{"SCSCF_HSS_DISCOVERY", DiscoveryDNS}, "SCSCF_HSS_DISCOVERY=dns"},
		{[]string{"SCSCF_DYNAMODB_ENDPOINT", "http://dynamodb:8000"}, "SCSCF_DYNAMODB_ENDPOINT"},
		{[]string{"SCSCF_DIAMETER_HOST", "scscf-a.rcs.local"}, "SCSCF_DIAMETER_HOST is set"},
		{[]string{"SCSCF_HSS_HOST_PATTERN", "*.rcs.local"}, "SCSCF_HSS_HOST_PATTERN is not <prefix>*.<namespace>"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			status, out := startup(t, with(prodEnv, tt.kv...))
			if status != runtime.ExitFailure || !strings.Contains(out, tt.want) {
				t.Fatalf("status %d, want %q refused:\n%s", status, tt.want, out)
			}
		})
	}
	// The valid production configuration is refused for nothing of
	// scscf's: it fails only at the listener the test refuses to open.
	if _, out := startup(t, prodEnv); strings.Contains(out, "SCSCF_") {
		t.Errorf("a valid production configuration was refused:\n%s", out)
	}
	for _, kv := range [][]string{{"SCSCF_STORE", StoreMemory}, {"SCSCF_HSS_DISCOVERY", DiscoveryDNS}, {"SCSCF_DIAMETER_HOST", "scscf-a.rcs.local"}, {"SCSCF_HSS_HOST_PATTERN", "*.rcs.local"}} {
		if _, err := configure(with(devEnv, kv...)); err != nil {
			t.Errorf("dev refused %s=%s: %v", kv[0], kv[1], err)
		}
	}
}

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

// TestTheConfigurationGivesNoKeyAway: printed, formatted, logged or
// encoded as JSON, it shows none of its keys.
func TestTheConfigurationGivesNoKeyAway(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	j, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("config", "config", c)
	keys, err := json.Marshal(c.ChallengeKeys)
	if err != nil {
		t.Fatal(err)
	}
	var loggedKeys bytes.Buffer
	slog.New(slog.NewJSONHandler(&loggedKeys, nil)).Info("keys", "challenge", c.ChallengeKeys, "dialog", c.DialogKeys,
		"one challenge key", c.ChallengeKeys[0], "one dialog key", c.DialogKeys[0])
	for _, out := range []string{
		fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s %d %o %b %t %x", c, c, c, c, c, c, c, c, c), string(j), logged.String(),
		// The key slices on their own.
		fmt.Sprintf("%v %+v %#v %s %d %x", c.ChallengeKeys, c.ChallengeKeys, c.ChallengeKeys, c.ChallengeKeys, c.ChallengeKeys, c.ChallengeKeys),
		fmt.Sprintf("%v %+v %#v %s %d %x", c.DialogKeys, c.DialogKeys, c.DialogKeys, c.DialogKeys, c.DialogKeys, c.DialogKeys),
		string(keys), loggedKeys.String(),
	} {
		for _, secret := range []string{
			"0123456789abcdef", "fedcba9876543210", "abcdefghijklmnop", nonceKey, dialogKey, challengeKey,
			// %d and %x of the nonce, challenge and dialog keys' bytes.
			"48 49 50 51 52", "97 98 99 100 101", "102 101 100 99 98",
			fmt.Sprintf("%x", []byte("01234567")), fmt.Sprintf("%x", []byte("abcdefgh")), fmt.Sprintf("%x", []byte("fedcba98")),
		} {
			if strings.Contains(out, secret) {
				t.Errorf("%q gives a key away", out)
			}
		}
	}
}
