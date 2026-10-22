package scscf

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/dynamostore"
)

// The keys are plain secrets of 32 bytes, as GenerateSecretString writes
// them; made up for the tests.
const (
	nonceKey     = "0123456789abcdef0123456789abcdef"
	dialogKey    = "fedcba9876543210fedcba9876543210"
	challengeKey = "abcdefghijklmnopqrstuvwxyz012345"
	// previousKey is a key a rotation replaced.
	previousKey = "ZYXWVUTSRQPONMLKJIHGFEDCBA987654"
)

// devEnv is a minimal valid dev configuration.
var devEnv = map[string]string{
	"RCS_ENV":             "dev",
	"RCS_IMS_DOMAIN":      realm,
	"SCSCF_CORE_HOST":     "10.0.4.9",
	"SCSCF_NONCE_KEY":     nonceKey,
	"SCSCF_DIALOG_KEY":    dialogKey,
	"SCSCF_CHALLENGE_KEY": challengeKey,
}

// prodEnv is a valid production configuration.
var prodEnv = with(devEnv,
	"RCS_ENV", "prod",
	"RCS_PII_HMAC_KEY", strings.Repeat("k", 32),
	"RCS_SERVICE_NAMESPACE", "rcs.local",
	"SCSCF_EDGE_PROXY_PUBLIC_HOSTS", "pcscf.example.net,203.0.113.5",
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
	if len(c.DialogKeys) != 1 || string(c.DialogKeys[0].Key) != dialogKey || len(c.ChallengeKeys) != 1 ||
		c.SealKeyID != c.ChallengeKeys[0].ID || string(c.NonceKey) != nonceKey {
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
		"no challenge key":       {with(devEnv, "SCSCF_CHALLENGE_KEY", ""), "SCSCF_CHALLENGE_KEY"},
		"short challenge key":    {with(devEnv, "SCSCF_CHALLENGE_KEY", challengeKey[:31]), "SCSCF_CHALLENGE_KEY"},
		"short previous":         {with(devEnv, "SCSCF_CHALLENGE_KEY_PREVIOUS", previousKey[:31]), "SCSCF_CHALLENGE_KEY_PREVIOUS"},
		"previous alone":         {with(devEnv, "SCSCF_STORE", StoreMemory, "SCSCF_CHALLENGE_KEY", "", "SCSCF_CHALLENGE_KEY_PREVIOUS", previousKey), "SCSCF_CHALLENGE_KEY_PREVIOUS"},
		"previous is current":    {with(devEnv, "SCSCF_DIALOG_KEY_PREVIOUS", dialogKey), "SCSCF_DIALOG_KEY_PREVIOUS"},
		"no nonce key":           {with(devEnv, "SCSCF_NONCE_KEY", ""), "SCSCF_NONCE_KEY"},
		"short nonce key":        {with(devEnv, "SCSCF_NONCE_KEY", nonceKey[:31]), "SCSCF_NONCE_KEY"},
		"no dialog key":          {with(devEnv, "SCSCF_DIALOG_KEY", ""), "SCSCF_DIALOG_KEY"},
		"short dialog key":       {with(devEnv, "SCSCF_DIALOG_KEY", dialogKey[:31]), "SCSCF_DIALOG_KEY"},
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
	if _, err := configure(with(devEnv, "SCSCF_STORE", StoreMemory, "SCSCF_CHALLENGE_KEY", "")); err != nil {
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
		// Narrower, but no use, and the message says why (#439 QA).
		{[]string{"SCSCF_HSS_HOST_PATTERN", "hss-1.rcs.local"}, "a pattern without the wildcard names one HSS task"},
		{[]string{"SCSCF_HSS_HOST_PATTERN", "HSS-*.RCS.LOCAL"}, "with the namespace spelt as it is"},
		{[]string{"SCSCF_EDGE_PROXY_PUBLIC_HOSTS", ""}, "SCSCF_EDGE_PROXY_PUBLIC_HOSTS is empty"},
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
	for _, kv := range [][]string{{"SCSCF_STORE", StoreMemory}, {"SCSCF_HSS_DISCOVERY", DiscoveryDNS}, {"SCSCF_DIAMETER_HOST", "scscf-a.rcs.local"}, {"SCSCF_HSS_HOST_PATTERN", "*.rcs.local"}, {"SCSCF_EDGE_PROXY_PUBLIC_HOSTS", ""}} {
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
			"0123456789abcdef", "fedcba9876543210", "abcdefghijklmnop",
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

// TestAKeysIDIsTheStartOfItsSHA256: each key is named, in what it seals or
// signs, by the first 8 hex digits of its SHA-256; the challenge key seals
// under a key of its own drawn from it, never the secret or its ID.
func TestAKeysIDIsTheStartOfItsSHA256(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	id := func(k string) string {
		sum := sha256.Sum256([]byte(k))
		return hex.EncodeToString(sum[:4])
	}
	if c.DialogKeys[0].ID != id(dialogKey) || c.ChallengeKeys[0].ID != id(challengeKey) || c.SealKeyID != id(challengeKey) {
		t.Errorf("IDs %s and %s, seal %s", c.DialogKeys[0].ID, c.ChallengeKeys[0].ID, c.SealKeyID)
	}
	seal := c.ChallengeKeys[0].Key
	if len(seal) != dynamostore.KeySize || string(seal) == challengeKey || strings.Contains(hex.EncodeToString(seal), c.SealKeyID) {
		t.Error("the challenge seal key is the secret, or holds its ID")
	}
}

// TestARotationKeepsTheReplacedKeyForWhatItSealedAndSigned: once the
// current key becomes the previous one, the new current key seals and
// signs, and the previous one, the same ID and key as before, still opens
// and verifies what it did (dynamostore and routing open and verify by
// the ID the item carries).
func TestARotationKeepsTheReplacedKeyForWhatItSealedAndSigned(t *testing.T) {
	before, err := configure(with(devEnv, "SCSCF_DIALOG_KEY", previousKey, "SCSCF_CHALLENGE_KEY", previousKey))
	if err != nil {
		t.Fatal(err)
	}
	after, err := configure(with(devEnv,
		"SCSCF_DIALOG_KEY_PREVIOUS", previousKey, "SCSCF_CHALLENGE_KEY_PREVIOUS", previousKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(after.DialogKeys) != 2 || after.DialogKeys[1].ID != before.DialogKeys[0].ID ||
		!bytes.Equal(after.DialogKeys[1].Key, before.DialogKeys[0].Key) || after.DialogKeys[0].ID == before.DialogKeys[0].ID {
		t.Errorf("dialog keys after the rotation: %v, before: %v", after.DialogKeys, before.DialogKeys)
	}
	if len(after.ChallengeKeys) != 2 || after.ChallengeKeys[1].ID != before.ChallengeKeys[0].ID ||
		!bytes.Equal(after.ChallengeKeys[1].Key, before.ChallengeKeys[0].Key) || after.SealKeyID != after.ChallengeKeys[0].ID ||
		after.SealKeyID == before.SealKeyID {
		t.Errorf("challenge keys after the rotation: %v seal %s, before: %v seal %s", after.ChallengeKeys, after.SealKeyID, before.ChallengeKeys, before.SealKeyID)
	}
}

// TestARefusedKeyIsNotPrinted: a key refused for its length is named by
// its variable, its value nowhere in the error.
func TestARefusedKeyIsNotPrinted(t *testing.T) {
	short := "s3cr3t-but-too-short-for-a-key"
	for _, name := range []string{"SCSCF_NONCE_KEY", "SCSCF_DIALOG_KEY", "SCSCF_DIALOG_KEY_PREVIOUS", "SCSCF_CHALLENGE_KEY", "SCSCF_CHALLENGE_KEY_PREVIOUS"} {
		_, err := configure(with(devEnv, name, short))
		if err == nil || !strings.Contains(err.Error(), name) || strings.Contains(err.Error(), short) || strings.Contains(err.Error(), "s3cr3t") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
