package hss

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

var devEnv = map[string]string{
	"RCS_ENV":         "dev",
	"RCS_IMS_DOMAIN":  domain,
	"HSS_STORE":       "memory",
	"HSS_FT_REALM":    ftRealm,
	"HSS_ADMIN_TOKEN": adminToken,
	"HSS_ACS_TOKEN":   acsToken,
	"HSS_FT_TOKEN":    ftToken,
}

// prodEnv is a configuration production accepts.
var prodEnv = with(devEnv,
	"RCS_ENV", "prod", "RCS_PII_HMAC_KEY", strings.Repeat("k", 32),
	"HSS_STORE", "dynamodb", "HSS_KMS_KEY_ID", "alias/hss", "HSS_DIAMETER_PEER_NETWORKS", "10.0.0.0/16",
	"HSS_ADMIN_TOKEN_NEXT", adminTokenNext)

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

func configure(env map[string]string) (Config, error) {
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	c := Configure(&runtime.Settings{Env: shared.WithPrefix("HSS_"), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	return c, shared.Err()
}

func TestDevConfigurationIsReadWithDefaults(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.DiameterAddr != DefaultDiameterAddr || c.APIAddr != DefaultAPIAddr || c.IMSRealm != domain || c.OriginRealm != domain ||
		c.PeerRealm != domain || c.SCSCFPattern != "scscf-*.rcs.local" || c.RCSASURI != "sip:rcs-as.rcs.local;transport=tcp" ||
		c.DefaultProfile != DefaultProfileID || c.MaxAuthItems != DefaultMaxAuthItems || c.CxTimeout != DefaultCxTimeout ||
		c.SubscribersTable != "subscribers" || c.ProfilesTable != "service-profiles" || c.OriginHost != "" {
		t.Fatalf("config = %+v", c)
	}
	if c.Tokens.tokens().Admin.Current != adminToken || c.Tokens.tokens().ACS.Current != acsToken || c.Tokens.tokens().FT.Current != ftToken || c.Tokens.tokens().Admin.Next != "" {
		t.Fatal("tokens not read")
	}
}

func TestNamespaceDefaultsToTheSharedServiceNamespace(t *testing.T) {
	c, err := configure(with(devEnv, "RCS_SERVICE_NAMESPACE", "prod.internal"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Namespace != "prod.internal" || c.SCSCFPattern != "scscf-*.prod.internal" || c.RCSASURI != "sip:rcs-as.prod.internal;transport=tcp" {
		t.Errorf("config = %+v", c)
	}
	// The shared value is used as the runtime normalises it, as the other
	// services use it.
	c, err = configure(with(devEnv, "RCS_SERVICE_NAMESPACE", "Prod.Internal."))
	if err != nil || c.Namespace != "prod.internal" || c.SCSCFPattern != "scscf-*.prod.internal" {
		t.Fatalf("normalised namespace: %+v, %v", c, err)
	}
	c, err = configure(with(devEnv, "RCS_SERVICE_NAMESPACE", "prod.internal", "HSS_NAMESPACE", "hss.internal"))
	if err != nil || c.Namespace != "hss.internal" {
		t.Errorf("HSS_NAMESPACE does not win: %v %+v", err, c)
	}
}

func TestConfigNeverPrintsItsSecrets(t *testing.T) {
	c, err := configure(with(devEnv, "HSS_DATA_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{c.Tokens.String(), c.DataKey.String(), c.Tokens.GoString(), c.DataKey.GoString()} {
		if s != "[redacted]" {
			t.Errorf("printed %q", s)
		}
	}
	// Every verb, valid or not, over the whole Config: an invalid one, %p
	// or %w, calls no method and prints the fields (#506).
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%t", "%x", "%o", "%b", "%p", "%w", "%c", "%e"} {
		for _, v := range []any{c, &c} {
			out := fmt.Sprintf(verb, v)
			for _, secret := range []string{adminToken[:12], acsToken[:12], ftToken[:12], key[:12], strings.Trim(fmt.Sprint([]byte(adminToken[:6])), "[]"), fmt.Sprintf("%x", adminToken[:6])} {
				if strings.Contains(out, secret) {
					t.Errorf("%s printed a secret: %s", verb, out)
				}
			}
		}
	}
}

func TestInvalidSettingsAreReported(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"FT realm is the IMS realm": {with(devEnv, "HSS_FT_REALM", domain), "HSS_FT_REALM"},
		"bad Diameter address":      {with(devEnv, "HSS_DIAMETER_ADDR", "3868"), "HSS_DIAMETER_ADDR"},
		"bad API address":           {with(devEnv, "HSS_API_ADDR", "nope"), "HSS_API_ADDR"},
		"bad namespace":             {with(devEnv, "HSS_NAMESPACE", "a..b"), "HSS_NAMESPACE"},
		"bad origin host":           {with(devEnv, "HSS_DIAMETER_HOST", "hss_1"), "HSS_DIAMETER_HOST"},
		"bad store":                 {with(devEnv, "HSS_STORE", "redis"), "HSS_STORE"},
		"short data key":            {with(devEnv, "HSS_DATA_KEY", "c2hvcnQ="), "HSS_DATA_KEY"},
		"data key with KMS":         {with(devEnv, "HSS_DATA_KEY", key, "HSS_KMS_KEY_ID", "alias/hss"), "HSS_DATA_KEY"},
		"DynamoDB without a key":    {with(devEnv, "HSS_STORE", "dynamodb"), "HSS_DATA_KEY"},
		"bad default profile":       {with(devEnv, "HSS_DEFAULT_PROFILE", "Bad"), "HSS_DEFAULT_PROFILE"},
		"bad rcs-as URI":            {with(devEnv, "HSS_RCS_AS_URI", "http://rcs-as"), "HSS_RCS_AS_URI"},
		"bad rcs-as port":           {with(devEnv, "HSS_RCS_AS_URI", "sip:rcs-as:99999"), "HSS_RCS_AS_URI"},
		"rcs-as over UDP":           {with(devEnv, "HSS_RCS_AS_URI", "sip:rcs-as;transport=udp"), "HSS_RCS_AS_URI"},
		"rcs-as with other params":  {with(devEnv, "HSS_RCS_AS_URI", "sip:rcs-as;lr"), "HSS_RCS_AS_URI"},
		"no auth items":             {with(devEnv, "HSS_MAX_AUTH_ITEMS", "0"), "HSS_MAX_AUTH_ITEMS"},
		"no rate":                   {with(devEnv, "HSS_ACS_RATE", "0"), "HSS_ACS_RATE"},
		"no Cx timeout":             {with(devEnv, "HSS_CX_TIMEOUT", "0s"), "HSS_CX_TIMEOUT"},
		"start-up beyond 240 s":     {with(devEnv, "HSS_START_TIMEOUT", "241s"), "HSS_START_TIMEOUT"},
		"bad networks":              {with(devEnv, "HSS_DIAMETER_PEER_NETWORKS", "10.0.0.1/8"), "HSS_DIAMETER_PEER_NETWORKS"},
		"no IMS domain":             {with(devEnv, "RCS_IMS_DOMAIN", ""), "RCS_IMS_DOMAIN"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := configure(c.env)
			var ce *runtime.ConfigError
			if !errors.As(err, &ce) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want one naming %s", err, c.want)
			}
		})
	}
	c, err := configure(with(devEnv, "HSS_RCS_AS_URI", "sip:rcs-as.rcs.local:5070", "HSS_CREATE_DEFAULT_PROFILE", "false", "HSS_DEFAULT_PROFILE", "mine"))
	if err != nil || c.CreateDefaultProfile || c.DefaultProfile != "mine" || c.RCSASURI != "sip:rcs-as.rcs.local:5070" {
		t.Errorf("explicit settings: %v %+v", err, c)
	}
	if c, err := configure(with(devEnv, "HSS_START_TIMEOUT", "240s")); err != nil || c.StartTimeout != 240*time.Second {
		t.Errorf("a 240 s start-up: %v %v", err, c.StartTimeout)
	}
}

// startUp runs the process far enough to see whether the configuration is
// accepted: an accepted one fails at the admin listener instead.
func startUp(env map[string]string) (int, string) {
	var out bytes.Buffer
	code := runtime.Run(context.Background(), Service(), runtime.Process{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Stdout:    &out, Stderr: &out,
		Listen: func(string, string) (net.Listener, error) { return nil, errors.New("no listener in this test") },
		Now:    time.Now,
	})
	return code, out.String()
}

func TestProductionRefusesUnsafeSettings(t *testing.T) {
	code, out := startUp(prodEnv)
	if code != runtime.ExitFailure || strings.Contains(out, "configuration rejected") || !strings.Contains(out, "admin listener failed") {
		t.Fatalf("a safe production configuration: %d\n%s", code, out)
	}
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"memory store":             {with(prodEnv, "HSS_STORE", "memory", "HSS_KMS_KEY_ID", ""), "HSS_STORE=memory"},
		"no KMS key":               {with(prodEnv, "HSS_KMS_KEY_ID", "", "HSS_DATA_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32))), "HSS_KMS_KEY_ID"},
		"no Diameter networks":     {with(prodEnv, "HSS_DIAMETER_PEER_NETWORKS", ""), "HSS_DIAMETER_PEER_NETWORKS"},
		"no admin token":           {with(prodEnv, "HSS_ADMIN_TOKEN", "", "HSS_ADMIN_TOKEN_NEXT", ""), "HSS_ADMIN_TOKEN"},
		"short token":              {with(prodEnv, "HSS_FT_TOKEN", "short"), "256 bits"},
		"token shared with admin":  {with(prodEnv, "HSS_ACS_TOKEN", adminToken), "shared between callers"},
		"token shared by services": {with(prodEnv, "HSS_FT_TOKEN_NEXT", acsToken), "shared between callers"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out := startUp(c.env)
			if code != runtime.ExitFailure || !strings.Contains(out, "configuration rejected") || !strings.Contains(out, c.want) {
				t.Fatalf("exit %d, output:\n%s", code, out)
			}
			for _, tok := range []string{adminToken, acsToken, ftToken} {
				if strings.Contains(out, tok) {
					t.Error("a token reached the output")
				}
			}
		})
	}
}

func TestTokenStrengthBoundaryInProduction(t *testing.T) {
	for name, c := range map[string]struct {
		token   string
		refused bool
	}{
		"42 base64url characters": {strings.Repeat("g", 42), true},
		"43 base64url characters": {strings.Repeat("g", 43), false},
		"63 hex digits":           {strings.Repeat("f", 63), true},
		"64 hex digits":           {strings.Repeat("f", 64), false},
	} {
		_, out := startUp(with(prodEnv, "HSS_FT_TOKEN", c.token))
		if got := strings.Contains(out, "256 bits"); got != c.refused {
			t.Errorf("%s: refused = %v, want %v", name, got, c.refused)
		}
	}
}

func TestTokensWithWhiteSpaceAreRefusedEverywhere(t *testing.T) {
	for _, v := range []string{ftToken + "\n", "a " + ftToken, ftToken + "\t", ftToken + "\u00e9"} {
		_, err := configure(with(devEnv, "HSS_FT_TOKEN_NEXT", v))
		if err == nil || !strings.Contains(err.Error(), "HSS_FT_TOKEN_NEXT") {
			t.Errorf("token %q: %v", v, err)
		}
	}
}

func TestProductionRefusesOpenNetworksAndHalfRotations(t *testing.T) {
	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"IPv4 /0":              {with(prodEnv, "HSS_DIAMETER_PEER_NETWORKS", "0.0.0.0/0"), "/0 prefix"},
		"IPv6 /0":              {with(prodEnv, "HSS_DIAMETER_PEER_NETWORKS", "10.0.0.0/16,::/0"), "/0 prefix"},
		"next without current": {with(prodEnv, "HSS_ACS_TOKEN", "", "HSS_ACS_TOKEN_NEXT", acsToken), "HSS_ACS_TOKEN_NEXT is set without"},
	} {
		code, out := startUp(c.env)
		if code != runtime.ExitFailure || !strings.Contains(out, "configuration rejected") || !strings.Contains(out, c.want) {
			t.Errorf("%s: exit %d\n%s", name, code, out)
		}
	}
}
