package hss

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
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
		c.PeerRealm != domain || c.SCSCFPattern != "scscf-*.rcs.local" || c.RCSASURI != "sip:rcs-as.rcs.local" ||
		c.DefaultProfile != DefaultProfileID || c.MaxAuthItems != DefaultMaxAuthItems || c.CxTimeout != DefaultCxTimeout ||
		c.SubscribersTable != "subscribers" || c.ProfilesTable != "service-profiles" || c.OriginHost != "" {
		t.Fatalf("config = %+v", c)
	}
	if len(c.Tokens.t.Admin) != 1 || len(c.Tokens.t.ACS) != 1 || len(c.Tokens.t.FT) != 1 {
		t.Fatalf("tokens = %d %d %d", len(c.Tokens.t.Admin), len(c.Tokens.t.ACS), len(c.Tokens.t.FT))
	}
}

func TestNamespaceDefaultsToTheSharedServiceNamespace(t *testing.T) {
	c, err := configure(with(devEnv, "RCS_SERVICE_NAMESPACE", "prod.internal"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Namespace != "prod.internal" || c.SCSCFPattern != "scscf-*.prod.internal" || c.RCSASURI != "sip:rcs-as.prod.internal" {
		t.Errorf("config = %+v", c)
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
		"no auth items":             {with(devEnv, "HSS_MAX_AUTH_ITEMS", "0"), "HSS_MAX_AUTH_ITEMS"},
		"no rate":                   {with(devEnv, "HSS_ACS_RATE", "0"), "HSS_ACS_RATE"},
		"no Cx timeout":             {with(devEnv, "HSS_CX_TIMEOUT", "0s"), "HSS_CX_TIMEOUT"},
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
