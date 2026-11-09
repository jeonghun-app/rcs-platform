package maap

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

const (
	imsDomain     = "ims.mnc001.mcc001.3gppnetwork.org"
	botDomain     = "botplatform.mnc001.mcc001.3gppnetwork.org"
	aliasHost     = "alias.mnc001.mcc001.3gppnetwork.org"
	operatorToken = "operator-token-0123456789abcdefghijklmnopqrstuvwxyz"
	nextToken     = "operator-next-token-0123456789abcdefghijklmnopqrstuvwxyz"
)

var devEnv = map[string]string{
	"RCS_ENV":            "dev",
	"RCS_IMS_DOMAIN":     imsDomain,
	"RCS_CHATBOT_DOMAIN": botDomain,
	"MAAP_ALIAS_HOST":    aliasHost,
}

// prodEnv is a valid production configuration, so that a refusal of a
// change to it comes from the setting changed.
var prodEnv = with(devEnv, "RCS_ENV", "prod", "RCS_PII_HMAC_KEY", strings.Repeat("k", 32), "MAAP_OPERATOR_TOKEN", operatorToken)

// with is base with the pairs kv set, or removed when the value is empty.
func with(base map[string]string, kv ...string) map[string]string {
	m := maps.Clone(base)
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
// configuration and every problem.
func configure(env map[string]string) (Config, error) {
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	shared := runtime.NewEnv("RCS_", lookup)
	c := Configure(&runtime.Settings{Env: shared.WithPrefix("MAAP_"), Shared: shared, Environment: runtime.Environment(env["RCS_ENV"])})
	return c, shared.Err()
}

// start runs the service with env up to its admin listener, which fails,
// and returns what it logged.
func start(t *testing.T, env map[string]string) string {
	t.Helper()
	var out bytes.Buffer
	runtime.Run(context.Background(), Service(), runtime.Process{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Stdout:    &out,
		Listen:    func(string, string) (net.Listener, error) { return nil, errors.New("not in this test") },
	})
	return out.String()
}

// TestTheDefaultsAreTheDocumentedOnes compares with docs/maap.md's values,
// not the constants: 8 decodes is what the 512 MB task of the memory rule
// is sized for, and :8081 is the port of docs/api/maap.yaml.
func TestTheDefaultsAreTheDocumentedOnes(t *testing.T) {
	c, err := configure(devEnv)
	if err != nil {
		t.Fatal(err)
	}
	if c.IMSDomain != imsDomain || c.ChatbotDomain.Name() != botDomain || c.AliasHost != aliasHost || c.WebhookPorts != nil ||
		c.InternalAddr != ":8081" || c.Decodes != 8 || !c.OperatorTokens.Current.IsZero() ||
		c.RegistryTable != "maap-registry" || c.SubscribersTable != "maap-subscribers" ||
		c.RequestsTable != "maap-requests" || c.CountersTable != "maap-counters" || c.DynamoDBEndpoint != "" || !c.HTTPWebhooks || !c.InternalWebhooks {
		t.Fatalf("config = %+v", c)
	}
}

func TestEverySettingIsRead(t *testing.T) {
	c, err := configure(with(devEnv,
		"MAAP_WEBHOOK_PORTS", "8443, 9443", "MAAP_INTERNAL_ADDR", "127.0.0.1:9000", "MAAP_DECODES", "3",
		"MAAP_OPERATOR_TOKEN", operatorToken, "MAAP_OPERATOR_TOKEN_NEXT", operatorToken+"-next",
		"MAAP_REGISTRY_TABLE", "r", "MAAP_SUBSCRIBERS_TABLE", "s", "MAAP_REQUESTS_TABLE", "q", "MAAP_COUNTERS_TABLE", "c",
		"MAAP_DYNAMODB_ENDPOINT", "http://dynamodb:8000"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.WebhookPorts, []uint16{8443, 9443}) || c.InternalAddr != "127.0.0.1:9000" || c.Decodes != 3 ||
		c.OperatorTokens.Current.RevealString() != operatorToken || c.OperatorTokens.Next.RevealString() != operatorToken+"-next" ||
		c.RegistryTable != "r" || c.SubscribersTable != "s" || c.RequestsTable != "q" || c.CountersTable != "c" ||
		c.DynamoDBEndpoint != "http://dynamodb:8000" {
		t.Fatalf("config = %+v", c)
	}
}

func TestAliasHostIsComparedWithTheDomainsWithoutCase(t *testing.T) {
	for _, tc := range []struct {
		host, ims, refusal string
	}{
		{"IMS.mnc001.mcc001.3gppnetwork.org", imsDomain, "equal to or under RCS_IMS_DOMAIN"},
		{"Alias.IMS.mnc001.mcc001.3gppnetwork.org", imsDomain, "equal to or under RCS_IMS_DOMAIN"},
		{aliasHost, "ALIAS.mnc001.mcc001.3gppnetwork.org.", "equal to or under RCS_IMS_DOMAIN"},
		{"BotPlatform.mnc001.mcc001.3gppnetwork.org", imsDomain, "equal to or under RCS_CHATBOT_DOMAIN"},
		{"A.BOTPLATFORM.mnc001.mcc001.3gppnetwork.org", imsDomain, "equal to or under RCS_CHATBOT_DOMAIN"},
		{"alias host", imsDomain, "not a DNS name"},
		{"10.0.0.5", imsDomain, "not a host name a SIP URI can carry"},
		{"alias.9x", imsDomain, "not a host name a SIP URI can carry"},
		{strings.Repeat("a.", 104) + "aliasx", imsDomain, "longer than 213 bytes"},
		{strings.Repeat("a.", 104) + "alias", imsDomain, ""}, // 213 bytes
		{"ALIAS.mnc001.mcc001.3gppnetwork.org", imsDomain, ""},
		{"MNC001.mcc001.3gppnetwork.org", imsDomain, ""},                                // a parent of both
		{"xims.mnc001.mcc001.3gppnetwork.org", "ims.mnc001.mcc001.3gppnetwork.org", ""}, // a suffix, not a label
	} {
		c, err := configure(with(devEnv, "MAAP_ALIAS_HOST", tc.host, "RCS_IMS_DOMAIN", tc.ims))
		switch {
		case tc.refusal == "" && err != nil:
			t.Errorf("%s: %v", tc.host, err)
		case tc.refusal == "" && c.AliasHost != strings.ToLower(tc.host):
			t.Errorf("%s: AliasHost = %q, want it in lower case", tc.host, c.AliasHost)
		case tc.refusal != "" && (err == nil || !strings.Contains(err.Error(), "MAAP_ALIAS_HOST: "+tc.refusal)):
			t.Errorf("%s: error = %v, want %q", tc.host, err, tc.refusal)
		}
	}
}

func TestInvalidSettingsAreRefusedEverywhere(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"MAAP_ALIAS_HOST", "", "MAAP_ALIAS_HOST: required"},
		{"RCS_CHATBOT_DOMAIN", "", "RCS_CHATBOT_DOMAIN: required by maap"},
		{"RCS_CHATBOT_DOMAIN", imsDomain, "RCS_CHATBOT_DOMAIN: the same as RCS_IMS_DOMAIN"},
		{"MAAP_WEBHOOK_PORTS", "8443,0", "MAAP_WEBHOOK_PORTS: holds an item"},
		{"MAAP_WEBHOOK_PORTS", "65536", "MAAP_WEBHOOK_PORTS: holds an item"},
		{"MAAP_INTERNAL_ADDR", "8081", "MAAP_INTERNAL_ADDR: not host:port"},
		{"MAAP_INTERNAL_ADDR", "127.0.0.1:99999", "MAAP_INTERNAL_ADDR: its port is not from 1 to 65535"},
		{"MAAP_INTERNAL_ADDR", ":0", "MAAP_INTERNAL_ADDR: its port is not from 1 to 65535"},
		{"MAAP_DECODES", "0", "MAAP_DECODES: must be at least 1"},
		{"MAAP_OPERATOR_TOKEN", operatorToken + "\n", "MAAP_OPERATOR_TOKEN: has white space"},
		{"MAAP_OPERATOR_TOKEN", strings.Repeat("é", 43), "MAAP_OPERATOR_TOKEN: has white space or characters outside printable ASCII"},
		{"MAAP_OPERATOR_TOKEN", operatorToken + "\x7f", "MAAP_OPERATOR_TOKEN: has white space or characters outside printable ASCII"},
		{"MAAP_OPERATOR_TOKEN_NEXT", "a b", "MAAP_OPERATOR_TOKEN_NEXT: has white space"},
		{"MAAP_OPERATOR_TOKEN", "", "MAAP_OPERATOR_TOKEN_NEXT: set without MAAP_OPERATOR_TOKEN"},
		{"MAAP_OPERATOR_TOKEN_NEXT", operatorToken, "MAAP_OPERATOR_TOKEN_NEXT: equal to MAAP_OPERATOR_TOKEN"},
	} {
		// Both tokens are set, so that a row clearing one sees the pair.
		_, err := configure(with(devEnv, "MAAP_OPERATOR_TOKEN", operatorToken, "MAAP_OPERATOR_TOKEN_NEXT", nextToken, tc.name, tc.value))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s=%q: error = %v, want %q", tc.name, tc.value, err, tc.want)
		}
	}
}

func TestStagingAndProdRefuseTheDevelopmentDefaults(t *testing.T) {
	for _, env := range []string{"staging", "prod"} {
		base := with(prodEnv, "RCS_ENV", env)
		if c, _ := configure(base); c.HTTPWebhooks || c.InternalWebhooks {
			t.Errorf("%s allows http or internal webhooks", env)
		}
		for _, ok := range []string{operatorToken, strings.Repeat("z", 43), strings.Repeat("ab", 32)} {
			if out := start(t, with(base, "MAAP_OPERATOR_TOKEN", ok)); strings.Contains(out, "configuration rejected") {
				t.Errorf("%s: a token of %d characters was refused:\n%s", env, len(ok), out)
			}
		}
		for _, tc := range []struct {
			env  map[string]string
			want string
		}{
			{with(base, "MAAP_OPERATOR_TOKEN", ""), "MAAP_OPERATOR_TOKEN is unset"},
			{with(base, "MAAP_OPERATOR_TOKEN", strings.Repeat("z", 42)), "MAAP_OPERATOR_TOKEN holds less than 256 bits"},
			{with(base, "MAAP_OPERATOR_TOKEN", strings.Repeat("ab", 31)+"a"), "MAAP_OPERATOR_TOKEN holds less than 256 bits"},
			{with(base, "MAAP_OPERATOR_TOKEN_NEXT", "short"), "MAAP_OPERATOR_TOKEN_NEXT holds less than 256 bits"},
			{with(base, "MAAP_DYNAMODB_ENDPOINT", "http://dynamodb:8000"), "MAAP_DYNAMODB_ENDPOINT points the registry away"},
		} {
			out := start(t, tc.env)
			if !strings.Contains(out, "configuration rejected") || !strings.Contains(out, "refused in "+env+": "+tc.want) {
				t.Errorf("want %q refused in %s:\n%s", tc.want, env, out)
			}
			// The same values only warn in dev.
			if dev := start(t, with(tc.env, "RCS_ENV", "dev")); strings.Contains(dev, "configuration rejected") {
				t.Errorf("%q refused in dev:\n%s", tc.want, dev)
			}
		}
	}
}

// The test environment allows http webhooks but, unlike dev, no internal
// address: only the compose stack needs one.
func TestOnlyDevAllowsInternalWebhookAddresses(t *testing.T) {
	c, err := configure(with(devEnv, "RCS_ENV", "test"))
	if err != nil || !c.HTTPWebhooks || c.InternalWebhooks {
		t.Fatalf("test: %+v, %v", c, err)
	}
}
