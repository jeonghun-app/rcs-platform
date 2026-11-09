package maap

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/chatbot"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// Defaults of the MAAP_ settings; docs/maap.md has the full table.
const (
	DefaultInternalAddr     = ":8081"
	DefaultDecodes          = 8
	DefaultRegistryTable    = "maap-registry"
	DefaultSubscribersTable = "maap-subscribers"
	DefaultRequestsTable    = "maap-requests"
	DefaultCountersTable    = "maap-counters"
	// DefaultStatusTTL is rcs-as's RCSAS_SENT_TTL default, the time a
	// notification about the message can still come (lead decision on
	// #713); #684 sets both from one parameter.
	DefaultStatusTTL = 8 * 24 * time.Hour
)

// maxAliasHost bounds MAAP_ALIAS_HOST so that the longest alias,
// sip:<alias-id>@<host>;user=rcstk with an alias ID of 128 bits in 26
// base32 characters (ADR 0009 §10), is still an identity every service
// takes (identity.MaxLength).
const maxAliasHost = identity.MaxLength - len("sip:") - 26 - len("@") - len(";user=rcstk")

// MinTokenLength is the shortest token accepted in staging and prod: 256
// bits as 43 base64url characters (ADR 0007 §4). Hex encodings need 64.
const MinTokenLength = 43

// TokenPair is one caller's current and next token (MAAP_<CALLER>_TOKEN and
// MAAP_<CALLER>_TOKEN_NEXT); either may be empty. They are secret.Keys, so
// a Config printed by mistake shows neither.
type TokenPair struct {
	Current, Next secret.Key
}

// Config is the maap configuration, read by Configure from MAAP_ and RCS_
// variables.
type Config struct {
	IMSDomain     string
	ChatbotDomain chatbot.Domain
	// AliasHost is the host of every alias, in lower case (ADR 0009 §10).
	AliasHost string
	// WebhookPorts are the ports a webhook URL may name besides 443 (§8).
	WebhookPorts []uint16
	// HTTPWebhooks lets a webhook URL be http, in dev and test only (§8).
	HTTPWebhooks bool
	// InternalWebhooks lets a webhook's host be a loopback or private IP
	// address, in dev only, for the compose stack.
	InternalWebhooks bool

	// InternalAddr is the listener of the operator API, and of rcs-as's
	// API once #683 adds it; never on the public load balancer (§7).
	InternalAddr   string
	OperatorTokens TokenPair
	// Decodes bounds the request bodies the internal listener decodes at
	// once; #683 gives the public listener a pool of its own (docs/maap.md
	// has the memory rule).
	Decodes int

	RegistryTable    string
	SubscribersTable string
	RequestsTable    string
	CountersTable    string
	// StatusTTL is how long a message's status is kept (ADR 0009 §10).
	StatusTTL time.Duration
	// StoreKey is RCS_PII_HMAC_KEY, which also keys the request digests
	// maap-requests keeps (#749 security review): a key the platform
	// already holds as a secret, unset only where production refuses it.
	StoreKey secret.Key
	// DynamoDBEndpoint replaces the AWS endpoint, for DynamoDB Local.
	DynamoDBEndpoint string
}

// Configure reads the MAAP_ settings and the shared RCS_IMS_DOMAIN and
// RCS_CHATBOT_DOMAIN, and refuses in staging and prod the ones unsafe there.
func Configure(s *runtime.Settings) Config {
	e := s.Env
	imsDomain := s.Shared.RequiredString("IMS_DOMAIN")
	c := Config{
		IMSDomain:        imsDomain,
		ChatbotDomain:    chatbot.LoadDomain(s.Shared, imsDomain),
		AliasHost:        strings.ToLower(e.RequiredString("ALIAS_HOST")),
		InternalAddr:     e.String("INTERNAL_ADDR", DefaultInternalAddr),
		Decodes:          e.Int("DECODES", DefaultDecodes),
		RegistryTable:    e.String("REGISTRY_TABLE", DefaultRegistryTable),
		SubscribersTable: e.String("SUBSCRIBERS_TABLE", DefaultSubscribersTable),
		RequestsTable:    e.String("REQUESTS_TABLE", DefaultRequestsTable),
		CountersTable:    e.String("COUNTERS_TABLE", DefaultCountersTable),
		StatusTTL:        e.Duration("STATUS_TTL", DefaultStatusTTL),
		DynamoDBEndpoint: e.String("DYNAMODB_ENDPOINT", ""),
		StoreKey:         secret.NewString(s.Shared.String("PII_HMAC_KEY", "")),
		HTTPWebhooks:     !s.Environment.Production(),
		InternalWebhooks: s.Environment == runtime.Dev,
	}
	if s.Shared.String("CHATBOT_DOMAIN", "") == "" {
		// LoadDomain takes an unset domain as "no chatbots"; maap exists
		// only to issue and serve chatbot URIs at it.
		s.Shared.Invalid("CHATBOT_DOMAIN", "required by maap")
	}
	if c.AliasHost != "" {
		if reason := aliasHostProblem(c.AliasHost, imsDomain, c.ChatbotDomain.Name()); reason != "" {
			e.Invalid("ALIAS_HOST", reason)
		}
	}
	if _, port, err := net.SplitHostPort(c.InternalAddr); err != nil {
		e.Invalid("INTERNAL_ADDR", "not host:port")
	} else if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		e.Invalid("INTERNAL_ADDR", "its port is not from 1 to 65535")
	}
	if c.Decodes < 1 {
		e.Invalid("DECODES", "must be at least 1")
	}
	if c.StatusTTL < store.IdempotencyTTL {
		// A repeat of a send gets its stored answer for 24 hours, which
		// names a message whose status must still be there.
		e.Invalid("STATUS_TTL", "shorter than the 24 hours an idempotency record is kept")
	}
	// The tables share their key form, so with one name a chatbot's
	// deletion in the registry would take the aliases' chatbot items and
	// leave their subscriber items (#753 security review). A table may be
	// named by its ARN, which DynamoDB takes too.
	for _, t := range []struct{ name, value string }{
		{"REGISTRY_TABLE", c.RegistryTable}, {"REQUESTS_TABLE", c.RequestsTable}, {"COUNTERS_TABLE", c.CountersTable},
	} {
		if tableName(c.SubscribersTable) == tableName(t.value) {
			e.Invalid("SUBSCRIBERS_TABLE", "names the table of MAAP_"+t.name)
		}
	}
	c.WebhookPorts = webhookPorts(e)
	s.ForbidInProduction(c.DynamoDBEndpoint != "", "MAAP_DYNAMODB_ENDPOINT points the registry away from DynamoDB")
	c.OperatorTokens = operatorTokens(s)
	return c
}

// aliasHostProblem says why host, in lower case, cannot be the alias host,
// or returns "". An alias at RCS_IMS_DOMAIN or under it could be an IMPU,
// and one at RCS_CHATBOT_DOMAIN or under it would fall in the chatbot range
// (ADR 0009 §2, §13). Hosts compare without regard to case (RFC 3261
// §19.1.4); the domains may be written in any case, and the IMS domain with
// a trailing dot. As chatbot.NewDomain does for the chatbot domain, the
// last label must start with a letter (RFC 3261 §25.1 toplabel), which
// refuses an IP address: §13 asks for a name in the operator's domain.
func aliasHostProblem(host, imsDomain, chatbotDomain string) string {
	if !identity.IsDomainName(host) {
		return "not a DNS name"
	}
	if top := host[strings.LastIndexByte(host, '.')+1:]; top[0] < 'a' || top[0] > 'z' {
		return "not a host name a SIP URI can carry (the last label must start with a letter)"
	}
	if len(host) > maxAliasHost {
		return "longer than " + strconv.Itoa(maxAliasHost) + " bytes, which the alias URI bound allows"
	}
	for _, d := range []struct{ name, value string }{{"RCS_IMS_DOMAIN", imsDomain}, {"RCS_CHATBOT_DOMAIN", chatbotDomain}} {
		v := strings.ToLower(strings.TrimSuffix(d.value, "."))
		if v != "" && (host == v || strings.HasSuffix(host, "."+v)) {
			return "equal to or under " + d.name
		}
	}
	return ""
}

// tableName is the table a setting names, by its name or by its ARN
// (arn:<partition>:dynamodb:<region>:<account>:table/<name>).
func tableName(v string) string {
	if rest, ok := strings.CutPrefix(v, "arn:"); ok {
		if _, name, ok := strings.Cut(rest, ":table/"); ok {
			return name
		}
	}
	return v
}

// webhookPorts reads MAAP_WEBHOOK_PORTS, a comma-separated list of ports.
func webhookPorts(e *runtime.Env) []uint16 {
	var ports []uint16
	for _, v := range e.List("WEBHOOK_PORTS", nil) {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil || n == 0 {
			e.Invalid("WEBHOOK_PORTS", "holds an item that is not a port from 1 to 65535")
			return nil
		}
		ports = append(ports, uint16(n))
	}
	return ports
}

// operatorTokens reads the operator's two tokens and applies ADR 0007 §4,
// as hss reads its own. Everywhere, a token must be printable ASCII
// without white space: a trailing newline from `echo` into Secrets Manager
// would make every request fail, since a header cannot carry it. A next
// token without a current one, or equal to it, is a rotation gone wrong
// and is refused everywhere, as msrp-relay refuses it. In staging and prod
// a token is required and each must hold 256 bits. These are maap's own settings: hss's HSS_ADMIN_TOKEN is never
// accepted here (ADR 0009 §7).
func operatorTokens(s *runtime.Settings) TokenPair {
	e := s.Env
	p := TokenPair{secret.NewString(e.String("OPERATOR_TOKEN", "")), secret.NewString(e.String("OPERATOR_TOKEN_NEXT", ""))}
	for _, t := range []struct {
		name  string
		value secret.Key
	}{{"OPERATOR_TOKEN", p.Current}, {"OPERATOR_TOKEN_NEXT", p.Next}} {
		v := t.value.RevealString()
		if !printableToken(v) {
			e.Invalid(t.name, "has white space or characters outside printable ASCII")
		}
		s.ForbidInProduction(v != "" && !strongToken(v),
			"MAAP_"+t.name+" holds less than 256 bits (64 hex digits or 43 base64url characters)")
	}
	switch {
	case p.Current.IsZero() && !p.Next.IsZero():
		e.Invalid("OPERATOR_TOKEN_NEXT", "set without MAAP_OPERATOR_TOKEN")
	case !p.Current.IsZero() && p.Current.Equal(p.Next):
		e.Invalid("OPERATOR_TOKEN_NEXT", "equal to MAAP_OPERATOR_TOKEN")
	}
	s.ForbidInProduction(p.Current.IsZero() && p.Next.IsZero(),
		"MAAP_OPERATOR_TOKEN is unset: the operator API would answer 503 to every call")
	return p
}

func printableToken(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] > '~' {
			return false
		}
	}
	return true
}

// strongToken reports whether a token can hold 256 bits: 64 hex digits, or
// MinTokenLength characters of a larger alphabet.
func strongToken(v string) bool {
	if strings.Trim(v, "0123456789abcdefABCDEF") == "" {
		return len(v) >= 64
	}
	return len(v) >= MinTokenLength
}
