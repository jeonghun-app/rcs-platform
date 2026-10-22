package hss

import (
	"cmp"
	"encoding/base64"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	secretkey "github.com/jeonghun-app/rcs-platform/internal/secret"
)

// The HSS_STORE values.
const (
	StoreDynamoDB = "dynamodb"
	StoreMemory   = "memory"
)

// Defaults of the HSS_ settings; docs/hss.md has the full table.
const (
	DefaultDiameterAddr     = ":3868"
	DefaultAPIAddr          = ":8081"
	DefaultNamespace        = "rcs.local"
	DefaultSubscribersTable = "subscribers"
	DefaultProfilesTable    = "service-profiles"
	DefaultProfileID        = "rcs-default"
	// DefaultStartTimeout bounds opening the store and the keyring.
	DefaultStartTimeout = 60 * time.Second
	// MaxStartTimeout keeps HSS_START_TIMEOUT within what a container
	// health check can wait for: /healthz fails until the start-up ends,
	// and ECS allows a startPeriod of at most 300 s, so a longer start-up
	// would have a task that is still starting replaced. The margin leaves
	// room for the check's interval and retries.
	MaxStartTimeout = 240 * time.Second
)

// Config is the HSS configuration, read by Configure from HSS_ variables.
// Secrets in it print as "[redacted]".
type Config struct {
	Store            string
	SubscribersTable string
	ProfilesTable    string
	DynamoDBEndpoint string
	KMSKeyID         string
	// DataKey is the local data key (dev and test), nil with KMS.
	DataKey secretkey.Key
	// KeyringBootstrap allows creating a first data key although
	// subscriptions are stored (see openStore).
	KeyringBootstrap bool

	IMSRealm string
	FTRealm  string

	DiameterAddr string
	// OriginHost is this task's Diameter identity: HSS_DIAMETER_HOST, or
	// hss-<random>.<namespace> chosen at start (ADR 0005).
	OriginHost   string
	Namespace    string
	OriginRealm  string
	PeerRealm    string
	PeerNetworks []netip.Prefix
	SCSCFPattern string
	SCSCFNames   []string

	APIAddr  string
	Tokens   Tokens
	ACSRate  int
	ACSBurst int
	// DefaultProfile is the profile of subscriptions created without one;
	// CreateDefaultProfile creates it at start as DefaultRCSProfile when it
	// does not exist.
	DefaultProfile       string
	CreateDefaultProfile bool
	RCSASURI             string

	MaxAuthItems int
	CxTimeout    time.Duration
	APITimeout   time.Duration
	StartTimeout time.Duration
	PushTimeout  time.Duration
}

// Configure reads the HSS_ settings and refuses, in staging and prod, the
// ones that are unsafe there (docs/architecture.md §8, ADR 0007).
func Configure(s *runtime.Settings) Config {
	e := s.Env
	domain := s.Shared.RequiredString("IMS_DOMAIN")
	c := Config{
		Store:            e.String("STORE", StoreDynamoDB),
		SubscribersTable: e.String("SUBSCRIBERS_TABLE", DefaultSubscribersTable),
		ProfilesTable:    e.String("PROFILES_TABLE", DefaultProfilesTable),
		DynamoDBEndpoint: e.String("DYNAMODB_ENDPOINT", ""),
		KMSKeyID:         e.String("KMS_KEY_ID", ""),
		DataKey:          secretkey.NewString(e.String("DATA_KEY", "")),
		KeyringBootstrap: e.Bool("KEYRING_BOOTSTRAP", false),
		IMSRealm:         e.String("IMS_REALM", domain),
		FTRealm:          e.String("FT_REALM", ""),
		DiameterAddr:     e.String("DIAMETER_ADDR", DefaultDiameterAddr),
		OriginHost:       e.String("DIAMETER_HOST", ""),
		// The shared Cloud Map namespace ft-server also reads, unless the
		// HSS is told otherwise.
		Namespace:            e.String("NAMESPACE", cmp.Or(s.ServiceNamespace(), DefaultNamespace)),
		OriginRealm:          e.String("DIAMETER_REALM", domain),
		PeerNetworks:         e.CIDRs("DIAMETER_PEER_NETWORKS", nil),
		SCSCFNames:           e.List("SCSCF_NAMES", nil),
		APIAddr:              e.String("API_ADDR", DefaultAPIAddr),
		ACSRate:              e.Int("ACS_RATE", DefaultACSRate),
		ACSBurst:             e.Int("ACS_BURST", DefaultACSBurst),
		DefaultProfile:       e.String("DEFAULT_PROFILE", DefaultProfileID),
		CreateDefaultProfile: e.Bool("CREATE_DEFAULT_PROFILE", true),
		MaxAuthItems:         e.Int("MAX_AUTH_ITEMS", DefaultMaxAuthItems),
		CxTimeout:            e.Duration("CX_TIMEOUT", DefaultCxTimeout),
		APITimeout:           e.Duration("API_TIMEOUT", DefaultAPIStoreTimeout),
		StartTimeout:         e.Duration("START_TIMEOUT", DefaultStartTimeout),
		PushTimeout:          e.Duration("PUSH_TIMEOUT", DefaultPushTimeout),
	}
	c.PeerRealm = e.String("DIAMETER_PEER_REALM", c.OriginRealm)
	c.SCSCFPattern = e.String("SCSCF_HOST_PATTERN", "scscf-*."+c.Namespace)
	// Over TCP, rcs-as's only SIP transport: a URI without one would be
	// sent over UDP (RFC 3263 §4.1), which scscf has no listener for (#14).
	c.RCSASURI = e.String("RCS_AS_URI", "sip:rcs-as."+c.Namespace+";transport=tcp")

	for _, addr := range []struct{ name, v string }{{"DIAMETER_ADDR", c.DiameterAddr}, {"API_ADDR", c.APIAddr}} {
		if _, _, err := net.SplitHostPort(addr.v); err != nil {
			e.Invalid(addr.name, "not host:port")
		}
	}
	if !identity.IsDomainName(c.Namespace) {
		e.Invalid("NAMESPACE", "not a domain name")
	}
	if c.OriginHost != "" && !identity.IsDomainName(c.OriginHost) {
		e.Invalid("DIAMETER_HOST", "not a domain name")
	}
	if domain != "" && !identity.IsDomainName(c.OriginRealm) {
		e.Invalid("DIAMETER_REALM", "not a domain name")
	}
	if c.FTRealm != "" && c.FTRealm == c.IMSRealm {
		// One HA1 per realm: the same realm for both would make an FT
		// credential a SIP Digest credential, and ft-server's HA1 one that
		// registers to the IMS core.
		e.Invalid("FT_REALM", "must differ from the IMS realm")
	}
	if err := ValidProfileID(c.DefaultProfile); err != nil {
		e.Invalid("DEFAULT_PROFILE", err.Error())
	}
	if c.CreateDefaultProfile && !isSIPHostURI(c.RCSASURI) {
		e.Invalid("RCS_AS_URI", "not a SIP URI sip:host[:port][;transport=tcp|tls]")
	}
	if c.MaxAuthItems < 1 || c.MaxAuthItems > 16 {
		e.Invalid("MAX_AUTH_ITEMS", "must be 1 to 16")
	}
	if c.ACSRate <= 0 || c.ACSBurst <= 0 {
		e.Invalid("ACS_RATE", "rate and burst must be positive")
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"CX_TIMEOUT", c.CxTimeout}, {"API_TIMEOUT", c.APITimeout}, {"START_TIMEOUT", c.StartTimeout}, {"PUSH_TIMEOUT", c.PushTimeout}} {
		if d.v <= 0 {
			e.Invalid(d.name, "must be greater than zero")
		}
	}
	if c.APITimeout > MaxAPITimeout {
		// The store work of a change and its pushes' budget together stay
		// within the API's write timeout (#491).
		e.Invalid("API_TIMEOUT", "must be at most 10s")
	}
	if c.PushTimeout > MaxPushTimeout {
		// A PPR and what its refusal brings may take twice it, and all of
		// a change's pushes together at most PushBudget, within the API's
		// write timeout (#491).
		e.Invalid("PUSH_TIMEOUT", "must be at most 8s")
	}
	if c.StartTimeout > MaxStartTimeout {
		e.Invalid("START_TIMEOUT", "must be at most 240s, which a container health check's startPeriod (300 s at most) can cover")
	}

	switch c.Store {
	case StoreMemory:
		s.ForbidInProduction(true, "HSS_STORE=memory keeps subscribers in one task and loses them on restart")
	case StoreDynamoDB:
	default:
		e.Invalid("STORE", "not one of dynamodb, memory")
	}
	switch {
	case c.KMSKeyID != "" && c.DataKey.RevealString() != "":
		e.Invalid("DATA_KEY", "not with HSS_KMS_KEY_ID: the data key comes from KMS")
	case c.DataKey.RevealString() != "":
		if k, err := base64.StdEncoding.DecodeString(c.DataKey.RevealString()); err != nil || len(k) != keyring.DataKeySize {
			e.Invalid("DATA_KEY", "not the base64 of "+strconv.Itoa(keyring.DataKeySize)+" bytes")
		}
	case c.KMSKeyID == "" && c.Store == StoreDynamoDB:
		e.Invalid("DATA_KEY", "required with HSS_STORE=dynamodb when HSS_KMS_KEY_ID is unset")
	}
	s.ForbidInProduction(c.KMSKeyID == "",
		"HSS_KMS_KEY_ID is unset: subscriber secrets would be encrypted with a key held in the task's environment")
	s.ForbidInProduction(len(c.PeerNetworks) == 0,
		"HSS_DIAMETER_PEER_NETWORKS is unset: Diameter peers would be accepted from any source address (ADR 0007 §6)")
	for _, n := range c.PeerNetworks {
		s.ForbidInProduction(n.Bits() == 0,
			"HSS_DIAMETER_PEER_NETWORKS holds a /0 prefix: it restricts no source address (ADR 0007 §6)")
	}

	c.Tokens = readTokens(s)
	return c
}

// isSIPHostURI accepts an AS address without a user part,
// sip:host[:port], with at most a transport parameter of tcp or tls.
func isSIPHostURI(v string) bool {
	host, ok := cutScheme(v)
	if !ok {
		return false
	}
	if h, params, found := strings.Cut(host, ";"); found {
		name, value, _ := strings.Cut(params, "=")
		if !strings.EqualFold(name, "transport") || !(strings.EqualFold(value, "tcp") || strings.EqualFold(value, "tls")) {
			return false
		}
		host = h
	}
	if h, port, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return false
		}
		host = h
	}
	return identity.IsDomainName(host)
}

func cutScheme(v string) (string, bool) {
	for _, scheme := range []string{"sip:", "sips:"} {
		if len(v) > len(scheme) && v[:len(scheme)] == scheme {
			return v[len(scheme):], true
		}
	}
	return "", false
}

// readTokens reads the current and next token of each caller and applies
// ADR 0007 §4. Everywhere, a token must be printable ASCII without white
// space: a trailing newline from `echo` into Secrets Manager would make
// every request fail, since a header cannot carry it. In staging and prod a
// token must hold 256 bits (64 hex digits, or 43 characters of base64 or
// another larger alphabet), no token may serve two callers, the admin needs
// a current token, and no caller may have a next token without a current
// one.
func readTokens(s *runtime.Settings) Tokens {
	e := s.Env
	read := func(name string) TokenPair {
		p := TokenPair{secretkey.NewString(e.String(name+"_TOKEN", "")), secretkey.NewString(e.String(name+"_TOKEN_NEXT", ""))}
		for _, v := range []struct {
			name  string
			value secretkey.Key
		}{{name + "_TOKEN", p.Current}, {name + "_TOKEN_NEXT", p.Next}} {
			if !printableToken(v.value.RevealString()) {
				e.Invalid(v.name, "has white space or characters outside printable ASCII")
			}
		}
		s.ForbidInProduction(p.Current.IsZero() && !p.Next.IsZero(),
			"HSS_"+name+"_TOKEN_NEXT is set without HSS_"+name+"_TOKEN: the rotation is in an unexpected state")
		return p
	}
	t := Tokens{Admin: read("ADMIN"), ACS: read("ACS"), FT: read("FT")}
	owner := map[string]string{}
	weak, shared := false, false
	for name, p := range map[string]TokenPair{"ADMIN": t.Admin, "ACS": t.ACS, "FT": t.FT} {
		for _, k := range []secretkey.Key{p.Current, p.Next} {
			if k.IsZero() {
				continue
			}
			v := k.RevealString()
			if !strongToken(v) {
				weak = true
			}
			if o, ok := owner[v]; ok && o != name {
				shared = true
			}
			owner[v] = name
		}
	}
	s.ForbidInProduction(t.Admin.Current.IsZero(), "HSS_ADMIN_TOKEN is unset: the provisioning API would answer 503 to operators")
	s.ForbidInProduction(weak, "an HSS API token holds less than 256 bits (64 hex digits or 43 base64url characters)")
	s.ForbidInProduction(shared, "an HSS API token is shared between callers")
	return t
}

func printableToken(v string) bool {
	for i := 0; i < len(v); i++ {
		if v[i] <= ' ' || v[i] > '~' {
			return false
		}
	}
	return true
}

// strongToken reports whether a token can hold 256 bits: a token of hex
// digits only needs 64 of them, any other needs MinTokenLength characters
// (base64url carries 6 bits a character).
func strongToken(v string) bool {
	if strings.Trim(v, "0123456789abcdefABCDEF") == "" {
		return len(v) >= 64
	}
	return len(v) >= MinTokenLength
}
