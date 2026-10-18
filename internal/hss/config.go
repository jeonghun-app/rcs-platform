package hss

import (
	"encoding/base64"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
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
	DataKey secret
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
	Tokens   secretTokens
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
	PushTimeout  time.Duration
}

// secret holds a configuration secret so that printing a Config cannot
// reveal it.
type secret struct{ v string }

func (secret) String() string   { return "[redacted]" }
func (secret) GoString() string { return "[redacted]" }

// secretTokens are the API tokens, which print as "[redacted]" too.
type secretTokens struct{ t Tokens }

func (secretTokens) String() string   { return "[redacted]" }
func (secretTokens) GoString() string { return "[redacted]" }

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
		DataKey:          secret{e.String("DATA_KEY", "")},
		KeyringBootstrap: e.Bool("KEYRING_BOOTSTRAP", false),
		IMSRealm:         e.String("IMS_REALM", domain),
		FTRealm:          e.String("FT_REALM", ""),
		DiameterAddr:     e.String("DIAMETER_ADDR", DefaultDiameterAddr),
		OriginHost:       e.String("DIAMETER_HOST", ""),
		// The shared Cloud Map namespace ft-server also reads, unless the
		// HSS is told otherwise.
		Namespace:            e.String("NAMESPACE", s.Shared.String("SERVICE_NAMESPACE", DefaultNamespace)),
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
		PushTimeout:          e.Duration("PUSH_TIMEOUT", DefaultPushTimeout),
	}
	c.PeerRealm = e.String("DIAMETER_PEER_REALM", c.OriginRealm)
	c.SCSCFPattern = e.String("SCSCF_HOST_PATTERN", "scscf-*."+c.Namespace)
	c.RCSASURI = e.String("RCS_AS_URI", "sip:rcs-as."+c.Namespace)

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
		e.Invalid("RCS_AS_URI", "not a SIP URI sip:host[:port]")
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
	}{{"CX_TIMEOUT", c.CxTimeout}, {"API_TIMEOUT", c.APITimeout}, {"PUSH_TIMEOUT", c.PushTimeout}} {
		if d.v <= 0 {
			e.Invalid(d.name, "must be greater than zero")
		}
	}

	switch c.Store {
	case StoreMemory:
		s.ForbidInProduction(true, "HSS_STORE=memory keeps subscribers in one task and loses them on restart")
	case StoreDynamoDB:
	default:
		e.Invalid("STORE", "not one of dynamodb, memory")
	}
	switch {
	case c.KMSKeyID != "" && c.DataKey.v != "":
		e.Invalid("DATA_KEY", "not with HSS_KMS_KEY_ID: the data key comes from KMS")
	case c.DataKey.v != "":
		if k, err := base64.StdEncoding.DecodeString(c.DataKey.v); err != nil || len(k) != keyring.DataKeySize {
			e.Invalid("DATA_KEY", "not the base64 of "+strconv.Itoa(keyring.DataKeySize)+" bytes")
		}
	case c.KMSKeyID == "" && c.Store == StoreDynamoDB:
		e.Invalid("DATA_KEY", "required with HSS_STORE=dynamodb when HSS_KMS_KEY_ID is unset")
	}
	s.ForbidInProduction(c.KMSKeyID == "",
		"HSS_KMS_KEY_ID is unset: subscriber secrets would be encrypted with a key held in the task's environment")
	s.ForbidInProduction(len(c.PeerNetworks) == 0,
		"HSS_DIAMETER_PEER_NETWORKS is unset: Diameter peers would be accepted from any source address (ADR 0007 §6)")

	c.Tokens = secretTokens{readTokens(s)}
	return c
}

// isSIPHostURI accepts an AS address without a user part, sip:host[:port].
func isSIPHostURI(v string) bool {
	host, ok := cutScheme(v)
	if !ok {
		return false
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
// ADR 0007 §4: at least 256 bits, and no token shared between callers.
func readTokens(s *runtime.Settings) Tokens {
	e := s.Env
	read := func(name string) []string {
		var out []string
		for _, v := range []string{e.String(name+"_TOKEN", ""), e.String(name+"_TOKEN_NEXT", "")} {
			if v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	t := Tokens{Admin: read("ADMIN"), ACS: read("ACS"), FT: read("FT")}
	owner := map[string]string{}
	short, shared := false, false
	for name, list := range map[string][]string{"ADMIN": t.Admin, "ACS": t.ACS, "FT": t.FT} {
		for _, v := range list {
			if len(v) < MinTokenLength {
				short = true
			}
			if o, ok := owner[v]; ok && o != name {
				shared = true
			}
			owner[v] = name
		}
	}
	s.ForbidInProduction(len(t.Admin) == 0, "HSS_ADMIN_TOKEN is unset: the provisioning API would answer 503 to operators")
	s.ForbidInProduction(short, "an HSS API token is shorter than 256 bits (43 base64url characters)")
	s.ForbidInProduction(shared, "an HSS API token is shared between callers")
	return t
}
