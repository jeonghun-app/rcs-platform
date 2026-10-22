package scscf

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/cxclient"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/regevent"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/registrar"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/routing"
	"github.com/jeonghun-app/rcs-platform/internal/scscf/state/dynamostore"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
)

// HSS discovery modes (SCSCF_HSS_DISCOVERY), as icscf's.
const (
	// DiscoveryCloudMap lists the HSS tasks with Cloud Map.
	DiscoveryCloudMap = "cloudmap"
	// DiscoveryDNS resolves hss.<namespace>, as the compose stack serves it.
	DiscoveryDNS = "dns"
)

// Stores (SCSCF_STORE).
const (
	// StoreDynamoDB keeps the shared state in DynamoDB (ADR 0005).
	StoreDynamoDB = "dynamodb"
	// StoreMemory keeps it in the task, for development: no other task
	// sees it, and a restart loses it.
	StoreMemory = "memory"
)

// Defaults of the settings in docs/scscf.md.
const (
	DefaultCoreAddr  = "0.0.0.0:5060"
	DefaultNamespace = "rcs.local"
	// DefaultPCSCFCorePort is the port of pcscf's core listener
	// (RCS_PCSCF_CORE_PORT), which pcscf listens on and scscf lets the
	// requests of a dialog go to.
	DefaultPCSCFCorePort = 5070
	DefaultCxTimeout     = cxclient.DefaultRequestTimeout
	DefaultSweepInterval = registrar.DefaultSweepInterval
	DefaultSweepLimit    = registrar.DefaultSweepLimit
	// stopMargin is what Run needs after the drain: the router's and the
	// notifier's queues, the Cx client and the transport, inside
	// RCS_SHUTDOWN_TIMEOUT.
	stopMargin = 5 * time.Second
	// returnMargin is the end of stopMargin Run keeps for returning, so that
	// it ends before the runtime's own deadline, which the default drain
	// puts at the end of stopMargin (#439 QA). It holds the proxy's Close,
	// a late end of the last wait (lateWake) and the goodbye's floor.
	returnMargin = 1500 * time.Millisecond
	// lateWake is how late the stop's last wait was seen to end on a
	// loaded host, where the process may not run for a while: the goodbye
	// up to 1.35 s past its deadline under the race detector, 2 CPUs and 16
	// busy loops (#502, #549 code review). returnMargin is sized from it.
	lateWake = 1350 * time.Millisecond
	// goodbyeFloor is the least time the goodbye has to send its DPR, past
	// stopBy if it starts that late (goodbyeDeadline).
	goodbyeFloor = 100 * time.Millisecond
	// closeMargin is the part of stopMargin before returnMargin kept for
	// the closes: the transport's, the sends the router gave up on, and the
	// Cx client's goodbye to the HSS. The sends get all of it but
	// goodbyeMargin: the transport's Close cuts a dial in progress (#474),
	// so they return at once, within 1 ms in 86 of 90 loaded stops and
	// 1.0 s at the slowest (#502). One still under way is waited for by the
	// proxy's Close.
	closeMargin = 2 * time.Second
	// goodbyeMargin is the end of closeMargin the Cx client's goodbye (DPR)
	// always has, however long the router's sends take to return (#502).
	goodbyeMargin = time.Second
	// coreDialTimeout bounds opening a connection to a P-CSCF, an
	// application server or the I-CSCF: inside the VPC, where a stopped
	// task drops the SYN, as icscf's.
	coreDialTimeout = 2 * time.Second
)

// ServiceConfig is scscf's configuration (docs/scscf.md), read by Configure
// from SCSCF_ variables.
type ServiceConfig struct {
	// HomeDomain is RCS_IMS_DOMAIN, the home network and the Digest
	// realm; Namespace the Cloud Map namespace the services are found in.
	HomeDomain string
	Namespace  string
	// CoreAddr is the core listener, the only one: pcscf, icscf and the
	// application servers reach scscf, clients never do (ADR 0007).
	// CoreHost is this task's address on it.
	CoreAddr string
	CoreHost netip.Addr

	// OriginHost is the Diameter identity: SCSCF_DIAMETER_HOST, or
	// scscf-<random>.<namespace> chosen at start (ADR 0005). OriginRealm is
	// the IMS core's realm, HSSRealm the HSS's.
	OriginHost  string
	OriginRealm string
	HSSRealm    string
	// HSSDiscovery is DiscoveryCloudMap or DiscoveryDNS; HSSHostPattern the
	// Origin-Host every HSS task must have, never empty.
	HSSDiscovery   string
	HSSHostPattern string
	CxTimeout      time.Duration

	// Store is StoreDynamoDB or StoreMemory, with the DynamoDB tables and,
	// for DynamoDB Local, its endpoint.
	Store              string
	RegistrationsTable string
	ChallengesTable    string
	SubscriptionsTable string
	DynamoDBEndpoint   string
	// ChallengeKeys seal the challenges in DynamoDB, SealKeyID naming the
	// one that seals, the current; the previous one only opens
	// (dynamostore.Config).
	ChallengeKeys []dynamostore.ChallengeKey
	SealKeyID     string
	// NonceKey authenticates Digest nonces, and DialogKeys sign the
	// Record-Route values and iFC positions; the same on every task.
	NonceKey   secret.Key
	DialogKeys []routing.DialogKey

	// ICSCF is where an originating request goes once its chain is done.
	ICSCF sip.URI
	// PCSCFCorePort is RCS_PCSCF_CORE_PORT; ApplicationServers and
	// EdgeProxyPublicHosts are routing.Config's.
	PCSCFCorePort        int
	ApplicationServers   []sip.URI
	EdgeProxyPublicHosts []string
	// ASTimeout, ThirdPartyTimeout and MaxThirdParty are routing.Config's,
	// NotifyTimeout regevent.Config's; 0 is each package's default.
	ASTimeout         time.Duration
	ThirdPartyTimeout time.Duration
	MaxThirdParty     int
	NotifyTimeout     time.Duration
	// SweepInterval and SweepLimit drive the registration and subscription
	// sweeps.
	SweepInterval time.Duration
	SweepLimit    int

	// DrainTimeout bounds how long a stop waits for the requests in
	// progress; by default RCS_SHUTDOWN_TIMEOUT less what the rest of the
	// stop needs.
	DrainTimeout time.Duration
	// MaxServerTransactions and MaxServerTransactionBytes bound the server
	// transactions scscf holds (#37).
	MaxServerTransactions     int
	MaxServerTransactionBytes int64
}

// A ServiceConfig prints as a placeholder, under every valid verb of fmt,
// log/slog and encoding/json: it holds NonceKey, the dialog keys and the
// challenge keys, which must never reach an output. The key types redact
// themselves too, for when one is printed on its own, and hold their bytes
// in a secret.Key, which an invalid verb, one that calls no method, does
// not show either (#455).
func (c ServiceConfig) String() string { return "scscf.ServiceConfig{[redacted]}" }

func (c ServiceConfig) GoString() string             { return c.String() }
func (c ServiceConfig) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, c.String()) }
func (c ServiceConfig) LogValue() slog.Value         { return slog.StringValue(c.String()) }
func (c ServiceConfig) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

// interfaceAddrs finds this task's addresses; tests replace it.
var interfaceAddrs = net.InterfaceAddrs

// Configure reads the SCSCF_ settings (docs/scscf.md) and refuses, in
// staging and prod, the ones that are unsafe there.
func Configure(s *runtime.Settings) ServiceConfig {
	e := s.Env
	domain := s.Shared.RequiredString("IMS_DOMAIN")
	c := ServiceConfig{
		HomeDomain:   domain,
		Namespace:    e.String("NAMESPACE", cmp.Or(s.ServiceNamespace(), DefaultNamespace)),
		CoreAddr:     e.String("CORE_ADDR", DefaultCoreAddr),
		OriginHost:   e.String("DIAMETER_HOST", ""),
		OriginRealm:  e.String("DIAMETER_REALM", domain),
		HSSDiscovery: e.String("HSS_DISCOVERY", DiscoveryCloudMap),
		CxTimeout:    e.Duration("CX_TIMEOUT", DefaultCxTimeout),

		Store:              e.String("STORE", StoreDynamoDB),
		RegistrationsTable: e.String("REGISTRATIONS_TABLE", dynamostore.DefaultRegistrationsTable),
		ChallengesTable:    e.String("CHALLENGES_TABLE", dynamostore.DefaultChallengesTable),
		SubscriptionsTable: e.String("SUBSCRIPTIONS_TABLE", dynamostore.DefaultSubscriptionsTable),
		DynamoDBEndpoint:   e.String("DYNAMODB_ENDPOINT", ""),

		PCSCFCorePort:        s.Shared.Int("PCSCF_CORE_PORT", DefaultPCSCFCorePort),
		EdgeProxyPublicHosts: e.List("EDGE_PROXY_PUBLIC_HOSTS", nil),
		ASTimeout:            e.Duration("AS_TIMEOUT", routing.DefaultASTimeout),
		ThirdPartyTimeout:    e.Duration("THIRD_PARTY_TIMEOUT", routing.DefaultThirdPartyTimeout),
		MaxThirdParty:        e.Int("MAX_THIRD_PARTY", routing.DefaultMaxThirdParty),
		NotifyTimeout:        e.Duration("NOTIFY_TIMEOUT", regevent.DefaultNotifyTimeout),
		SweepInterval:        e.Duration("SWEEP_INTERVAL", DefaultSweepInterval),
		SweepLimit:           e.Int("SWEEP_LIMIT", DefaultSweepLimit),

		MaxServerTransactions:     e.Int("MAX_SERVER_TRANSACTIONS", transaction.DefaultMaxServerTransactions),
		MaxServerTransactionBytes: int64(e.Int("MAX_SERVER_TRANSACTION_BYTES", transaction.DefaultMaxServerTransactionBytes)),
	}
	c.HSSRealm = e.String("HSS_REALM", c.OriginRealm)
	c.HSSHostPattern = e.String("HSS_HOST_PATTERN", "hss-*."+c.Namespace)
	c.CoreHost = runtime.InstanceAddr(e, "CORE_HOST", interfaceAddrs)
	c.DrainTimeout = drainTimeout(s)

	if domain != "" && !identity.IsDomainName(domain) {
		s.Shared.Invalid("IMS_DOMAIN", "not a domain name")
	}
	if !identity.IsDomainName(c.Namespace) {
		e.Invalid("NAMESPACE", "not a domain name")
	}
	if _, port, err := net.SplitHostPort(c.CoreAddr); err != nil {
		e.Invalid("CORE_ADDR", "not host:port")
	} else if p, err := strconv.Atoi(port); err != nil || p < 0 || p > 65535 {
		e.Invalid("CORE_ADDR", "the port is not a number from 0 to 65535")
	}
	for _, d := range []struct{ name, v string }{{"DIAMETER_HOST", c.OriginHost}, {"DIAMETER_REALM", c.OriginRealm}, {"HSS_REALM", c.HSSRealm}} {
		if d.v != "" && !identity.IsDomainName(d.v) {
			e.Invalid(d.name, "not a domain name")
		}
	}
	// A Diameter identity is a fully qualified name (RFC 6733 §4.3.1).
	if c.OriginHost != "" && !strings.Contains(c.OriginHost, ".") {
		e.Invalid("DIAMETER_HOST", "needs two or more labels")
	}
	s.ForbidInProduction(c.OriginHost != "",
		"SCSCF_DIAMETER_HOST is set: every task would share one Origin-Host, and a task replacing a dead one would find the HSS holding its predecessor's connection in REOPEN (ADR 0005); leave it unset in ECS")
	switch c.HSSDiscovery {
	case DiscoveryCloudMap:
	case DiscoveryDNS:
		s.ForbidInProduction(true,
			"SCSCF_HSS_DISCOVERY=dns sees at most eight HSS tasks in an answer, so scscf would send all its Cx traffic to a subset of them; use cloudmap")
	default:
		e.Invalid("HSS_DISCOVERY", "not one of cloudmap, dns")
	}
	// As icscf's: the pattern cannot be switched off, and "**" matches no
	// host at all (threat model T1).
	if !identity.IsDomainName(strings.ReplaceAll(c.HSSHostPattern, "*", "x")) || strings.Contains(c.HSSHostPattern, "**") {
		e.Invalid("HSS_HOST_PATTERN", "not a domain name with one '*' at most in a label")
	}
	s.ForbidInProduction(!prefixWildcard(c.HSSHostPattern, c.Namespace),
		"SCSCF_HSS_HOST_PATTERN is not <prefix>*.<namespace>, with the namespace spelt as it is: a pattern without the wildcard names one HSS task, though every task has an Origin-Host of its own, and a wider one trusts as the HSS peers that are not HSS tasks (threat model T1)")
	if c.CxTimeout <= 0 {
		e.Invalid("CX_TIMEOUT", "must be greater than zero")
	}
	// rcsjta's session-timer re-INVITE carries pcscf's public address after
	// its route set (#208, #322): without the names, scscf takes it for a
	// next hop it did not sign (#439 code review).
	s.ForbidInProduction(len(c.EdgeProxyPublicHosts) == 0,
		"SCSCF_EDGE_PROXY_PUBLIC_HOSTS is empty: a re-INVITE whose route set ends at pcscf's public address, as rcsjta's session refreshes do, would be refused 403; list the names and addresses clients reach pcscf at")

	switch c.Store {
	case StoreDynamoDB:
	case StoreMemory:
		s.ForbidInProduction(true, "SCSCF_STORE=memory keeps registrations in one task and loses them on restart")
	default:
		e.Invalid("STORE", "not one of dynamodb, memory")
	}
	s.ForbidInProduction(c.DynamoDBEndpoint != "", "SCSCF_DYNAMODB_ENDPOINT points the store away from DynamoDB")

	// The keys are plain secrets, as CloudFormation's GenerateSecretString
	// writes them, each with an optional previous one for a rotation; an
	// ID drawn from each names it in what it seals or signs.
	if current, previous := readKeyPair(e, "CHALLENGE_KEY", c.Store == StoreDynamoDB,
		"required with SCSCF_STORE=dynamodb: challenges are sealed in the table"); current != nil {
		for _, k := range [][]byte{current, previous} {
			if k != nil {
				c.ChallengeKeys = append(c.ChallengeKeys, dynamostore.ChallengeKey{ID: keyID(k), Key: secret.NewKey(challengeSealKey(k))})
			}
		}
		c.SealKeyID = keyID(current)
	}
	c.NonceKey = secret.NewKey(readKey(e, "NONCE_KEY", true, "required: every task authenticates the Digest nonces of the others"))
	if current, previous := readKeyPair(e, "DIALOG_KEY", true,
		"required: it signs the Record-Route values and iFC positions"); current != nil {
		for _, k := range [][]byte{current, previous} {
			if k != nil {
				c.DialogKeys = append(c.DialogKeys, routing.DialogKey{ID: keyID(k), Key: secret.NewKey(k)})
			}
		}
	}

	icscf := e.String("ICSCF_URI", "sip:icscf."+c.Namespace+":5060;transport=tcp;lr")
	if u, err := sip.ParseURI(icscf); err != nil || !u.IsSIP() || u.Host == "" {
		e.Invalid("ICSCF_URI", "not a SIP URI with a host")
	} else {
		c.ICSCF = u
	}
	if c.PCSCFCorePort < 1 || c.PCSCFCorePort > 65535 {
		s.Shared.Invalid("PCSCF_CORE_PORT", "not a port from 1 to 65535")
	}
	for _, v := range e.List("APPLICATION_SERVERS", []string{"sip:rcs-as." + c.Namespace + ":5060;transport=tcp"}) {
		u, err := sip.ParseURI(v)
		if err != nil || !u.IsSIP() || u.Host == "" {
			e.Invalid("APPLICATION_SERVERS", "holds what is not a SIP URI with a host")
			continue
		}
		c.ApplicationServers = append(c.ApplicationServers, u)
	}
	for _, d := range []struct {
		name string
		v    time.Duration
	}{{"AS_TIMEOUT", c.ASTimeout}, {"THIRD_PARTY_TIMEOUT", c.ThirdPartyTimeout}, {"NOTIFY_TIMEOUT", c.NotifyTimeout}, {"SWEEP_INTERVAL", c.SweepInterval}} {
		if d.v <= 0 {
			e.Invalid(d.name, "must be greater than zero")
		}
	}
	if c.MaxThirdParty < 1 {
		e.Invalid("MAX_THIRD_PARTY", "must be at least 1")
	}
	if c.SweepLimit < 1 {
		e.Invalid("SWEEP_LIMIT", "must be at least 1")
	}
	if c.MaxServerTransactions < 1 || c.MaxServerTransactions > transaction.MaxMaxServerTransactions {
		e.Invalid("MAX_SERVER_TRANSACTIONS", "must be from 1 to "+strconv.Itoa(transaction.MaxMaxServerTransactions))
	}
	return c
}

// minKeyBytes is the shortest key setting.
const minKeyBytes = 32

// readKey reads the key setting name, its value used as raw bytes, at
// least minKeyBytes of them; nil when unset, which why explains when the
// key is required. A refusal names the variable, never the value.
func readKey(e *runtime.Env, name string, required bool, why string) []byte {
	v := e.String(name, "")
	switch {
	case v == "" && required:
		e.Invalid(name, why)
		return nil
	case v == "":
		return nil
	case len(v) < minKeyBytes:
		e.Invalid(name, "shorter than "+strconv.Itoa(minKeyBytes)+" bytes")
		return nil
	}
	return []byte(v)
}

// readKeyPair reads name, the key that signs or seals, and name_PREVIOUS,
// the other key of a rotation, which only verifies or opens: the new key
// before every task signs with it, then the old one until what it made has
// expired (docs/scscf.md). It needs a current key, and must differ from it.
func readKeyPair(e *runtime.Env, name string, required bool, why string) (current, previous []byte) {
	current = readKey(e, name, required, why)
	previous = readKey(e, name+"_PREVIOUS", false, "")
	switch {
	case previous != nil && current == nil:
		e.Invalid(name+"_PREVIOUS", "set without SCSCF_"+name)
		return nil, nil
	case previous != nil && string(previous) == string(current):
		e.Invalid(name+"_PREVIOUS", "the same key as SCSCF_"+name)
		return nil, nil
	}
	return current, previous
}

// keyID names a key in what it seals or signs: the first 8 hex digits of
// its SHA-256 under a label of its own, the same on every task, which
// tells nothing of the key and matches no other hash of it.
func keyID(key []byte) string {
	sum := sha256.Sum256(append([]byte("rcs scscf key id|"), key...))
	return hex.EncodeToString(sum[:4])
}

// challengeSealKey is the AES-256 key a challenge key setting gives: the
// SHA-256 of the secret under a label of its own, as AES-256 takes 32
// bytes whatever the secret's length, and as the ID, a SHA-256 of the
// secret itself, must tell nothing of the key that seals.
func challengeSealKey(secret []byte) []byte {
	sum := sha256.Sum256(append([]byte("rcs-platform scscf challenge seal v1|"), secret...))
	return sum[:]
}

// drainTimeout reads SCSCF_DRAIN_TIMEOUT, by default RCS_SHUTDOWN_TIMEOUT
// less stopMargin, as icscf's.
func drainTimeout(s *runtime.Settings) time.Duration {
	e := s.Env
	stop, known := runtime.DefaultShutdownTimeout, true
	if v := s.Shared.String("SHUTDOWN_TIMEOUT", ""); v != "" {
		d, err := time.ParseDuration(v)
		if known = err == nil; known {
			stop = d
		}
	}
	def := runtime.DefaultShutdownTimeout - stopMargin
	if known {
		def = max(stop-stopMargin, 0)
	}
	d := e.Duration("DRAIN_TIMEOUT", def)
	switch {
	case d <= 0:
		e.Invalid("DRAIN_TIMEOUT", "must be greater than zero, and RCS_SHUTDOWN_TIMEOUT longer than "+stopMargin.String())
	case known && d+stopMargin > stop:
		e.Invalid("DRAIN_TIMEOUT", "plus "+stopMargin.String()+" must not exceed RCS_SHUTDOWN_TIMEOUT ("+stop.String()+")")
	}
	return d
}

// prefixWildcard reports whether pattern is one label ending in '*' after a
// prefix, followed by exactly the namespace, as hss-*.rcs.local is.
func prefixWildcard(pattern, namespace string) bool {
	label, rest, ok := strings.Cut(pattern, ".")
	return ok && rest == namespace && strings.Count(pattern, "*") == 1 &&
		strings.HasSuffix(label, "*") && len(label) > 1
}
