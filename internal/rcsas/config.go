// Package rcsas is the rcs-as service: the RCSAS_ settings
// (docs/rcs-as.md), read into the messaging engine's configuration, the
// store's and the SIP layer's, and Run, which puts the store, the engine
// and the SIP layer (sipas) together.
//
// The prefix is RCSAS_, not RCS_AS_: the runtime reserves RCS_ for the
// settings every service shares.
package rcsas

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/awsstore"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/group"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/messaging"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/sipas"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// EnvPrefix is the prefix of rcs-as's own settings.
const EnvPrefix = "RCSAS_"

// The RCSAS_STORE values.
const (
	StoreMemory   = "memory"
	StoreDynamoDB = "dynamodb"
)

// Defaults of the settings without a messaging default.
const (
	DefaultMSRPListenAddr = ":2855"
	// DefaultSIPListenAddr is the SIP listener, which only the core reaches
	// (ADR 0007 §2).
	DefaultSIPListenAddr = "0.0.0.0:5060"
	DefaultTable         = "messages"
	DefaultGroupsTable   = "groupchats"
)

// Config is rcs-as's configuration.
type Config struct {
	// MSRPListenAddr is where msrp-relay connects (ADR 0004).
	MSRPListenAddr string
	// SIPListenAddr is the SIP listener (TCP), and SIPHost this task's
	// address, which its Via and Call-IDs name (ADR 0005).
	SIPListenAddr string
	SIPHost       netip.Addr
	// HomeDomain is the operator's IMS domain (RCS_IMS_DOMAIN).
	HomeDomain string
	// Core is where rcs-as sends the requests it originates (scscf), a SIP
	// URI of a host with transport=tcp and lr, and Namespace the Cloud Map
	// namespace its names are looked up in (ADR 0007 §5).
	Core      sip.URI
	Namespace string
	// MaxSessions bounds the SIP sessions this task holds, and
	// MaxOutgoingPerUser those one user opens, and MaxIncomingPerUser those
	// rcs-as opens to one user (threat model T9).
	MaxSessions        int
	MaxOutgoingPerUser int
	MaxIncomingPerUser int
	Store              string
	DynamoDB           awsstore.Config
	// Messaging is the engine's configuration; its Clock, Rand and Logger
	// are left for the service to set.
	Messaging messaging.Config
	// GroupsTable is the groupchats table, with RCSAS_STORE=dynamodb.
	GroupsTable string
	// Group is the group chat focus's configuration; its Clock and Rand
	// are left for the service to set.
	Group group.Config
}

// Configure reads the RCSAS_ settings and refuses the ones unsafe with more
// than one task in staging and prod.
func Configure(s *runtime.Settings) Config {
	e := s.Env
	storeTTL := e.Duration("STORE_TTL", messaging.DefaultStoreTTL)
	c := Config{
		MSRPListenAddr: e.String("MSRP_LISTEN_ADDR", DefaultMSRPListenAddr),
		Store:          e.String("STORE", StoreDynamoDB),
		DynamoDB: awsstore.Config{
			Table:    e.String("DYNAMODB_TABLE", DefaultTable),
			Endpoint: e.String("DYNAMODB_ENDPOINT", ""),
		},
		Messaging: messaging.Config{
			MSRPHost:         e.RequiredString("MSRP_HOST"),
			Self:             e.List("SELF_URIS", nil),
			Intermediaries:   e.List("IMDN_INTERMEDIARIES", nil),
			MaxMessageSize:   e.Int("MAX_MESSAGE_SIZE", messaging.DefaultMaxMessageSize),
			PagerLimit:       e.Int("PAGER_LIMIT", messaging.DefaultPagerLimit),
			StoreTTL:         storeTTL,
			SentTTL:          e.Duration("SENT_TTL", storeTTL+messaging.DefaultSentMargin),
			TrustedRoutes:    e.List("TRUSTED_ROUTES", nil),
			MaxQueueMessages: e.Int("MAX_QUEUE_MESSAGES", messaging.DefaultMaxQueueMessages),
			MaxQueueBytes:    int64(e.Int("MAX_QUEUE_BYTES", messaging.DefaultMaxQueueBytes)),
			QueueSenderShare: e.Int("QUEUE_SENDER_SHARE", messaging.DefaultQueueSenderShare),
			SenderRate: messaging.Rate{
				PerMinute: e.Int("SENDER_RATE", messaging.DefaultSenderRate.PerMinute),
				Burst:     e.Int("SENDER_BURST", messaging.DefaultSenderRate.Burst),
			},
			NotificationRate: messaging.Rate{
				PerMinute: e.Int("NOTIFICATION_RATE", messaging.DefaultNotificationRate.PerMinute),
				Burst:     e.Int("NOTIFICATION_BURST", messaging.DefaultNotificationRate.Burst),
			},
			DeliveryTimeout:  e.Duration("DELIVERY_TIMEOUT", messaging.DefaultDeliveryTimeout),
			InviteTimeout:    e.Duration("INVITE_TIMEOUT", messaging.DefaultInviteTimeout),
			AnswerTimeout:    e.Duration("ANSWER_TIMEOUT", messaging.DefaultAnswerTimeout),
			RetryInterval:    e.Duration("RETRY_INTERVAL", messaging.DefaultRetryInterval),
			MaxRetryInterval: e.Duration("MAX_RETRY_INTERVAL", messaging.DefaultMaxRetryInterval),
			StoreTimeout:     e.Duration("STORE_TIMEOUT", messaging.DefaultStoreTimeout),
			SweepInterval:    e.Duration("SWEEP_INTERVAL", messaging.DefaultSweepInterval),
			MSRP: msrp.Config{
				// ADR 0003: below the NLB's fixed 350 s TLS idle timeout.
				KeepAliveInterval: e.Duration("MSRP_KEEPALIVE", msrp.DefaultKeepAliveInterval),
			},
		},
	}
	c.SIPListenAddr = e.String("SIP_LISTEN_ADDR", DefaultSIPListenAddr)
	c.MaxSessions = e.Int("MAX_SESSIONS", sipas.DefaultMaxSessions)
	c.MaxOutgoingPerUser = e.Int("MAX_OUTGOING_SESSIONS_PER_USER", sipas.DefaultMaxSessionsPerUser)
	positive(e, "MAX_SESSIONS", c.MaxSessions)
	positive(e, "MAX_OUTGOING_SESSIONS_PER_USER", c.MaxOutgoingPerUser)
	c.MaxIncomingPerUser = e.Int("MAX_INCOMING_SESSIONS_PER_USER", sipas.DefaultMaxSessionsPerUser)
	positive(e, "MAX_INCOMING_SESSIONS_PER_USER", c.MaxIncomingPerUser)
	if _, port, err := net.SplitHostPort(c.SIPListenAddr); err != nil {
		e.Invalid("SIP_LISTEN_ADDR", "not host:port")
	} else if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		// Not 0 either: scscf reaches rcs-as on the port the HSS's AS URI
		// names, which a port chosen at start would not be.
		e.Invalid("SIP_LISTEN_ADDR", "needs a port")
	}
	c.SIPHost = runtime.InstanceAddr(e, "SIP_HOST", interfaceAddrs)
	c.HomeDomain = s.Shared.RequiredString("IMS_DOMAIN")
	c.Namespace = s.ServiceNamespace()
	c.Core = coreURI(s)
	if _, port, err := net.SplitHostPort(c.MSRPListenAddr); err != nil {
		e.Invalid("MSRP_LISTEN_ADDR", "not host:port")
	} else if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		e.Invalid("MSRP_LISTEN_ADDR", "needs a port")
	} else {
		// The advertised port is the one listened on; the host is the
		// task's own address, which the listener (all interfaces) does
		// not name.
		c.Messaging.MSRPPort = p
	}
	// 0 turns a limit off, which the engine spells as a negative rate (its
	// zero Rate means the default).
	for prefix, r := range map[string]*messaging.Rate{"SENDER_": &c.Messaging.SenderRate, "NOTIFICATION_": &c.Messaging.NotificationRate} {
		if r.Burst < 0 {
			e.Invalid(prefix+"BURST", "must not be negative")
		}
		switch {
		case r.PerMinute < 0:
			e.Invalid(prefix+"RATE", "must not be negative")
		case r.PerMinute == 0:
			r.PerMinute = -1
		}
	}
	positive(e, "MAX_MESSAGE_SIZE", c.Messaging.MaxMessageSize)
	positive(e, "PAGER_LIMIT", c.Messaging.PagerLimit)
	positive(e, "MAX_QUEUE_MESSAGES", c.Messaging.MaxQueueMessages)
	positive(e, "MAX_QUEUE_BYTES", int(c.Messaging.MaxQueueBytes))
	positive(e, "QUEUE_SENDER_SHARE", c.Messaging.QueueSenderShare)
	if c.Messaging.QueueSenderShare > 0 && c.Messaging.MaxQueueBytes/int64(c.Messaging.QueueSenderShare) < int64(c.Messaging.MaxMessageSize) {
		// Otherwise a message of the largest size could never be queued.
		e.Invalid("QUEUE_SENDER_SHARE", "leaves a sender less than RCSAS_MAX_MESSAGE_SIZE of RCSAS_MAX_QUEUE_BYTES")
	}
	for name, d := range map[string]bool{
		"STORE_TTL": c.Messaging.StoreTTL > 0, "SENT_TTL": c.Messaging.SentTTL > 0,
		"DELIVERY_TIMEOUT": c.Messaging.DeliveryTimeout > 0, "INVITE_TIMEOUT": c.Messaging.InviteTimeout > 0,
		"STORE_TIMEOUT": c.Messaging.StoreTimeout > 0, "SWEEP_INTERVAL": c.Messaging.SweepInterval > 0,
		"ANSWER_TIMEOUT": c.Messaging.AnswerTimeout > 0, "RETRY_INTERVAL": c.Messaging.RetryInterval > 0,
	} {
		if !d {
			e.Invalid(name, "must be positive")
		}
	}
	if c.Messaging.SentTTL < c.Messaging.StoreTTL {
		// A notification about a message delivered late must still find
		// the message's record.
		e.Invalid("SENT_TTL", "shorter than RCSAS_STORE_TTL")
	}
	if c.Messaging.MaxRetryInterval < c.Messaging.RetryInterval {
		e.Invalid("MAX_RETRY_INTERVAL", "shorter than RCSAS_RETRY_INTERVAL")
	}
	if c.Messaging.MaxQueueBytes < int64(c.Messaging.MaxMessageSize) {
		e.Invalid("MAX_QUEUE_BYTES", "smaller than RCSAS_MAX_MESSAGE_SIZE")
	}
	if c.Messaging.PagerLimit > c.Messaging.MaxMessageSize {
		e.Invalid("PAGER_LIMIT", "larger than RCSAS_MAX_MESSAGE_SIZE")
	}
	switch c.Store {
	case StoreDynamoDB:
		if c.Messaging.MaxMessageSize > awsstore.MaxCPIMSize {
			e.Invalid("MAX_MESSAGE_SIZE", "larger than a DynamoDB item holds ("+strconv.Itoa(awsstore.MaxCPIMSize)+" bytes)")
		}
	case StoreMemory:
		s.ForbidInProduction(true, "RCSAS_STORE=memory keeps stored messages in one task, which loses them when it stops")
	default:
		e.Invalid("STORE", "must be memory or dynamodb")
	}
	s.ForbidInProduction(c.DynamoDB.Endpoint != "", "RCSAS_DYNAMODB_ENDPOINT replaces the AWS endpoint")
	c.GroupsTable = e.String("GROUPCHATS_TABLE", DefaultGroupsTable)
	maxParticipants := e.Int("GROUP_MAX_PARTICIPANTS", group.DefaultMaxParticipants)
	addRate := messaging.Rate{PerMinute: group.DefaultAddRate.PerMinute, Burst: group.DefaultAddBurst(maxParticipants)}
	c.Group = group.Config{
		ConferenceHost:  e.RequiredString("CONFERENCE_HOST"),
		MaxParticipants: maxParticipants,
		IdleTTL:         e.Duration("GROUP_IDLE_TTL", group.DefaultIdleTTL),
		SenderRate:      readRate(e, "GROUP_SENDER", group.DefaultSenderRate),
		FanoutRate: readRate(e, "GROUP_FANOUT",
			messaging.Rate{PerMinute: group.DefaultFanoutRate.PerMinute, Burst: group.DefaultFanoutBurst(maxParticipants)}),
		AddRate:    readRate(e, "GROUP_ADD", addRate),
		CreateRate: readRate(e, "GROUP_CREATE", group.DefaultCreateRate),
	}
	positive(e, "GROUP_MAX_PARTICIPANTS", c.Group.MaxParticipants)
	if c.Group.MaxParticipants > group.LimitParticipants {
		e.Invalid("GROUP_MAX_PARTICIPANTS", "above "+strconv.Itoa(group.LimitParticipants)+", the most one stored group holds")
	}
	if c.Group.IdleTTL <= 0 {
		e.Invalid("GROUP_IDLE_TTL", "must be positive")
	}
	if r := c.Group.FanoutRate; r.PerMinute > 0 && r.Burst/group.FanoutSenderShare < group.FanoutSenderMessages*(c.Group.MaxParticipants-1) {
		// One sender may use a quarter of the budget, which must still
		// carry a few messages in a row to a full group.
		e.Invalid("GROUP_FANOUT_BURST", "a quarter of it does not cover "+strconv.Itoa(group.FanoutSenderMessages)+
			" messages to a full group (RCSAS_GROUP_MAX_PARTICIPANTS - 1 each)")
	}
	if r := c.Group.AddRate; r.PerMinute > 0 && r.Burst < c.Group.MaxParticipants-1 {
		// Otherwise a full group could never be created.
		e.Invalid("GROUP_ADD_BURST", "smaller than a full group's invitees (RCSAS_GROUP_MAX_PARTICIPANTS - 1)")
	}
	return c
}

// interfaceAddrs lists this host's addresses; tests replace it.
var interfaceAddrs = net.InterfaceAddrs

// coreURI reads RCSAS_CORE_URI, or makes scscf's Cloud Map name in
// RCS_SERVICE_NAMESPACE: where rcs-as sends the requests it originates,
// as their first Route.
func coreURI(s *runtime.Settings) sip.URI {
	e := s.Env
	v := e.String("CORE_URI", "")
	if v == "" {
		ns := s.ServiceNamespace()
		if ns == "" {
			e.Invalid("CORE_URI", "required when RCS_SERVICE_NAMESPACE is unset")
			return sip.URI{}
		}
		v = "sip:scscf." + ns + ";transport=tcp;lr"
	}
	u, err := sip.ParseURI(v)
	network, _ := u.Param("transport")
	if err != nil || u.Scheme != "sip" || u.User != "" || !u.Params.Has("lr") || !strings.EqualFold(network, "tcp") {
		e.Invalid("CORE_URI", "not a sip URI of a host with transport=tcp and lr")
		return sip.URI{}
	}
	host := strings.TrimSuffix(strings.TrimPrefix(u.Host, "["), "]")
	if _, err := netip.ParseAddr(host); err != nil && !runtime.InServiceNamespace(host, s.ServiceNamespace()) {
		e.Invalid("CORE_URI", "a host name outside RCS_SERVICE_NAMESPACE, which rcs-as does not look up (ADR 0007 §5)")
		return sip.URI{}
	}
	return u
}

// readRate reads <prefix>RATE and <prefix>BURST; a rate of 0 turns the
// limit off, which the packages spell as a negative rate.
func readRate(e *runtime.Env, prefix string, def messaging.Rate) messaging.Rate {
	r := messaging.Rate{PerMinute: e.Int(prefix+"_RATE", def.PerMinute), Burst: e.Int(prefix+"_BURST", def.Burst)}
	if r.Burst < 0 {
		e.Invalid(prefix+"_BURST", "must not be negative")
	}
	switch {
	case r.PerMinute < 0:
		e.Invalid(prefix+"_RATE", "must not be negative")
	case r.PerMinute == 0:
		r.PerMinute = -1
	}
	return r
}

func positive(e *runtime.Env, name string, v int) {
	if v <= 0 {
		e.Invalid(name, "must be positive")
	}
}
