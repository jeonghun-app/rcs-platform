// Package store holds the HSS data model, the Store interface the HSS keeps
// it behind, and a memory backend for tests and local runs. The DynamoDB
// backend is in internal/hss/awsstore; package storetest checks that both
// behave the same.
//
// The model follows the IMS subscription of TS 23.228 §5.2.1 and TS 29.228:
// one private identity (IMPI) per subscription, its public identities
// (IMPUs) grouped into implicit registration sets (TS 29.228 §6.5), the
// credentials for IMS AKA (TS 33.203) and SIP/HTTP Digest, a reference to a
// shared service profile holding the initial filter criteria, and the state
// the Cx procedures maintain: the assigned S-CSCF name and each IMPU's
// registration state. Shared public identities and several IMPIs per
// subscription are not modelled; the platform provisions one IMPI per
// subscriber (docs/architecture.md §4).
//
// Secrets are held only as Sealed values, which the HSS seals and opens with
// internal/hss/keyring: a Store never sees a key or an HA1 in clear.
//
// Every write is conditional on the version read (optimistic concurrency),
// so two HSS tasks that update one subscription at the same time, for
// example two MARs reserving sequence numbers, cannot both succeed: one gets
// ErrConflict, reads again and retries.
package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// Errors returned by Store implementations, wrapped.
var (
	// ErrNotFound means no subscription, identity or profile has the key.
	ErrNotFound = errors.New("store: not found")
	// ErrExists means a subscription or profile with the key exists.
	ErrExists = errors.New("store: already exists")
	// ErrConflict means the stored version is not the one the write was
	// based on: another writer got there first.
	ErrConflict = errors.New("store: version conflict")
	// ErrIdentityInUse means a public identity belongs to another
	// subscription.
	ErrIdentityInUse = errors.New("store: public identity belongs to another subscription")
	// ErrProfileMissing means a subscription refers to a service profile
	// that does not exist.
	ErrProfileMissing = errors.New("store: service profile does not exist")
	// ErrProfileInUse means a service profile is still referred to.
	ErrProfileInUse = errors.New("store: service profile is in use")
	// ErrInvalid means a record breaks a structural rule of the model; the
	// HSS validates formats before it writes, so this is a programming
	// error or a corrupted record.
	ErrInvalid = errors.New("store: invalid record")
)

// Limits of the model. They keep a subscription inside one DynamoDB
// transaction (100 items: the subscription, its identities added and
// removed, and the profile check) and its User-Data inside
// ifc.MaxDocumentSize.
const (
	MaxPublicIdentities = 32
	MaxDigestRealms     = 4
	MaxCapabilities     = 32
	MaxIdentityLength   = 255
	MaxProfileIDLength  = 64
)

// RegistrationState is the state of a public identity at the HSS
// (TS 29.228 §6.1.2, Table 6.1.2.1 and the procedures that change it).
type RegistrationState uint8

// RegistrationState values.
const (
	// NotRegistered: no S-CSCF serves the identity.
	NotRegistered RegistrationState = iota
	// Registered: the user registered; an S-CSCF serves the identity.
	Registered
	// Unregistered: an S-CSCF serves the identity for a terminating or
	// originating request although the user is not registered, or keeps
	// its profile after a deregistration that stored the server name.
	Unregistered
)

// String returns the TS 29.228 name of the state.
func (s RegistrationState) String() string {
	switch s {
	case NotRegistered:
		return "NOT_REGISTERED"
	case Registered:
		return "REGISTERED"
	case Unregistered:
		return "UNREGISTERED"
	}
	return fmt.Sprintf("RegistrationState(%d)", uint8(s))
}

// Served reports whether an S-CSCF holds the identity's profile in this
// state: registered or unregistered.
func (s RegistrationState) Served() bool { return s == Registered || s == Unregistered }

// Sealed is a secret sealed by internal/hss/keyring. It is not secret by
// itself, but it formats as a placeholder so that it is never mistaken for
// data a log or an API response may carry.
type Sealed []byte

const sealedPlaceholder = "[sealed]"

// String returns a placeholder.
func (Sealed) String() string { return sealedPlaceholder }

// GoString returns a placeholder.
func (Sealed) GoString() string { return sealedPlaceholder }

// Format prints the placeholder for every verb.
func (Sealed) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, sealedPlaceholder) }

// LogValue logs the placeholder.
func (Sealed) LogValue() slog.Value { return slog.StringValue(sealedPlaceholder) }

// MarshalJSON writes the placeholder; the store's own encoding does not use
// it.
func (Sealed) MarshalJSON() ([]byte, error) { return []byte(`"` + sealedPlaceholder + `"`), nil }

// PublicIdentity is one IMPU of a subscription.
type PublicIdentity struct {
	// IMPU is a SIP URI or a global tel URI in the canonical form the HSS
	// matches on (see identity.CanonicalIMPU).
	IMPU string
	// Barred bars the identity from every IMS communication except
	// registration (TS 29.228 B.2.1, TS 23.228 §4.3.3.4).
	Barred bool
	// Type is the identity type of TS 29.228 Table E.1. Only distinct public
	// user identities are provisioned for now.
	Type ifc.IdentityType
	// ImplicitSet groups the identities registered together (TS 29.228
	// §6.5): identities with the same number form one implicit registration
	// set, and share their registration state.
	ImplicitSet int
	State       RegistrationState
}

// AKA holds the IMS AKA credentials (TS 33.203, TS 35.206). OP is never
// stored: the HSS derives OPc when an operator provisions OP.
type AKA struct {
	K, OPc Sealed // 16 bytes each before sealing
	AMF    [2]byte
	// SQN is SQN_HE, the highest sequence number issued (TS 33.102 Annex C),
	// in the low 48 bits.
	SQN uint64
}

// DigestCredential is the HA1 of a Digest password for one realm, for each
// algorithm the HSS serves (RFC 7616 §3.4.2, TS 29.229 §6.3.36): the S-CSCF
// gets MD5 and SHA-256 HA1 in one MAA, ft-server asks for either.
type DigestCredential struct {
	Realm     string
	HA1MD5    Sealed // hex, as sent in Digest-HA1
	HA1SHA256 Sealed
}

// ChargingInformation holds the charging function addresses of the user
// (TS 29.229 §6.3.19); DiameterURIs.
type ChargingInformation struct {
	PrimaryEventChargingFunctionName        string
	SecondaryEventChargingFunctionName      string
	PrimaryChargingCollectionFunctionName   string
	SecondaryChargingCollectionFunctionName string
}

// Subscription is one IMS subscription.
type Subscription struct {
	IMPI string
	// IMSI is the subscriber's IMSI for SIM-based subscriptions, or empty.
	IMSI             string
	PublicIdentities []PublicIdentity
	AKA              *AKA
	Digest           []DigestCredential
	// Profile is the ID of the service profile every identity uses.
	Profile  string
	Charging *ChargingInformation
	// ACSManaged lets acs issue and read the subscription's credentials
	// (ADR 0007 §3); only the operator sets it.
	ACSManaged bool

	// ServerName is the S-CSCF name assigned to the subscription, or empty.
	// The platform's S-CSCFs share one name (ADR 0005), so one name per
	// subscription stands for the per-identity name of TS 29.228.
	ServerName string
	// AuthPending is the authentication pending flag a MAR sets and a SAR
	// clears (TS 29.228 §6.3.1, §6.1.2.1).
	AuthPending bool

	// Version is the stored version: 1 after creation, incremented by every
	// write. A write is accepted only if it carries the stored version.
	Version int64
}

// Identity returns the public identity with the IMPU, or nil.
func (s *Subscription) Identity(impu string) *PublicIdentity {
	for i := range s.PublicIdentities {
		if s.PublicIdentities[i].IMPU == impu {
			return &s.PublicIdentities[i]
		}
	}
	return nil
}

// DigestFor returns the Digest credential for the realm, or nil.
func (s *Subscription) DigestFor(realm string) *DigestCredential {
	for i := range s.Digest {
		if s.Digest[i].Realm == realm {
			return &s.Digest[i]
		}
	}
	return nil
}

// ServiceProfile is a set of services shared by reference: the initial
// filter criteria and the S-CSCF capabilities the I-CSCF selects with.
type ServiceProfile struct {
	ID       string
	Criteria []ifc.FilterCriteria
	// MandatoryCapabilities and OptionalCapabilities go into
	// Server-Capabilities (TS 29.229 §6.3.4); their meaning is operator
	// defined (TS 29.228 §6.7).
	MandatoryCapabilities []uint32
	OptionalCapabilities  []uint32
	Version               int64
}

// Page is one page of a listing.
type Page struct {
	IMPIs []string
	// Next continues the listing; empty at the end.
	Next string
}

// MaxPageSize bounds a page.
const MaxPageSize = 100

// Store keeps subscriptions, service profiles and the wrapped data keys of
// internal/hss/keyring. Reads are strongly consistent except
// SubscriptionsByProfile. Implementations are safe for concurrent use and
// return copies: changing a returned value changes nothing stored.
type Store interface {
	// CreateSubscription stores a new subscription with version 1. It fails
	// with ErrExists, ErrIdentityInUse or ErrProfileMissing.
	CreateSubscription(ctx context.Context, s *Subscription) (*Subscription, error)
	// Subscription returns the subscription of an IMPI.
	Subscription(ctx context.Context, impi string) (*Subscription, error)
	// SubscriptionByIMPU returns the subscription an IMPU belongs to.
	SubscriptionByIMPU(ctx context.Context, impu string) (*Subscription, error)
	// UpdateSubscription replaces old, as read, with s and returns s with
	// its new version. old.Version must still be the stored version
	// (ErrConflict otherwise); identities added must be free
	// (ErrIdentityInUse) and the profile must exist (ErrProfileMissing).
	UpdateSubscription(ctx context.Context, old, s *Subscription) (*Subscription, error)
	// DeleteSubscription deletes s, as read, and its identities. It fails
	// with ErrConflict when s.Version is no longer the stored version.
	DeleteSubscription(ctx context.Context, s *Subscription) error
	// SubscriptionsByProfile lists, in no particular order, the IMPIs of
	// subscriptions using a profile, at most limit (≤ MaxPageSize) per page.
	// The listing is eventually consistent.
	SubscriptionsByProfile(ctx context.Context, profile, cursor string, limit int) (Page, error)

	CreateProfile(ctx context.Context, p *ServiceProfile) (*ServiceProfile, error)
	Profile(ctx context.Context, id string) (*ServiceProfile, error)
	// UpdateProfile replaces the profile; p.Version must be the stored
	// version.
	UpdateProfile(ctx context.Context, p *ServiceProfile) (*ServiceProfile, error)
	// DeleteProfile deletes the profile with p.Version, or fails with
	// ErrProfileInUse while a subscription refers to it.
	DeleteProfile(ctx context.Context, p *ServiceProfile) error

	// Store keeps the wrapped data keys: DataKeys and AddDataKey, whose
	// duplicate is keyring.ErrExists.
	keyring.Store
}
