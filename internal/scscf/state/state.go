package state

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
)

// Errors of the stores. Backends wrap them, so callers test with errors.Is.
var (
	// ErrNotFound means the item does not exist, or has expired. A key no
	// item can have, such as an empty nonce, is not found either.
	ErrNotFound = errors.New("state: not found")
	// ErrExists means an item to be created exists already.
	ErrExists = errors.New("state: already exists")
	// ErrConflict means the item changed since it was read: another instance
	// wrote it first, or deleted it and another created it again. The caller
	// reads it again and decides afresh.
	ErrConflict = errors.New("state: changed by another writer")
	// ErrInvalid means an item breaks a rule of this package, such as a limit,
	// or a stored item cannot be decoded or opened.
	ErrInvalid = errors.New("state: invalid")
	// ErrExhausted means a subscription's NOTIFY counters have reached their
	// limit; the subscription must be ended.
	ErrExhausted = errors.New("state: NOTIFY counters exhausted")
)

// Limits on what one item holds. Both backends apply them the same way, so a
// write that passes in tests with Memory does not fail on DynamoDB's limits
// (400 KB per item, 2048 bytes per partition key and 1024 per sort key).
const (
	// MaxItemBytes bounds the encoded size of a registration or subscription,
	// leaving DynamoDB's 400 KB room for the item's other attributes.
	MaxItemBytes = 350 << 10
	// MaxKey bounds every key but the nonce: IMPUs, IMPIs and subscription
	// IDs, which identity.MaxLength already bounds.
	MaxKey = identity.MaxLength
	// MaxNonce bounds a challenge nonce, well inside DynamoDB's sort key
	// limit; an AKA nonce is 44 characters (TS 33.203 §6.1), a Digest one
	// what the S-CSCF chose.
	MaxNonce = 512
	// MaxContacts bounds the contacts of one public identity. RFC 5626 lets
	// a UA register one contact per flow, and a user has a few devices.
	MaxContacts = 32
	// MaxPath bounds the Path entries of one contact (RFC 3327); the edge
	// proxy adds one, and a visited network a few more.
	MaxPath = 8
	// MaxUserData is the largest User-Data the HSS sends (TS 29.228 Annex E
	// documents are bounded at 128 KiB by the HSS, docs/hss.md).
	MaxUserData = 128 << 10
	// MaxRouteSet bounds the route set of a reg-event dialog.
	MaxRouteSet = 16
	// MaxChallengeLifetime bounds how long a challenge may live: TS 33.203
	// vectors are for the next REGISTER, seconds away, and a bound keeps a
	// wrongly computed expiry from keeping credentials for years.
	MaxChallengeLifetime = 10 * time.Minute
	// MaxCounter bounds the NOTIFY CSeq and reginfo version: CSeq must stay
	// below 2^31 (RFC 3261 §8.1.1.5).
	MaxCounter = 1<<31 - 1
	// maxText bounds every other string field.
	maxText = 4096
)

// Store is the shared state of the S-CSCF instances (ADR 0005).
type Store interface {
	Registrations
	Profiles
	Challenges
	Subscriptions
}

// KeyOK reports whether s can be a key of at most max bytes. A backend answers
// ErrNotFound for any other without asking its storage, which would refuse it
// with an error of its own.
func KeyOK(s string, max int) bool { return s != "" && len(s) <= max }

// FirstVersion is the version a backend gives a new item: a random one, so
// that an item deleted and created again never comes back with a version a
// writer read before the delete. A writer holding the old item then fails its
// save with ErrConflict instead of overwriting the new one. Versions stay below
// 2^53, which every JSON and DynamoDB number holds exactly.
func FirstVersion(r io.Reader) (int64, error) {
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("state: drawing a version: %w", err)
	}
	return int64(binary.BigEndian.Uint64(b[:])>>12) + 1, nil
}

// randReader is the default source of FirstVersion.
var randReader io.Reader = rand.Reader

// Registration is the registration state of one public identity: the bindings
// of RFC 3261 §10.3 with the RFC 5626 additions. The user profile is a Profile
// of its own, written only when it changes.
type Registration struct {
	// IMPU is the public identity in canonical form (identity.CanonicalIMPU).
	IMPU string
	// IMPI is the private identity that registered it.
	IMPI     string
	Contacts []Contact
	// Deregistering is set on a registration left without contacts by the
	// sweep that claimed it: until then that instance handles the
	// deregistration (SAR, NOTIFY), after it any sweep retries it. A
	// registration without contacts is deleted once that has succeeded.
	Deregistering time.Time
	// Version is the stored version, 0 before the first save. Saves are
	// conditional on it (optimistic concurrency). It is opaque: a new item
	// starts at a random value (FirstVersion).
	Version int64
}

// Contact is one binding.
type Contact struct {
	// URI is the Contact URI as registered.
	URI string
	// Q is the q value in thousandths (RFC 3261 §20.10), which orders
	// sequential forking; a Contact without one is stored as 1000.
	Q int
	// InstanceID is +sip.instance and RegID reg-id (RFC 5626 §4.1, §4.2);
	// RegID 0 means absent.
	InstanceID string
	RegID      uint32
	// Path is the Path of the REGISTER, topmost first (RFC 3327 §5.3): the
	// route to the edge proxy and its flow.
	Path    []string
	Expires time.Time
	// FeatureTags are the Contact header parameters that are feature tags
	// (RFC 3840 §9), as received, such as +g.3gpp.icsi-ref="...".
	FeatureTags []string
	// CallID and CSeq order REGISTERs from the same UA (RFC 3261 §10.3 step
	// 6).
	CallID string
	CSeq   uint32
	// FlowToken names the edge proxy's flow (RFC 5626 §5.2), as found in Path,
	// so that a 430 from the edge proxy identifies the binding to remove.
	FlowToken string
	// KeepAlive records that the UA negotiated keep-alives with outbound (RFC
	// 5626 §5.4).
	KeepAlive bool
}

// Expired reports whether c has expired at now.
func (c Contact) Expired(now time.Time) bool { return !c.Expires.After(now) }

// NextExpiry is the earliest contact expiry, the zero time without contacts.
func (r *Registration) NextExpiry() time.Time {
	var next time.Time
	for _, c := range r.Contacts {
		if next.IsZero() || c.Expires.Before(next) {
			next = c.Expires
		}
	}
	return next
}

// SweepAt is when a sweep next has something to do with r: its earliest
// contact expiry, or, without contacts, when its deregistration may be retried.
func (r *Registration) SweepAt() time.Time {
	if len(r.Contacts) == 0 {
		return r.Deregistering
	}
	return r.NextExpiry()
}

// Prune removes the contacts that have expired at now and returns them.
func (r *Registration) Prune(now time.Time) []Contact {
	var expired []Contact
	r.Contacts = slices.DeleteFunc(r.Contacts, func(c Contact) bool {
		if c.Expired(now) {
			expired = append(expired, c)
			return true
		}
		return false
	})
	return expired
}

// Clone returns a deep copy.
func (r *Registration) Clone() *Registration {
	c := *r
	c.Contacts = make([]Contact, len(r.Contacts))
	for i, ct := range r.Contacts {
		ct.Path = slices.Clone(ct.Path)
		ct.FeatureTags = slices.Clone(ct.FeatureTags)
		c.Contacts[i] = ct
	}
	if r.Contacts == nil {
		c.Contacts = nil
	}
	return &c
}

// Validate checks r against the limits of this package.
func (r *Registration) Validate() error {
	if canon, ok := identity.CanonicalIMPU(r.IMPU); !ok || canon != r.IMPU || !KeyOK(r.IMPU, MaxKey) {
		return fmt.Errorf("%w: registration IMPU is not a canonical public identity", ErrInvalid)
	}
	if err := identity.ValidIMPI(r.IMPI); err != nil {
		return fmt.Errorf("%w: registration IMPI: %w", ErrInvalid, err)
	}
	if len(r.Contacts) > MaxContacts {
		return fmt.Errorf("%w: more than %d contacts", ErrInvalid, MaxContacts)
	}
	if !r.Deregistering.IsZero() && !validTime(r.Deregistering) {
		return fmt.Errorf("%w: Deregistering out of range", ErrInvalid)
	}
	for _, c := range r.Contacts {
		if c.URI == "" || !validTime(c.Expires) {
			return fmt.Errorf("%w: a contact needs a URI and an expiry", ErrInvalid)
		}
		if c.Q < 0 || c.Q > 1000 {
			return fmt.Errorf("%w: a contact's q is outside 0 to 1000", ErrInvalid)
		}
		if len(c.Path) > MaxPath || len(c.FeatureTags) > MaxContacts {
			return fmt.Errorf("%w: contact Path or feature tags over the limit", ErrInvalid)
		}
		if !textOK(c.URI, c.InstanceID, c.CallID, c.FlowToken) || !textOK(c.Path...) || !textOK(c.FeatureTags...) {
			return fmt.Errorf("%w: a contact field is longer than %d bytes", ErrInvalid, maxText)
		}
	}
	return sizeOK("registration", r)
}

// sizeOK refuses an item whose JSON form exceeds MaxItemBytes. The backends'
// own encodings are no larger, so a registration this accepts fits everywhere.
func sizeOK(what string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("%w: %s does not encode", ErrInvalid, what)
	}
	if len(b) > MaxItemBytes {
		return fmt.Errorf("%w: %s is larger than %d bytes encoded", ErrInvalid, what, MaxItemBytes)
	}
	return nil
}

// Registrations stores the registration state, one item per public identity.
type Registrations interface {
	// Registration returns the registration of a canonical IMPU.
	Registration(ctx context.Context, impu string) (*Registration, error)
	// RegistrationsOf returns every registration of a private identity, which
	// a Registration-Termination-Request without public identities ends (TS
	// 29.228 §6.1.3).
	RegistrationsOf(ctx context.Context, impi string) ([]*Registration, error)
	// SaveRegistration stores r and returns it with its new version. A
	// Version of 0 creates it and fails with ErrExists if it exists; any
	// other is conditional on that version and fails with ErrConflict if the
	// stored one differs, which includes an item deleted and created again
	// since r was read, or ErrNotFound if it is gone.
	SaveRegistration(ctx context.Context, r *Registration) (*Registration, error)
	// DeleteRegistration deletes r if its version is still the stored one
	// (ErrConflict otherwise, ErrNotFound if gone).
	DeleteRegistration(ctx context.Context, r *Registration) error
	// ExpiringRegistrations returns up to limit registrations whose SweepAt
	// has come at now, for SweepRegistrations.
	ExpiringRegistrations(ctx context.Context, now time.Time, limit int) ([]*Registration, error)
}

// Profiles stores the user profile of each private identity: the
// IMSSubscription document of the last SAA or PPR (TS 29.228 Annex E), which
// every instance needs to run the initial filter criteria. It is kept apart
// from the registrations so a re-registration, which changes only contacts,
// does not rewrite it, and so that an unregistered user's profile (SAR
// UNREGISTERED_USER, TS 29.228 §6.1.2) stays as long as the HSS has the user
// assigned: the S-CSCF deletes it with the assignment, no sweep does.
type Profiles interface {
	// Profile returns the User-Data stored for impi.
	Profile(ctx context.Context, impi string) ([]byte, error)
	// SaveProfile stores userData for impi, received at received: the time the
	// SAA or PPR that carried it arrived, which orders the profiles of one
	// user across instances. A profile received earlier than the stored one
	// is not stored (ErrConflict): an SAA that took longer to arrive must not
	// undo the PPR that followed it. Saving the same one again succeeds.
	SaveProfile(ctx context.Context, impi string, userData []byte, received time.Time) error
	// DeleteProfile deletes the profile of impi; deleting none is no error.
	DeleteProfile(ctx context.Context, impi string) error
}

// ValidProfile checks a profile against the limits of this package; the
// backends apply it in SaveProfile.
func ValidProfile(impi string, userData []byte, received time.Time) error {
	if err := identity.ValidIMPI(impi); err != nil {
		return fmt.Errorf("%w: profile IMPI: %w", ErrInvalid, err)
	}
	if !validTime(received) {
		return fmt.Errorf("%w: a profile needs the time it was received", ErrInvalid)
	}
	if len(userData) == 0 || len(userData) > MaxUserData {
		return fmt.Errorf("%w: User-Data empty or larger than %d bytes", ErrInvalid, MaxUserData)
	}
	return nil
}

// Challenge is an authentication challenge the S-CSCF issued with a 401 and
// expects the answer to in the next REGISTER, which another instance may
// receive (ADR 0005). It holds credentials: String, LogValue and MarshalJSON
// leave them out.
type Challenge struct {
	// IMPI and Nonce identify the challenge: the nonce is RAND‖AUTN encoded
	// for IMS AKA (TS 33.203 §6.1), a random value for SIP Digest.
	IMPI  string
	Nonce string
	// IMPU is the public identity of the REGISTER that was challenged.
	IMPU string
	// Issued and Expires bound the challenge; Expires is at most
	// MaxChallengeLifetime after Issued.
	Issued  time.Time
	Expires time.Time
	// Exactly one of AKA and Digest is set.
	AKA    *AKAVector
	Digest *DigestChallenge
}

// challengeRedacted is what a Challenge prints and logs.
type challengeRedacted struct {
	Issued, Expires time.Time
	AKA, Digest     bool
}

func (c Challenge) redacted() challengeRedacted {
	return challengeRedacted{Issued: c.Issued, Expires: c.Expires, AKA: c.AKA != nil, Digest: c.Digest != nil}
}

// String describes the challenge without identities or credentials.
func (c Challenge) String() string { return fmt.Sprintf("Challenge%+v", c.redacted()) }

// GoString is String, so %#v does not print the credentials either.
func (c Challenge) GoString() string { return c.String() }

// LogValue logs the challenge without identities or credentials.
func (c Challenge) LogValue() slog.Value {
	return slog.GroupValue(slog.Time("expires", c.Expires), slog.Bool("aka", c.AKA != nil), slog.Bool("digest", c.Digest != nil))
}

// MarshalJSON writes the challenge without identities or credentials, for
// logs: the slog JSON handler marshals what it is given rather than call
// String, and the stores encode documents of their own.
func (c Challenge) MarshalJSON() ([]byte, error) { return json.Marshal(c.redacted()) }

// AKAVector is what the S-CSCF keeps of an IMS AKA authentication vector to
// check the response and protect the client's traffic (TS 33.203 §6.1).
// Every field is a credential: String, LogValue and MarshalJSON leave them
// out.
type AKAVector struct {
	RAND, AUTN, XRES, CK, IK []byte
}

// String describes the vector without its contents.
func (AKAVector) String() string { return "AKAVector{...}" }

// GoString is String, so %#v does not print the credentials either.
func (v AKAVector) GoString() string { return v.String() }

// LogValue logs that there is a vector, and nothing of it.
func (AKAVector) LogValue() slog.Value { return slog.StringValue("AKAVector{...}") }

// MarshalJSON writes nothing of the vector; see Challenge.MarshalJSON.
func (AKAVector) MarshalJSON() ([]byte, error) { return []byte(`"AKAVector{...}"`), nil }

// DigestChallenge is the SIP Digest state of a challenge (RFC 2617, RFC 7616):
// the parameters the S-CSCF sent and the HA1 from the HSS, a credential that
// String, LogValue and MarshalJSON leave out.
type DigestChallenge struct {
	Realm     string
	Algorithm string
	QoP       string
	Opaque    string
	HA1       string
}

// String describes the challenge without HA1.
func (d DigestChallenge) String() string {
	return fmt.Sprintf("DigestChallenge{Algorithm:%s QoP:%s}", d.Algorithm, d.QoP)
}

// GoString is String, so %#v does not print HA1 either.
func (d DigestChallenge) GoString() string { return d.String() }

// LogValue logs the parameters without HA1 and the realm.
func (d DigestChallenge) LogValue() slog.Value {
	return slog.GroupValue(slog.String("algorithm", d.Algorithm), slog.String("qop", d.QoP))
}

// MarshalJSON writes the parameters without HA1; see Challenge.MarshalJSON.
func (d DigestChallenge) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct{ Algorithm, QoP string }{d.Algorithm, d.QoP})
}

// Validate checks c against the limits of this package.
func (c *Challenge) Validate() error {
	if err := identity.ValidIMPI(c.IMPI); err != nil {
		return fmt.Errorf("%w: challenge IMPI: %w", ErrInvalid, err)
	}
	if !KeyOK(c.Nonce, MaxNonce) || !textOK(c.IMPU) {
		return fmt.Errorf("%w: a challenge needs a nonce of 1 to %d bytes", ErrInvalid, MaxNonce)
	}
	if !validTime(c.Issued) || !c.Expires.After(c.Issued) || c.Expires.Sub(c.Issued) > MaxChallengeLifetime {
		return fmt.Errorf("%w: a challenge expires within %s of being issued", ErrInvalid, MaxChallengeLifetime)
	}
	if (c.AKA == nil) == (c.Digest == nil) {
		return fmt.Errorf("%w: a challenge holds exactly one of an AKA vector and Digest state", ErrInvalid)
	}
	return nil
}

// Clone returns a deep copy.
func (c *Challenge) Clone() *Challenge {
	cp := *c
	if c.AKA != nil {
		v := AKAVector{
			RAND: slices.Clone(c.AKA.RAND), AUTN: slices.Clone(c.AKA.AUTN), XRES: slices.Clone(c.AKA.XRES),
			CK: slices.Clone(c.AKA.CK), IK: slices.Clone(c.AKA.IK),
		}
		cp.AKA = &v
	}
	if c.Digest != nil {
		d := *c.Digest
		cp.Digest = &d
	}
	return &cp
}

// Challenges stores authentication challenges until their first use or
// expiry (ADR 0005). The store is strongly consistent, so the instance that
// gets the second REGISTER finds a challenge the first one stored a moment ago.
//
// There is only TakeChallenge: whatever a REGISTER answers a challenge with, a
// response to check or an AKA resynchronisation (AUTS), takes the challenge, so
// a captured REGISTER cannot be replayed within the challenge's lifetime.
type Challenges interface {
	// AddChallenge stores a new challenge; ErrExists if one with the same
	// IMPI and nonce exists.
	AddChallenge(ctx context.Context, c *Challenge) error
	// TakeChallenge removes a challenge that has not expired at now and
	// returns it. Of several callers for the same challenge, on any number of
	// instances, exactly one gets it. ErrNotFound and ErrInvalid (a challenge
	// that no longer opens, as during a key rotation done out of order) both
	// mean the challenge is unusable: the S-CSCF challenges again with a 401,
	// rather than failing the REGISTER.
	TakeChallenge(ctx context.Context, impi, nonce string, now time.Time) (*Challenge, error)
}

// Subscription is a subscription to the reg event package (RFC 3680) that the
// S-CSCF, as notifier, serves: pcscf and the UA subscribe to the state of a
// registration (TS 24.229 §5.4.2.1).
type Subscription struct {
	// ID identifies the subscription; the S-CSCF derives it from the dialog.
	ID string
	// IMPU is the watched registration, in canonical form.
	IMPU string
	// Subscriber is the identity of the watcher.
	Subscriber string
	Dialog     Dialog
	// Expires is when the subscription ends. A Terminated one is deleted by
	// the first sweep after it; whoever terminates a subscription sets it a
	// little ahead (TerminatedGrace) to send its final NOTIFY first.
	Expires time.Time
	// Terminated marks a subscription that has ended and is about to be
	// deleted; a sweep sets it to claim the subscription's final NOTIFY.
	Terminated bool
	// CSeq is the last CSeq the notifier used in the dialog and
	// ReginfoVersion the last reginfo version it sent. NextNotify advances
	// both, so the subscription's first NOTIFY, version 0 (RFC 3680 §5.2), is
	// sent with the values stored at creation, and every later one with
	// NextNotify's.
	CSeq           uint32
	ReginfoVersion uint32
	// Version is the stored version, as for Registration.
	Version int64
}

// Dialog is the notifier's side of the subscription dialog (RFC 3261 §12).
type Dialog struct {
	CallID       string
	LocalTag     string
	RemoteTag    string
	LocalURI     string
	RemoteURI    string
	RemoteTarget string
	RouteSet     []string
}

// Clone returns a deep copy.
func (s *Subscription) Clone() *Subscription {
	c := *s
	c.Dialog.RouteSet = slices.Clone(s.Dialog.RouteSet)
	return &c
}

// Validate checks s against the limits of this package.
func (s *Subscription) Validate() error {
	if !KeyOK(s.ID, MaxKey) || !textOK(s.Subscriber) {
		return fmt.Errorf("%w: a subscription needs an ID of 1 to %d bytes", ErrInvalid, MaxKey)
	}
	if canon, ok := identity.CanonicalIMPU(s.IMPU); !ok || canon != s.IMPU {
		return fmt.Errorf("%w: subscription IMPU is not a canonical public identity", ErrInvalid)
	}
	d := s.Dialog
	if d.CallID == "" || !textOK(d.CallID, d.LocalTag, d.RemoteTag, d.LocalURI, d.RemoteURI, d.RemoteTarget) {
		return fmt.Errorf("%w: a subscription needs its dialog's Call-ID", ErrInvalid)
	}
	if len(d.RouteSet) > MaxRouteSet || !textOK(d.RouteSet...) {
		return fmt.Errorf("%w: route set over the limit", ErrInvalid)
	}
	if !validTime(s.Expires) {
		// A terminated subscription needs one too, so both backends sweep it.
		return fmt.Errorf("%w: a subscription needs an expiry", ErrInvalid)
	}
	if s.CSeq > MaxCounter || s.ReginfoVersion > MaxCounter {
		return fmt.Errorf("%w: NOTIFY counters above %d", ErrInvalid, MaxCounter)
	}
	return sizeOK("subscription", s)
}

// Subscriptions stores reg event subscriptions.
type Subscriptions interface {
	// Subscription returns a subscription by ID.
	Subscription(ctx context.Context, id string) (*Subscription, error)
	// SubscriptionsOf returns the subscriptions to a registration, which a
	// change of it is notified to.
	SubscriptionsOf(ctx context.Context, impu string) ([]*Subscription, error)
	// SaveSubscription stores s, created or conditional on its version, as
	// SaveRegistration does. The counters are stored as given, which is right
	// because the version condition means s was read after the last
	// NextNotify.
	SaveSubscription(ctx context.Context, s *Subscription) (*Subscription, error)
	// DeleteSubscription deletes s if its version is still the stored one.
	DeleteSubscription(ctx context.Context, s *Subscription) error
	// NextNotify advances the CSeq and reginfo version of a subscription in
	// one atomic step and returns the new values, for the next NOTIFY. Two
	// calls, on any instances, never return the same values. It changes the
	// item's version, so a save based on an earlier read fails. At MaxCounter
	// it fails with ErrExhausted and the subscription must be ended.
	NextNotify(ctx context.Context, id string) (cseq, reginfoVersion uint32, err error)
	// ExpiringSubscriptions returns up to limit subscriptions whose expiry has
	// passed at now, Terminated ones included, for SweepSubscriptions.
	ExpiringSubscriptions(ctx context.Context, now time.Time, limit int) ([]*Subscription, error)
}

// validTime reports whether t is a time the stores can hold: after 1970, so
// its Unix seconds index it in order, and before year 10000, which JSON cannot
// write.
func validTime(t time.Time) bool {
	y := t.UTC().Year()
	return !t.IsZero() && y >= 1970 && y <= 9999
}

func textOK(vs ...string) bool {
	for _, v := range vs {
		if len(v) > maxText {
			return false
		}
	}
	return true
}
