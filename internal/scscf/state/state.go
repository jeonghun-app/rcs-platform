package state

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
)

// Errors of the stores. Backends wrap them, so callers test with errors.Is.
var (
	// ErrNotFound means the item does not exist, or has expired.
	ErrNotFound = errors.New("state: not found")
	// ErrExists means an item to be created exists already.
	ErrExists = errors.New("state: already exists")
	// ErrConflict means the item changed since it was read: another instance
	// wrote it first. The caller reads it again and decides afresh.
	ErrConflict = errors.New("state: changed by another writer")
	// ErrInvalid means an item breaks a rule of this package, such as an
	// empty key or a limit, or a stored item cannot be decoded.
	ErrInvalid = errors.New("state: invalid")
)

// Limits on what one item holds. They keep every item well inside DynamoDB's
// 400 KB item limit, so a write never fails for its size in production after
// passing in tests.
const (
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
	// maxText bounds every other string field.
	maxText = 4096
)

// Store is the shared state of the S-CSCF instances (ADR 0005).
type Store interface {
	Registrations
	Challenges
	Subscriptions
}

// Registration is the registration state of one public identity: the
// bindings of RFC 3261 §10.3 with the RFC 5626 additions, and the user profile
// the S-CSCF downloaded with SAR, which every instance needs to run the
// initial filter criteria.
type Registration struct {
	// IMPU is the public identity in canonical form (identity.CanonicalIMPU).
	IMPU string
	// IMPI is the private identity that registered it.
	IMPI     string
	Contacts []Contact
	// UserData is the IMSSubscription document of the last SAA (TS 29.228
	// Annex E), nil when the S-CSCF has not downloaded one.
	UserData []byte
	// Version is the stored version, 0 before the first save. Saves are
	// conditional on it (optimistic concurrency).
	Version int64
}

// Contact is one binding.
type Contact struct {
	// URI is the Contact URI as registered.
	URI string
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
	c.UserData = slices.Clone(r.UserData)
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
	if canon, ok := identity.CanonicalIMPU(r.IMPU); !ok || canon != r.IMPU || len(r.IMPU) > identity.MaxLength {
		return fmt.Errorf("%w: registration IMPU is not a canonical public identity", ErrInvalid)
	}
	if err := identity.ValidIMPI(r.IMPI); err != nil {
		return fmt.Errorf("%w: registration IMPI: %w", ErrInvalid, err)
	}
	if len(r.Contacts) > MaxContacts {
		return fmt.Errorf("%w: more than %d contacts", ErrInvalid, MaxContacts)
	}
	if len(r.UserData) > MaxUserData {
		return fmt.Errorf("%w: User-Data larger than %d bytes", ErrInvalid, MaxUserData)
	}
	for _, c := range r.Contacts {
		if c.URI == "" || !validTime(c.Expires) {
			return fmt.Errorf("%w: a contact needs a URI and an expiry", ErrInvalid)
		}
		if len(c.Path) > MaxPath || len(c.FeatureTags) > MaxContacts {
			return fmt.Errorf("%w: contact Path or feature tags over the limit", ErrInvalid)
		}
		if !textOK(c.URI, c.InstanceID, c.CallID, c.FlowToken) || !textOK(c.Path...) || !textOK(c.FeatureTags...) {
			return fmt.Errorf("%w: a contact field is longer than %d bytes", ErrInvalid, maxText)
		}
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
	// stored one differs, or ErrNotFound if it is gone.
	SaveRegistration(ctx context.Context, r *Registration) (*Registration, error)
	// DeleteRegistration deletes r if its version is still the stored one
	// (ErrConflict otherwise, ErrNotFound if gone).
	DeleteRegistration(ctx context.Context, r *Registration) error
	// ExpiringRegistrations returns up to limit registrations with a contact
	// that has expired at now, and registrations left without contacts, for
	// SweepRegistrations.
	ExpiringRegistrations(ctx context.Context, now time.Time, limit int) ([]*Registration, error)
}

// Challenge is an authentication challenge the S-CSCF issued with a 401 and
// expects the answer to in the next REGISTER, which another instance may
// receive (ADR 0005).
type Challenge struct {
	// IMPI and Nonce identify the challenge: the nonce is RAND‖AUTN encoded
	// for IMS AKA (TS 33.203 §6.1), a random value for SIP Digest.
	IMPI  string
	Nonce string
	// IMPU is the public identity of the REGISTER that was challenged.
	IMPU    string
	Expires time.Time
	// Exactly one of AKA and Digest is set.
	AKA    *AKAVector
	Digest *DigestChallenge
}

// AKAVector is what the S-CSCF keeps of an IMS AKA authentication vector to
// check the response and protect the client's traffic (TS 33.203 §6.1).
// Every field is a credential: String leaves them out.
type AKAVector struct {
	RAND, AUTN, XRES, CK, IK []byte
}

// String describes the vector without its contents.
func (AKAVector) String() string { return "AKAVector{...}" }

// GoString is String, so %#v does not print the credentials either.
func (v AKAVector) GoString() string { return v.String() }

// DigestChallenge is the SIP Digest state of a challenge (RFC 2617, RFC 7616):
// the parameters the S-CSCF sent and the HA1 from the HSS, a credential that
// String leaves out.
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

// Validate checks c against the limits of this package.
func (c *Challenge) Validate() error {
	if err := identity.ValidIMPI(c.IMPI); err != nil {
		return fmt.Errorf("%w: challenge IMPI: %w", ErrInvalid, err)
	}
	if c.Nonce == "" || !textOK(c.Nonce, c.IMPU) || !validTime(c.Expires) {
		return fmt.Errorf("%w: a challenge needs a nonce and an expiry", ErrInvalid)
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
// expiry (ADR 0005). Reads are strongly consistent, so the instance that gets
// the second REGISTER finds a challenge the first one stored a moment ago.
type Challenges interface {
	// AddChallenge stores a new challenge; ErrExists if one with the same
	// IMPI and nonce exists.
	AddChallenge(ctx context.Context, c *Challenge) error
	// Challenge returns a challenge that has not expired at now, leaving it
	// in place.
	Challenge(ctx context.Context, impi, nonce string, now time.Time) (*Challenge, error)
	// TakeChallenge removes a challenge that has not expired at now and
	// returns it. Of several callers for the same challenge, on any number of
	// instances, exactly one gets it, so a response to it is checked once and
	// cannot be replayed.
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
	Expires    time.Time
	// Terminated marks a subscription that has ended and is about to be
	// deleted; a sweep sets it to claim the subscription's final NOTIFY.
	Terminated bool
	// CSeq is the last CSeq the notifier used in the dialog and
	// ReginfoVersion the last reginfo version it sent (RFC 3680 §5.2, which
	// starts at 0). NextNotify advances both.
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
	if s.ID == "" || !textOK(s.ID, s.Subscriber) || len(s.ID) > identity.MaxLength {
		return fmt.Errorf("%w: a subscription needs an ID", ErrInvalid)
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
	if s.Expires.IsZero() && !s.Terminated || !s.Expires.IsZero() && !validTime(s.Expires) {
		return fmt.Errorf("%w: a live subscription needs an expiry", ErrInvalid)
	}
	return nil
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
	// item's version, so a save based on an earlier read fails.
	NextNotify(ctx context.Context, id string) (cseq, reginfoVersion uint32, err error)
	// ExpiringSubscriptions returns up to limit subscriptions whose expiry has
	// passed at now, Terminated ones included, for SweepSubscriptions.
	ExpiringSubscriptions(ctx context.Context, now time.Time, limit int) ([]*Subscription, error)
}

// validTime reports whether t is an expiry the stores can hold: after 1970,
// so its Unix seconds index it in order, and before year 10000, which JSON
// cannot write.
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
