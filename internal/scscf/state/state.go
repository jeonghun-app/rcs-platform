package state

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"slices"
	"strings"
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
	// ErrStale means a NOTIFY would number an older state than one already
	// numbered, or follow the subscription's last; it is not sent.
	ErrStale = errors.New("state: a later state was notified")
	// ErrContended means a write lost to other writers on every attempt; the
	// caller may try again later. It is not ErrConflict, which says what won.
	ErrContended = errors.New("state: changed by others on every attempt")
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

// Registration is the registration state of one implicit registration set
// (TS 23.228 §5.2.1a): the bindings of RFC 3261 §10.3, with the RFC 5626
// additions, that every identity of the set shares. The set is one record, so
// that a REGISTER, a deregistration or a sweep is one conditional save of it,
// whichever identity of the set it came for; each identity points at it
// (Identity). The user profile is a Profile of its own under the same key,
// written only when it changes.
type Registration struct {
	// Key is the private identity and the set's default public identity.
	Key SetKey
	// Incarnation is drawn when the record is created and kept by every save
	// of it but one: the identities that point at the set name it, so that
	// one pointing at an earlier record of the same key is told apart. A save
	// that brings back a record claimed for a deregistration (Deregistering
	// set, and zero in the save) must draw a new one, or the deregistration,
	// which deletes the identities naming the incarnation it claimed, would
	// delete those of the registration that took the record over. Both
	// backends refuse such a save that keeps it (ErrInvalid).
	Incarnation int64
	// Identities are the set's public identities, in canonical form, in the
	// order of its User-Data; Key.IMPU is one of them.
	Identities []SetIdentity
	Contacts   []Contact
	// Deregistering is set on a registration left without contacts by the
	// instance that is deregistering it, a sweep or a user's REGISTER: until
	// then that instance handles the deregistration (SAR, NOTIFY), after it
	// any sweep retries it. A registration without contacts is deleted once
	// that has succeeded.
	Deregistering time.Time
	// Unregistered is set on the record of an unregistered user, which the
	// S-CSCF stores after SAR UNREGISTERED_USER (TS 29.228 §6.1.2) so that
	// later terminating requests reuse the set's profile instead of asking
	// again: it is when that state ends, the time the record was stored plus
	// the configured TTL. Such a record has no contacts. A REGISTER makes it
	// a registration, with contacts and Unregistered zero; at Unregistered a
	// sweep claims it as it claims a registration whose last contact expired.
	Unregistered time.Time
	// Reassert is set on a live registration whose assignment the HSS may
	// have lost: a deregistration's SAR crossed a REGISTER's, and telling the
	// HSS again (SAR REGISTRATION) failed. It is when a sweep hands the
	// registration to its handler again (SweepRegistrations), which owns the
	// retry: it clears both fields once the HSS has taken the SAR, and
	// otherwise counts the failure in ReassertAttempts and moves Reassert on,
	// backing off and giving up by MaxReassertAttempts at the latest.
	Reassert         time.Time
	ReassertAttempts int
	// Version is the stored version, 0 before the first save. Saves are
	// conditional on it (optimistic concurrency). It is opaque: a new item
	// starts at a random value (FirstVersion).
	Version int64
}

// MaxReassertAttempts bounds Registration.ReassertAttempts.
const MaxReassertAttempts = 16

// SetIdentity is one public identity of an implicit registration set.
type SetIdentity struct {
	IMPU string
	// Barred bars the identity from every communication but registration
	// (TS 29.228 Annex B.2.1).
	Barred bool
}

// Identity is what one public identity names: the implicit registration set
// it belongs to. Identities go before their record both ways. They are
// written before a record with a new incarnation or new identities is saved,
// the save being the commit point: one naming a record not saved (yet) is
// as good as none, and its KeepUntil ends it. They are deleted with the set
// before its record, so that a deregistration cut short is done again by a
// sweep. A re-registration only keeps them (KeepIdentity), or repairs them.
// An IMPU names one set: an IMPU shared by several private identities (TS
// 23.228 §4.3.3.4) is out of scope: the last set saved for it takes it.
type Identity struct {
	// IMPU is the public identity in canonical form.
	IMPU string
	// Set and Incarnation name the set's record.
	Set         SetKey
	Incarnation int64
	Barred      bool
	// KeepUntil is the safety net Profile.KeepUntil is, for an identity a
	// failed deregistration left: from then on it is not found, and DynamoDB
	// removes it (TTL). The S-CSCF sets and extends it with the set's
	// profile. Backends keep it to the second.
	KeepUntil time.Time
	// Version is as for Registration.
	Version int64
}

// Validate checks i against the limits of this package.
func (i *Identity) Validate() error {
	if !canonicalIMPU(i.IMPU) {
		return fmt.Errorf("%w: identity IMPU is not a canonical public identity", ErrInvalid)
	}
	if err := validSetKey(i.Set); err != nil {
		return err
	}
	if i.Incarnation == 0 {
		return fmt.Errorf("%w: an identity names its set's incarnation", ErrInvalid)
	}
	if !validTime(i.KeepUntil) {
		return fmt.Errorf("%w: an identity needs a KeepUntil", ErrInvalid)
	}
	return nil
}

// MaxIdentities bounds the public identities of one implicit registration
// set.
const MaxIdentities = 32

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
// contact expiry, or a due Reassert if earlier, or, without contacts, when its
// deregistration may be retried, or else when its unregistered state ends. A
// registration with none of these is due at once.
func (r *Registration) SweepAt() time.Time {
	switch {
	case len(r.Contacts) > 0:
		if next := r.NextExpiry(); r.Reassert.IsZero() || next.Before(r.Reassert) {
			return next
		}
		return r.Reassert
	case !r.Deregistering.IsZero():
		return r.Deregistering
	}
	return r.Unregistered
}

// ReassertDue reports whether a sweep at now should tell the HSS again that
// this S-CSCF serves r's set (Reassert).
func (r *Registration) ReassertDue(now time.Time) bool {
	return !r.Reassert.IsZero() && !r.Reassert.After(now)
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
	c.Identities = slices.Clone(r.Identities)
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
	if err := validSetKey(r.Key); err != nil {
		return err
	}
	if r.Incarnation == 0 {
		return fmt.Errorf("%w: a registration needs an incarnation", ErrInvalid)
	}
	if len(r.Identities) == 0 || len(r.Identities) > MaxIdentities {
		return fmt.Errorf("%w: a set has 1 to %d identities", ErrInvalid, MaxIdentities)
	}
	found := false
	for _, id := range r.Identities {
		if !canonicalIMPU(id.IMPU) {
			return fmt.Errorf("%w: a set identity is not a canonical public identity", ErrInvalid)
		}
		found = found || id.IMPU == r.Key.IMPU
	}
	if !found {
		return fmt.Errorf("%w: the set's default identity is not among its identities", ErrInvalid)
	}
	if len(r.Contacts) > MaxContacts {
		return fmt.Errorf("%w: more than %d contacts", ErrInvalid, MaxContacts)
	}
	if !r.Deregistering.IsZero() && (!validTime(r.Deregistering) || len(r.Contacts) > 0) {
		// A record claimed for a deregistration has no bindings: one saved
		// with them would be brought back under the claimed incarnation
		// without counting as a revival (Incarnation).
		return fmt.Errorf("%w: a record claimed for a deregistration has contacts, or Deregistering is out of range", ErrInvalid)
	}
	if !r.Reassert.IsZero() && !validTime(r.Reassert) || r.ReassertAttempts < 0 || r.ReassertAttempts > MaxReassertAttempts {
		return fmt.Errorf("%w: Reassert out of range", ErrInvalid)
	}
	if !r.Unregistered.IsZero() && (!validTime(r.Unregistered) || len(r.Contacts) > 0) {
		return fmt.Errorf("%w: an unregistered user's record has contacts, or Unregistered is out of range", ErrInvalid)
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

func canonicalIMPU(impu string) bool {
	canon, ok := identity.CanonicalIMPU(impu)
	return ok && canon == impu && KeyOK(impu, MaxKey)
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

// Registrations stores the registration state: one record per implicit
// registration set, and per public identity the set it belongs to.
type Registrations interface {
	// Registration returns the registration of a set.
	Registration(ctx context.Context, k SetKey) (*Registration, error)
	// RegistrationsOf returns every registration of a private identity, which
	// a Registration-Termination-Request without public identities ends (TS
	// 29.228 §6.1.3). It is read through an index, which may miss one saved
	// moments ago.
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
	// Identity returns what a canonical IMPU names, ErrNotFound if nothing
	// or its KeepUntil has come at now.
	Identity(ctx context.Context, impu string, now time.Time) (*Identity, error)
	// SaveIdentity and DeleteIdentity are as SaveRegistration and
	// DeleteRegistration, for an identity. A create (Version 0) also
	// replaces an item whose KeepUntil has come at now, which Identity no
	// longer returns and so no caller could name by its version.
	SaveIdentity(ctx context.Context, i *Identity, now time.Time) (*Identity, error)
	DeleteIdentity(ctx context.Context, i *Identity) error
	// KeepIdentity is KeepProfile for an identity: it moves KeepUntil to
	// until if later. A move changes the version, so that a save from an
	// earlier read gets ErrConflict and reads again rather than bringing
	// KeepUntil back.
	KeepIdentity(ctx context.Context, impu string, until, now time.Time) error
	// ExpiringRegistrations returns up to limit registrations whose SweepAt
	// has come at now, for SweepRegistrations.
	ExpiringRegistrations(ctx context.Context, now time.Time, limit int) ([]*Registration, error)
}

// Profiles stores the user profiles: the IMSSubscription document of the
// last SAA or PPR (TS 29.228 Annex E), which every instance needs to run the
// initial filter criteria. The HSS sends User-Data per implicit registration
// set, an SAA only the set of the identity it was asked about and a PPR one
// set at a time (TS 29.228 §6.1.2, §6.2.2), so a profile is stored per set
// (SetKey): one private identity with two sets has two, and saving one
// leaves the other. Profiles are kept apart from the registrations so a
// re-registration, which changes only contacts, does not rewrite them, and so
// that an unregistered user's profile stays as long as the HSS has the user
// assigned: the S-CSCF deletes it with the assignment, no sweep does.
// KeepUntil is only a safety net for a deregistration that failed to.
type Profiles interface {
	// Profile returns the profile stored for k, ErrNotFound if there is none
	// or its KeepUntil has come at now.
	Profile(ctx context.Context, k SetKey, now time.Time) (*Profile, error)
	// SaveProfile stores p. A profile received earlier than the one stored
	// for its key is not stored (ErrConflict): an SAA that took longer to
	// arrive must not undo the PPR that followed it; its KeepUntil still
	// counts, the stored one moving to it if later. A save never brings
	// KeepUntil closer, which a registration may have just extended.
	// Saving the same one again succeeds. Other sets of the same IMPI are not
	// touched. ErrContended means the profile kept changing under it.
	SaveProfile(ctx context.Context, p *Profile) error
	// KeepProfile moves the KeepUntil of k's profile to until, if that is
	// later; it never brings it closer. It returns ErrNotFound if Profile
	// would at now. A profile saved again while it runs, with an earlier
	// KeepUntil, is extended in a second attempt; if it is saved again
	// during that one too, KeepProfile returns nil and the saved KeepUntil
	// stands: that profile was just written, and the next registration
	// extends it (KeepDue). It never returns ErrConflict.
	KeepProfile(ctx context.Context, k SetKey, until, now time.Time) error
	// DeleteProfile deletes the profile of k; deleting none is no error.
	DeleteProfile(ctx context.Context, k SetKey) error
	// DeleteProfileIf deletes the profile of k only if it is still the one
	// received at received (Profile.Received): one another instance saved
	// since, for a registration of its own, stays and gives ErrConflict.
	// Deleting none is no error.
	DeleteProfileIf(ctx context.Context, k SetKey, received time.Time) error
}

// SetKey names one implicit registration set: its registration and its
// profile.
type SetKey struct {
	// IMPI is the private identity the set belongs to.
	IMPI string
	// IMPU is the set's default public identity in canonical form: the first
	// of its identities that is not barred (TS 24.229 §5.4.1.2.2F). Every
	// identity of the set names it (Identity.Set).
	IMPU string
}

func validSetKey(k SetKey) error {
	if err := identity.ValidIMPI(k.IMPI); err != nil {
		return fmt.Errorf("%w: set IMPI: %w", ErrInvalid, err)
	}
	if !canonicalIMPU(k.IMPU) {
		return fmt.Errorf("%w: set IMPU is not a canonical public identity", ErrInvalid)
	}
	return nil
}

// ProfileGrace is how long a profile outlives the last contact expiry of its
// set, or the end of its unregistered state (Registration.Unregistered): the
// S-CSCF sets KeepUntil to that time plus ProfileGrace. A registration
// extends it only when it has moved that time ProfileKeepMargin or more past
// what KeepUntil covers (KeepDue), so a set re-registering every hour writes
// it about twice a day, and KeepUntil stays at least ProfileGrace -
// ProfileKeepMargin past every live binding, however long registrations
// last.
const (
	ProfileGrace      = 24 * time.Hour
	ProfileKeepMargin = 12 * time.Hour
)

// Profile is the User-Data of one implicit registration set.
type Profile struct {
	Key      SetKey
	UserData []byte
	// Received is when the SAA or PPR that carried UserData arrived, which
	// orders the profiles of one set across instances.
	Received time.Time
	// KeepUntil is when the profile is deleted if no deregistration did it:
	// from then on it is not found, and DynamoDB removes it (TTL), so a
	// profile a failed deregistration left behind does not stay for ever.
	// Backends keep it to the second.
	KeepUntil time.Time
}

// KeepDue reports whether a registration whose last binding of the set now
// expires at lastExpiry should extend p with KeepProfile(lastExpiry +
// ProfileGrace): when KeepUntil is less than ProfileGrace - ProfileKeepMargin
// past lastExpiry. Measured from the expiry rather than the time left, a
// registration longer than ProfileGrace still extends it before it runs out.
func (p *Profile) KeepDue(lastExpiry time.Time) bool {
	return keepDue(p.KeepUntil, lastExpiry)
}

// KeepDue is Profile.KeepDue for an identity, with KeepIdentity. Each has its
// own: a PPR or a refused save may move the profile's alone.
func (i *Identity) KeepDue(lastExpiry time.Time) bool {
	return keepDue(i.KeepUntil, lastExpiry)
}

func keepDue(keepUntil, lastExpiry time.Time) bool {
	return keepUntil.Sub(lastExpiry) < ProfileGrace-ProfileKeepMargin
}

// Clone returns a copy of p that shares no memory with it.
func (p *Profile) Clone() *Profile {
	c := *p
	c.UserData = slices.Clone(p.UserData)
	return &c
}

// ValidProfile checks a profile against the limits of this package; the
// backends apply it in SaveProfile.
func ValidProfile(p *Profile) error {
	if err := validSetKey(p.Key); err != nil {
		return err
	}
	if !validTime(p.Received) || !validTime(p.KeepUntil) {
		return fmt.Errorf("%w: a profile needs the time it was received and a KeepUntil", ErrInvalid)
	}
	if len(p.UserData) == 0 || len(p.UserData) > MaxUserData {
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
	// Resynchronised marks an AKA challenge whose vector the HSS issued
	// after a resynchronisation (TS 33.102 §6.3.5): a further synchronisation
	// failure for it is not sent to the HSS again.
	Resynchronised bool
	// Flow is the FlowScope of the P-CSCF flow the challenged REGISTER came
	// over, "" without one: an AUTS that answers the challenge over the same
	// flow is the same client's (registrar limits).
	Flow string
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
	if !KeyOK(c.Nonce, MaxNonce) || !textOK(c.IMPU) || strings.HasPrefix(c.Nonce, ReservedNoncePrefix) {
		return fmt.Errorf("%w: a challenge needs a nonce of 1 to %d bytes", ErrInvalid, MaxNonce)
	}
	if !validTime(c.Issued) || !c.Expires.After(c.Issued) || c.Expires.Sub(c.Issued) > MaxChallengeLifetime {
		return fmt.Errorf("%w: a challenge expires within %s of being issued", ErrInvalid, MaxChallengeLifetime)
	}
	if (c.AKA == nil) == (c.Digest == nil) {
		return fmt.Errorf("%w: a challenge holds exactly one of an AKA vector and Digest state", ErrInvalid)
	}
	if c.Resynchronised && c.AKA == nil {
		return fmt.Errorf("%w: only an AKA challenge is resynchronised", ErrInvalid)
	}
	if c.Flow != "" && !validScope(c.Flow) {
		return fmt.Errorf("%w: a challenge's flow is a FlowScope", ErrInvalid)
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
	// CountAttempt adds n, 1 or -1 to give back an attempt that came to
	// nothing, to the count a names, and returns the count after. Every
	// instance counts into the same count, which is kept until expires. A
	// resent request may count twice: that errs on the side of the limit.
	CountAttempt(ctx context.Context, a Attempt, n int64, expires time.Time) (int64, error)
}

// ReservedNoncePrefix starts no challenge's nonce: the backends keep their
// attempt counts beside the challenges, under keys that start with it. Digest
// and AKA nonces are base64, which never contains it.
const ReservedNoncePrefix = "#"

// The kinds of CountAttempt: the challenges the S-CSCF issues, and the
// resynchronisations among them.
const (
	AttemptChallenge = "challenge"
	AttemptResync    = "resync"
)

// Attempt names one count of CountAttempt: an IMPI's attempts of Kind in the
// window that starts at Window, for the IMPI as a whole (Scope "") or over
// one P-CSCF flow (FlowScope).
type Attempt struct {
	IMPI, Kind, Scope string
	Window            time.Time
}

// FlowScope is the Attempt scope of the P-CSCF flow whose token is in a
// REGISTER's Path: a digest, so that what the store keeps is fixed in length
// and alphabet whatever the token holds.
func FlowScope(token string) string {
	sum := sha256.Sum256([]byte("scscf/attempt-flow|" + token))
	return hex.EncodeToString(sum[:16])
}

// ValidAttempt checks CountAttempt's arguments; the backends apply it.
func ValidAttempt(a Attempt, n int64, expires time.Time) error {
	if err := identity.ValidIMPI(a.IMPI); err != nil {
		return fmt.Errorf("%w: attempt IMPI: %w", ErrInvalid, err)
	}
	if a.Kind != AttemptChallenge && a.Kind != AttemptResync {
		return fmt.Errorf("%w: unknown kind of attempt", ErrInvalid)
	}
	if a.Scope != "" && !validScope(a.Scope) {
		return fmt.Errorf("%w: an attempt scope is a FlowScope", ErrInvalid)
	}
	if n != 1 && n != -1 {
		return fmt.Errorf("%w: an attempt counts 1 or -1", ErrInvalid)
	}
	if !validTime(a.Window) || !expires.After(a.Window) {
		return fmt.Errorf("%w: an attempt window needs a start and a later expiry", ErrInvalid)
	}
	return nil
}

// Subscription is a subscription to the reg event package (RFC 3680) that the
// S-CSCF, as notifier, serves: pcscf and the UA subscribe to the state of a
// registration (TS 24.229 §5.4.2.1).
type Subscription struct {
	// ID identifies the subscription; the S-CSCF derives it from the dialog.
	ID string
	// IMPU is the watched registration, in canonical form.
	IMPU string
	// Set and Incarnation are the record of the set IMPU belonged to when
	// the subscription was made: it watches that set alone, and ends when
	// IMPU leaves it or the record goes, so that it never reports another
	// set's state (#256 security review).
	Set         SetKey
	Incarnation int64
	// Subscriber is the identity of the watcher, and Kind what it is: the
	// P-CSCF (SubscriberPCSCF), whose identity is the Path of a binding of
	// the set, or the UE (SubscriberUE), one of the set's identities.
	Subscriber string
	Kind       string
	// Binding is, for a UE, the binding key of the UE's own binding
	// (regevent), "" if none matched: the subscription ends with it.
	Binding string
	// EventID is the id parameter of the SUBSCRIBE's Event, which every
	// NOTIFY carries back (RFC 6665 §4.5.2).
	EventID string
	Dialog  Dialog
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
	// NotifiedOf is the version of the set's record whose state the last
	// NOTIFY numbered by NextNotify carried, so that no older state takes a
	// later reginfo version.
	NotifiedOf int64
	// Version is the stored version, as for Registration.
	Version int64
}

// FinalNotify is the of of a subscription's last NOTIFY (NextNotify): no
// state is later, and no call after it numbers another, so that two
// instances ending one subscription send one terminated NOTIFY.
const FinalNotify = math.MaxInt64

// The kinds of subscriber (Subscription.Kind).
const (
	SubscriberPCSCF = "pcscf"
	SubscriberUE    = "ue"
)

// Dialog is the notifier's side of the subscription dialog (RFC 3261 §12).
type Dialog struct {
	CallID       string
	LocalTag     string
	RemoteTag    string
	LocalURI     string
	RemoteURI    string
	RemoteTarget string
	RouteSet     []string
	// RemoteSeq is the CSeq of the subscriber's last SUBSCRIBE, which a
	// refresh must not go below (RFC 3261 §12.2.2).
	RemoteSeq uint32
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
	if err := validSetKey(s.Set); err != nil || s.Incarnation == 0 {
		return fmt.Errorf("%w: a subscription names its set and its incarnation", ErrInvalid)
	}
	if s.Kind != SubscriberPCSCF && s.Kind != SubscriberUE || !textOK(s.Binding, s.EventID) {
		return fmt.Errorf("%w: unknown kind of subscriber", ErrInvalid)
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
	// one atomic step and returns the new values, for a NOTIFY of the state
	// of the set's record at version of. Two calls, on any instances, never
	// return the same values, and a call with an of below the last one's
	// fails with ErrStale: a later state has the later number already, as
	// does any call after one with FinalNotify. It
	// changes the item's version, so a save based on an earlier read fails.
	// At MaxCounter it fails with ErrExhausted and the subscription must be
	// ended.
	NextNotify(ctx context.Context, id string, of int64) (cseq, reginfoVersion uint32, err error)
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

// validScope reports whether s is what FlowScope returns.
func validScope(s string) bool {
	return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == ""
}
