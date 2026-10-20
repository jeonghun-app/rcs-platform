package dynamostore

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
)

// The documents stored in the doc attributes. They are separate from the state
// types so that renaming a Go field never changes the stored format. Unknown
// fields are ignored on decoding, so during a rolling update an older instance
// reads what a newer one wrote; but when it saves the item again it writes only
// the fields it knows, and a newer field is lost. A field added later must
// therefore be one whose loss for a while is harmless, or wait until no older
// instance runs before it is relied on.

type registrationDoc struct {
	IMPI          string        `json:"impi"`
	DefaultIMPU   string        `json:"default_impu"`
	Incarnation   int64         `json:"incarnation"`
	Identities    []identityRef `json:"identities"`
	Contacts      []contactDoc  `json:"contacts,omitempty"`
	Deregistering *time.Time    `json:"deregistering,omitempty"`
	Unregistered  *time.Time    `json:"unregistered,omitempty"`
	Reassert      *time.Time    `json:"reassert,omitempty"`
	Attempts      int           `json:"reassert_attempts,omitempty"`
}

type identityRef struct {
	IMPU   string `json:"impu"`
	Barred bool   `json:"barred,omitempty"`
}

// identityDoc is what an identity item holds.
type identityDoc struct {
	IMPI        string `json:"impi"`
	DefaultIMPU string `json:"default_impu"`
	Incarnation int64  `json:"incarnation"`
	Barred      bool   `json:"barred,omitempty"`
}

func encodeIdentity(i *state.Identity) ([]byte, error) {
	return json.Marshal(identityDoc{IMPI: i.Set.IMPI, DefaultIMPU: i.Set.IMPU, Incarnation: i.Incarnation, Barred: i.Barred})
}

func decodeIdentity(b []byte, impu string, version int64, keepUntil time.Time) (*state.Identity, error) {
	var doc identityDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: identity document does not decode", state.ErrInvalid)
	}
	i := &state.Identity{IMPU: impu, Set: state.SetKey{IMPI: doc.IMPI, IMPU: doc.DefaultIMPU}, Incarnation: doc.Incarnation, Barred: doc.Barred, KeepUntil: keepUntil, Version: version}
	if err := i.Validate(); err != nil {
		return nil, err
	}
	return i, nil
}

type contactDoc struct {
	URI         string    `json:"uri"`
	Q           int       `json:"q"`
	InstanceID  string    `json:"instance_id,omitempty"`
	RegID       uint32    `json:"reg_id,omitempty"`
	Path        []string  `json:"path,omitempty"`
	Expires     time.Time `json:"expires"`
	FeatureTags []string  `json:"feature_tags,omitempty"`
	CallID      string    `json:"call_id,omitempty"`
	CSeq        uint32    `json:"cseq,omitempty"`
	FlowToken   string    `json:"flow_token,omitempty"`
	KeepAlive   bool      `json:"keep_alive,omitempty"`
}

func encodeRegistration(r *state.Registration) ([]byte, error) {
	doc := registrationDoc{IMPI: r.Key.IMPI, DefaultIMPU: r.Key.IMPU, Incarnation: r.Incarnation}
	for _, id := range r.Identities {
		doc.Identities = append(doc.Identities, identityRef{IMPU: id.IMPU, Barred: id.Barred})
	}
	if !r.Deregistering.IsZero() {
		t := r.Deregistering.UTC()
		doc.Deregistering = &t
	}
	if !r.Unregistered.IsZero() {
		t := r.Unregistered.UTC()
		doc.Unregistered = &t
	}
	if !r.Reassert.IsZero() {
		t := r.Reassert.UTC()
		doc.Reassert = &t
	}
	doc.Attempts = r.ReassertAttempts
	for _, c := range r.Contacts {
		doc.Contacts = append(doc.Contacts, contactDoc{
			URI: c.URI, Q: c.Q, InstanceID: c.InstanceID, RegID: c.RegID, Path: c.Path, Expires: c.Expires.UTC(),
			FeatureTags: c.FeatureTags, CallID: c.CallID, CSeq: c.CSeq, FlowToken: c.FlowToken, KeepAlive: c.KeepAlive,
		})
	}
	return json.Marshal(doc)
}

func decodeRegistration(b []byte, version int64) (*state.Registration, error) {
	var doc registrationDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: registration document does not decode", state.ErrInvalid)
	}
	r := &state.Registration{Key: state.SetKey{IMPI: doc.IMPI, IMPU: doc.DefaultIMPU}, Incarnation: doc.Incarnation, Version: version}
	for _, id := range doc.Identities {
		r.Identities = append(r.Identities, state.SetIdentity{IMPU: id.IMPU, Barred: id.Barred})
	}
	if doc.Deregistering != nil {
		r.Deregistering = *doc.Deregistering
	}
	if doc.Unregistered != nil {
		r.Unregistered = *doc.Unregistered
	}
	if doc.Reassert != nil {
		r.Reassert = *doc.Reassert
	}
	r.ReassertAttempts = doc.Attempts
	for _, c := range doc.Contacts {
		r.Contacts = append(r.Contacts, state.Contact{
			URI: c.URI, Q: c.Q, InstanceID: c.InstanceID, RegID: c.RegID, Path: nilIfEmpty(c.Path), Expires: c.Expires,
			FeatureTags: nilIfEmpty(c.FeatureTags), CallID: c.CallID, CSeq: c.CSeq, FlowToken: c.FlowToken, KeepAlive: c.KeepAlive,
		})
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

type challengeDoc struct {
	IMPU    string     `json:"impu,omitempty"`
	Issued  time.Time  `json:"issued"`
	Expires time.Time  `json:"expires"`
	AKA     *akaDoc    `json:"aka,omitempty"`
	Digest  *digestDoc `json:"digest,omitempty"`
	Resync  bool       `json:"resync,omitempty"`
	Flow    string     `json:"flow,omitempty"`
}

type akaDoc struct {
	RAND []byte `json:"rand"`
	AUTN []byte `json:"autn"`
	XRES []byte `json:"xres"`
	CK   []byte `json:"ck"`
	IK   []byte `json:"ik"`
}

type digestDoc struct {
	Realm     string `json:"realm"`
	Algorithm string `json:"algorithm,omitempty"`
	QoP       string `json:"qop,omitempty"`
	Opaque    string `json:"opaque,omitempty"`
	HA1       string `json:"ha1"`
}

func encodeChallenge(c *state.Challenge) ([]byte, error) {
	doc := challengeDoc{IMPU: c.IMPU, Issued: c.Issued.UTC(), Expires: c.Expires.UTC(), Resync: c.Resynchronised, Flow: c.Flow}
	if v := c.AKA; v != nil {
		doc.AKA = &akaDoc{RAND: v.RAND, AUTN: v.AUTN, XRES: v.XRES, CK: v.CK, IK: v.IK}
	}
	if g := c.Digest; g != nil {
		doc.Digest = &digestDoc{Realm: g.Realm, Algorithm: g.Algorithm, QoP: g.QoP, Opaque: g.Opaque, HA1: g.HA1}
	}
	return json.Marshal(doc)
}

func decodeChallenge(b []byte, impi, nonce string) (*state.Challenge, error) {
	var doc challengeDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: challenge document does not decode", state.ErrInvalid)
	}
	c := &state.Challenge{IMPI: impi, Nonce: nonce, IMPU: doc.IMPU, Issued: doc.Issued, Expires: doc.Expires, Resynchronised: doc.Resync, Flow: doc.Flow}
	if v := doc.AKA; v != nil {
		c.AKA = &state.AKAVector{RAND: v.RAND, AUTN: v.AUTN, XRES: v.XRES, CK: v.CK, IK: v.IK}
	}
	if g := doc.Digest; g != nil {
		c.Digest = &state.DigestChallenge{Realm: g.Realm, Algorithm: g.Algorithm, QoP: g.QoP, Opaque: g.Opaque, HA1: g.HA1}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// subscriptionDoc leaves out the counters, which are attributes of their own
// so that NextNotify can advance them in place.
type subscriptionDoc struct {
	ID          string    `json:"id"`
	IMPU        string    `json:"impu"`
	Subscriber  string    `json:"subscriber,omitempty"`
	SetIMPI     string    `json:"set_impi"`
	SetIMPU     string    `json:"set_impu"`
	Incarnation int64     `json:"incarnation"`
	Kind        string    `json:"kind"`
	Binding     string    `json:"binding,omitempty"`
	EventID     string    `json:"event_id,omitempty"`
	Dialog      dialogDoc `json:"dialog"`
	Expires     time.Time `json:"expires"`
	Terminated  bool      `json:"terminated,omitempty"`
	EndReason   string    `json:"end_reason,omitempty"`
	SetEnded    bool      `json:"set_ended,omitempty"`
}

type dialogDoc struct {
	CallID       string   `json:"call_id"`
	LocalTag     string   `json:"local_tag,omitempty"`
	RemoteTag    string   `json:"remote_tag,omitempty"`
	LocalURI     string   `json:"local_uri,omitempty"`
	RemoteURI    string   `json:"remote_uri,omitempty"`
	RemoteTarget string   `json:"remote_target,omitempty"`
	RouteSet     []string `json:"route_set,omitempty"`
	RemoteSeq    uint32   `json:"remote_seq,omitempty"`
}

func encodeSubscription(s *state.Subscription) ([]byte, error) {
	d := s.Dialog
	return json.Marshal(subscriptionDoc{
		ID: s.ID, IMPU: s.IMPU, Subscriber: s.Subscriber, Expires: s.Expires.UTC(), Terminated: s.Terminated,
		SetIMPI: s.Set.IMPI, SetIMPU: s.Set.IMPU, Incarnation: s.Incarnation, Kind: s.Kind, Binding: s.Binding, EventID: s.EventID,
		EndReason: s.EndReason, SetEnded: s.SetEnded,
		Dialog: dialogDoc{CallID: d.CallID, LocalTag: d.LocalTag, RemoteTag: d.RemoteTag, LocalURI: d.LocalURI,
			RemoteURI: d.RemoteURI, RemoteTarget: d.RemoteTarget, RouteSet: d.RouteSet, RemoteSeq: d.RemoteSeq},
	})
}

func decodeSubscription(b []byte, version int64, cseq, rver uint32) (*state.Subscription, error) {
	var doc subscriptionDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%w: subscription document does not decode", state.ErrInvalid)
	}
	d := doc.Dialog
	s := &state.Subscription{
		ID: doc.ID, IMPU: doc.IMPU, Subscriber: doc.Subscriber, Expires: doc.Expires, Terminated: doc.Terminated,
		Set: state.SetKey{IMPI: doc.SetIMPI, IMPU: doc.SetIMPU}, Incarnation: doc.Incarnation, Kind: doc.Kind, Binding: doc.Binding, EventID: doc.EventID,
		EndReason: doc.EndReason, SetEnded: doc.SetEnded,
		Dialog: state.Dialog{CallID: d.CallID, LocalTag: d.LocalTag, RemoteTag: d.RemoteTag, LocalURI: d.LocalURI,
			RemoteURI: d.RemoteURI, RemoteTarget: d.RemoteTarget, RouteSet: nilIfEmpty(d.RouteSet), RemoteSeq: d.RemoteSeq},
		CSeq: cseq, ReginfoVersion: rver, Version: version,
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// nilIfEmpty gives an empty list one form, nil, whichever way it was written:
// the encoder leaves empty lists out, so a decoded value encodes back to the
// same document.
func nilIfEmpty[T any](s []T) []T {
	if len(s) == 0 {
		return nil
	}
	return s
}
