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
	IMPU          string       `json:"impu"`
	IMPI          string       `json:"impi"`
	DefaultIMPU   string       `json:"default_impu"`
	Contacts      []contactDoc `json:"contacts,omitempty"`
	Deregistering *time.Time   `json:"deregistering,omitempty"`
	Unregistered  *time.Time   `json:"unregistered,omitempty"`
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
	doc := registrationDoc{IMPU: r.IMPU, IMPI: r.IMPI, DefaultIMPU: r.DefaultIMPU}
	if !r.Deregistering.IsZero() {
		t := r.Deregistering.UTC()
		doc.Deregistering = &t
	}
	if !r.Unregistered.IsZero() {
		t := r.Unregistered.UTC()
		doc.Unregistered = &t
	}
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
	r := &state.Registration{IMPU: doc.IMPU, IMPI: doc.IMPI, DefaultIMPU: doc.DefaultIMPU, Version: version}
	if doc.Deregistering != nil {
		r.Deregistering = *doc.Deregistering
	}
	if doc.Unregistered != nil {
		r.Unregistered = *doc.Unregistered
	}
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
	doc := challengeDoc{IMPU: c.IMPU, Issued: c.Issued.UTC(), Expires: c.Expires.UTC(), Resync: c.Resynchronised}
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
	c := &state.Challenge{IMPI: impi, Nonce: nonce, IMPU: doc.IMPU, Issued: doc.Issued, Expires: doc.Expires, Resynchronised: doc.Resync}
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
	ID         string    `json:"id"`
	IMPU       string    `json:"impu"`
	Subscriber string    `json:"subscriber,omitempty"`
	Dialog     dialogDoc `json:"dialog"`
	Expires    time.Time `json:"expires"`
	Terminated bool      `json:"terminated,omitempty"`
}

type dialogDoc struct {
	CallID       string   `json:"call_id"`
	LocalTag     string   `json:"local_tag,omitempty"`
	RemoteTag    string   `json:"remote_tag,omitempty"`
	LocalURI     string   `json:"local_uri,omitempty"`
	RemoteURI    string   `json:"remote_uri,omitempty"`
	RemoteTarget string   `json:"remote_target,omitempty"`
	RouteSet     []string `json:"route_set,omitempty"`
}

func encodeSubscription(s *state.Subscription) ([]byte, error) {
	d := s.Dialog
	return json.Marshal(subscriptionDoc{
		ID: s.ID, IMPU: s.IMPU, Subscriber: s.Subscriber, Expires: s.Expires.UTC(), Terminated: s.Terminated,
		Dialog: dialogDoc{CallID: d.CallID, LocalTag: d.LocalTag, RemoteTag: d.RemoteTag, LocalURI: d.LocalURI,
			RemoteURI: d.RemoteURI, RemoteTarget: d.RemoteTarget, RouteSet: d.RouteSet},
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
		Dialog: state.Dialog{CallID: d.CallID, LocalTag: d.LocalTag, RemoteTag: d.RemoteTag, LocalURI: d.LocalURI,
			RemoteURI: d.RemoteURI, RemoteTarget: d.RemoteTarget, RouteSet: nilIfEmpty(d.RouteSet)},
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
