package cx

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// MAR is a Multimedia-Auth-Request (TS 29.229 §6.1.7): the S-CSCF asks for
// authentication vectors (TS 29.228 §6.3). AuthDataItem carries the scheme
// and, to resynchronise IMS AKA, RAND‖AUTS in Authorization.
type MAR struct {
	Request
	UserName        string // the private user identity
	PublicIdentity  string
	AuthDataItem    AuthDataItem
	NumberAuthItems uint32 // vectors requested, at least 1
	ServerName      string
}

// Message builds the request.
func (r *MAR) Message(n *diameter.Node) (*diameter.Message, error) {
	switch {
	case r.UserName == "":
		return nil, errMissing("MAR", "User-Name")
	case r.PublicIdentity == "":
		return nil, errMissing("MAR", "Public-Identity")
	case r.NumberAuthItems == 0:
		return nil, errMissing("MAR", "SIP-Number-Auth-Items")
	case r.ServerName == "":
		return nil, errMissing("MAR", "Server-Name")
	}
	item, err := r.AuthDataItem.avp()
	if err != nil {
		return nil, err
	}
	return r.NewMessage(n, Application, CodeMultimediaAuth,
		specUserName.UTF8String(r.UserName),
		specPublicIdentity.UTF8String(r.PublicIdentity),
		item,
		specSIPNumberAuthItems.Unsigned32(r.NumberAuthItems),
		specServerName.UTF8String(r.ServerName),
	)
}

// ParseMAR reads a received MAR.
func ParseMAR(m *diameter.Message) (*MAR, error) {
	if err := checkCommand(m, CodeMultimediaAuth, true); err != nil {
		return nil, err
	}
	req, f := ParseRequest(m)
	r := &MAR{
		Request:        req,
		UserName:       f.UTF8String(specUserName, Required),
		PublicIdentity: f.UTF8String(specPublicIdentity, Required),
	}
	if g := f.Grouped(specSIPAuthDataItem, Required); g != nil {
		r.AuthDataItem = readAuthDataItem(g)
	}
	r.NumberAuthItems = f.Unsigned32(specSIPNumberAuthItems, Required)
	if r.NumberAuthItems == 0 && f.Err() == nil {
		f.Fail(diameter.ResultInvalidAVPValue, m.Find(AVPSIPNumberAuthItems, Vendor3GPP), "SIP-Number-Auth-Items is 0")
	}
	r.ServerName = f.UTF8String(specServerName, Required)
	if err := f.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

// MAA is a Multimedia-Auth-Answer (TS 29.229 §6.1.8).
type MAA struct {
	Answer
	UserName       string
	PublicIdentity string
	// NumberAuthItems is the number of items returned; 0 leaves the AVP
	// out, as failure answers do.
	NumberAuthItems uint32
	AuthDataItems   []AuthDataItem
}

// Message builds the answer to req.
func (a *MAA) Message(n *diameter.Node, req *diameter.Message) (*diameter.Message, error) {
	body := optionalUTF8(specUserName, a.UserName)
	body = append(body, optionalUTF8(specPublicIdentity, a.PublicIdentity)...)
	if a.NumberAuthItems != 0 {
		body = append(body, specSIPNumberAuthItems.Unsigned32(a.NumberAuthItems))
	}
	for i := range a.AuthDataItems {
		item, err := a.AuthDataItems[i].avp()
		if err != nil {
			return nil, err
		}
		body = append(body, item)
	}
	return a.NewMessage(n, req, Application, body...)
}

// ParseMAA reads a received MAA.
func ParseMAA(m *diameter.Message) (*MAA, error) {
	if err := checkCommand(m, CodeMultimediaAuth, false); err != nil {
		return nil, err
	}
	ans, f := ParseAnswer(m)
	a := &MAA{
		Answer:          ans,
		UserName:        f.UTF8String(specUserName, Optional),
		PublicIdentity:  f.UTF8String(specPublicIdentity, Optional),
		NumberAuthItems: f.Unsigned32(specSIPNumberAuthItems, Optional),
	}
	for _, g := range f.AllGrouped(specSIPAuthDataItem) {
		a.AuthDataItems = append(a.AuthDataItems, readAuthDataItem(g))
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	return a, nil
}

// AuthDataItem is a SIP-Auth-Data-Item (TS 29.229 §6.3.13).
//
// For IMS AKA (TS 33.203) the HSS returns RAND‖AUTN in Authenticate, XRES in
// Authorization and the keys in ConfidentialityKey and IntegrityKey; for SIP
// Digest it returns Digest. Those are credentials: String and LogValue leave
// them out, so that an item printed or logged by mistake does not leak them
// (docs/architecture.md §8), and XRES, CK and IK are secret.Keys, which print
// as "[redacted]" under the valid verbs and as their closure's address under
// the invalid ones, never as their bytes (#570). A zero Key leaves its AVP
// out, an empty one sends it empty.
type AuthDataItem struct {
	// ItemNumber orders the items of one answer; 0 leaves the AVP out.
	ItemNumber            uint32
	Scheme                string
	Authenticate          []byte
	Authorization         secret.Key
	AuthenticationContext []byte
	ConfidentialityKey    secret.Key
	IntegrityKey          secret.Key
	Digest                *DigestAuthenticate
}

// DigestAuthenticate is a SIP-Digest-Authenticate (TS 29.229 §6.3.36): what
// the S-CSCF needs to challenge and check a SIP Digest client. HA1 is a
// credential and is left out by String and LogValue. The Alternate fields
// carry a second algorithm, such as SHA-256 (RFC 7616), next to the MD5 HA1.
type DigestAuthenticate struct {
	Realm              string
	Algorithm          string
	QoP                string
	HA1                string
	AlternateAlgorithm string
	AlternateHA1       string
}

func (a *AuthDataItem) avp() (*diameter.AVP, error) {
	var children []*diameter.AVP
	if a.ItemNumber != 0 {
		children = append(children, specSIPItemNumber.Unsigned32(a.ItemNumber))
	}
	children = append(children, optionalUTF8(specSIPAuthenticationScheme, a.Scheme)...)
	children = append(children, optionalOctets(specSIPAuthenticate, a.Authenticate)...)
	children = append(children, optionalOctets(specSIPAuthorization, a.Authorization.Reveal())...)
	children = append(children, optionalOctets(specSIPAuthenticationContext, a.AuthenticationContext)...)
	children = append(children, optionalOctets(specConfidentialityKey, a.ConfidentialityKey.Reveal())...)
	children = append(children, optionalOctets(specIntegrityKey, a.IntegrityKey.Reveal())...)
	if d := a.Digest; d != nil {
		switch {
		case d.Realm == "":
			return nil, errMissing("SIP-Digest-Authenticate", "Digest-Realm")
		case d.QoP == "":
			return nil, errMissing("SIP-Digest-Authenticate", "Digest-QoP")
		case d.HA1 == "":
			return nil, errMissing("SIP-Digest-Authenticate", "Digest-HA1")
		}
		digest := []*diameter.AVP{specDigestRealm.UTF8String(d.Realm)}
		digest = append(digest, optionalUTF8(specDigestAlgorithm, d.Algorithm)...)
		digest = append(digest, specDigestQoP.UTF8String(d.QoP), specDigestHA1.UTF8String(d.HA1))
		digest = append(digest, optionalUTF8(specAlternateDigestAlgorithm, d.AlternateAlgorithm)...)
		digest = append(digest, optionalUTF8(specAlternateDigestHA1, d.AlternateHA1)...)
		children = append(children, specSIPDigestAuthenticate.Grouped(digest...))
	}
	return specSIPAuthDataItem.Grouped(children...), nil
}

// optionalKey keeps an AVP's absence: a missing AVP is the zero Key, which
// optionalOctets leaves out again.
func optionalKey(b []byte) secret.Key {
	if b == nil {
		return secret.Key{}
	}
	return secret.NewKey(b)
}

func readAuthDataItem(g *Fields) AuthDataItem {
	item := AuthDataItem{
		ItemNumber:            g.Unsigned32(specSIPItemNumber, Optional),
		Scheme:                g.UTF8String(specSIPAuthenticationScheme, Optional),
		Authenticate:          g.OctetString(specSIPAuthenticate, Optional),
		Authorization:         optionalKey(g.OctetString(specSIPAuthorization, Optional)),
		AuthenticationContext: g.OctetString(specSIPAuthenticationContext, Optional),
		ConfidentialityKey:    optionalKey(g.OctetString(specConfidentialityKey, Optional)),
		IntegrityKey:          optionalKey(g.OctetString(specIntegrityKey, Optional)),
	}
	if d := g.Grouped(specSIPDigestAuthenticate, Optional); d != nil {
		item.Digest = &DigestAuthenticate{
			Realm:              d.UTF8String(specDigestRealm, Required),
			Algorithm:          d.UTF8String(specDigestAlgorithm, Optional),
			QoP:                d.UTF8String(specDigestQoP, Required),
			HA1:                d.UTF8String(specDigestHA1, Required),
			AlternateAlgorithm: d.UTF8String(specAlternateDigestAlgorithm, Optional),
			AlternateHA1:       d.UTF8String(specAlternateDigestHA1, Optional),
		}
	}
	return item
}

// The credentials of an item must stay out of every log line, however the
// item reaches the logger (docs/architecture.md §8). fmt uses String and
// GoString; slog uses LogValue only for the value it is handed, and the JSON
// handler the services use writes anything else, such as an MAA holding a
// slice of items, through encoding/json, so the items and digests also
// marshal to JSON without their credentials. The messages that carry items
// have a LogValue of their own, which leaves out the subscriber identities
// as well.

const redacted = "redacted"

// String describes the item without its credentials.
func (a AuthDataItem) String() string {
	return fmt.Sprintf("SIP-Auth-Data-Item{number %d, scheme %q, digest %t, credentials redacted}",
		a.ItemNumber, a.Scheme, a.Digest != nil)
}

// GoString is String, so that %#v does not print the credentials either.
func (a AuthDataItem) GoString() string { return a.String() }

// LogValue logs the item without its credentials.
func (a AuthDataItem) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("item_number", uint64(a.ItemNumber)),
		slog.String("scheme", a.Scheme),
		slog.Bool("digest", a.Digest != nil),
	)
}

// MarshalJSON writes the item without its credentials. The result is for
// logs only; nothing reads it back.
func (a AuthDataItem) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ItemNumber  uint32
		Scheme      string
		Digest      bool
		Credentials string
	}{a.ItemNumber, a.Scheme, a.Digest != nil, redacted})
}

// String describes the digest parameters without HA1.
func (d DigestAuthenticate) String() string {
	return fmt.Sprintf("SIP-Digest-Authenticate{algorithm %q, qop %q, HA1 redacted}", d.Algorithm, d.QoP)
}

// GoString is String, so that %#v does not print HA1 either.
func (d DigestAuthenticate) GoString() string { return d.String() }

// LogValue logs the digest parameters without HA1. The realm is left out
// too: it is often the user's home domain and adds nothing to a log line.
func (d DigestAuthenticate) LogValue() slog.Value {
	return slog.GroupValue(slog.String("algorithm", d.Algorithm), slog.String("qop", d.QoP))
}

// MarshalJSON writes the digest parameters without HA1, for logs only.
func (d DigestAuthenticate) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Algorithm, QoP, AlternateAlgorithm, HA1 string
	}{d.Algorithm, d.QoP, d.AlternateAlgorithm, redacted})
}

// LogValue logs the request without the identities and the item's
// credentials. It has a value receiver so that an MAR logged by value or by
// pointer gives the same line.
func (r MAR) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("command", "MAR"),
		slog.Any("auth_data_item", r.AuthDataItem),
		slog.Uint64("number_auth_items", uint64(r.NumberAuthItems)),
	)
}

// LogValue logs the answer's result and items without the identities and
// the credentials. Each item is its own attribute, so that every handler
// resolves its LogValue.
func (a MAA) LogValue() slog.Value {
	items := make([]slog.Attr, len(a.AuthDataItems))
	for i, item := range a.AuthDataItems {
		items[i] = slog.Any(strconv.Itoa(i+1), item)
	}
	return slog.GroupValue(
		slog.String("command", "MAA"),
		slog.String("result", a.Result.String()),
		slog.Uint64("number_auth_items", uint64(a.NumberAuthItems)),
		slog.Attr{Key: "auth_data_items", Value: slog.GroupValue(items...)},
	)
}
