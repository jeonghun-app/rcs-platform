package sip

import (
	"strconv"
	"strings"
)

// CSeq is the value of a CSeq header field (RFC 3261 §20.16).
type CSeq struct {
	// Seq is below 2^31 (RFC 3261 §8.1.1.5).
	Seq    uint32
	Method string
}

func parseCSeq(s string) (CSeq, error) {
	s = trimWS(s)
	j := 0
	for j < len(s) && '0' <= s[j] && s[j] <= '9' {
		j++
	}
	k := skipWS(s, j)
	n, valid := parseDelta(s[:j])
	method := s[k:]
	if k == j || !valid || n >= 1<<31 || !isAll(method, classToken) {
		// An overlarge sequence number is refused, not truncated (RFC 4475 §3.1.2.4).
		return CSeq{}, syntaxError("invalid CSeq")
	}
	return CSeq{Seq: n, Method: method}, nil
}

// String writes the CSeq value.
func (c CSeq) String() string {
	return strconv.FormatUint(uint64(c.Seq), 10) + " " + c.Method
}

// isCallID checks callid = word ["@" word] (RFC 3261 §25.1).
func isCallID(s string) bool {
	local, host, found := strings.Cut(s, "@")
	return isAll(local, classWord) && (!found || isAll(host, classWord))
}

// MediaType is the value of a Content-Type header field (RFC 3261 §20.15).
type MediaType struct {
	Type    string
	Subtype string
	Params  Params
}

func parseMediaType(s string) (MediaType, error) {
	i := skipWS(s, 0)
	j := scanClass(s, i, classToken)
	k := skipWS(s, j)
	if j == i || k >= len(s) || s[k] != '/' {
		return MediaType{}, syntaxError("invalid media type")
	}
	k = skipWS(s, k+1)
	l := scanClass(s, k, classToken)
	if l == k {
		return MediaType{}, syntaxError("invalid media subtype")
	}
	ps, err := parseTrailingParams(s, l)
	if err != nil {
		return MediaType{}, err
	}
	return MediaType{Type: s[i:j], Subtype: s[k:l], Params: ps}, nil
}

// Is reports whether the media type is typ/subtype, ignoring case.
func (m MediaType) Is(typ, subtype string) bool {
	return strings.EqualFold(m.Type, typ) && strings.EqualFold(m.Subtype, subtype)
}

// String writes the media type with its parameters.
func (m MediaType) String() string {
	b := make([]byte, 0, len(m.Type)+len(m.Subtype)+16)
	b = append(b, m.Type...)
	b = append(b, '/')
	b = append(b, m.Subtype...)
	return string(m.Params.appendHeaderParams(b))
}

// ChargingVector is the value of P-Charging-Vector (RFC 7315 §4.6): icid-value
// first, then charging parameters such as orig-ioi and term-ioi.
type ChargingVector struct {
	// Params hold every parameter, icid-value first.
	Params Params
}

func parseChargingVector(s string) (ChargingVector, error) {
	i := skipWS(s, 0)
	first, next, err := parseParam(s, i)
	if err != nil {
		return ChargingVector{}, err
	}
	if !strings.EqualFold(first.Name, "icid-value") || first.Value == "" {
		return ChargingVector{}, syntaxError("P-Charging-Vector must start with icid-value")
	}
	rest, err := parseTrailingParams(s, next)
	if err != nil {
		return ChargingVector{}, err
	}
	if rest.Has("icid-value") {
		return ChargingVector{}, syntaxError("repeated parameter")
	}
	return ChargingVector{Params: append(Params{first}, rest...)}, nil
}

// ICID returns the IMS charging identifier.
func (c ChargingVector) ICID() string {
	v, _ := c.Params.Get("icid-value")
	return v
}

// String writes the charging vector.
func (c ChargingVector) String() string {
	if len(c.Params) == 0 {
		return ""
	}
	b := c.Params[0].appendTo(nil, classGenValue)
	return string(c.Params[1:].appendHeaderParams(b))
}

// VisitedNetwork is one element of P-Visited-Network-ID (RFC 7315 §4.3).
type VisitedNetwork struct {
	// Name is the network identifier, a token or the content of a quoted-string.
	Name string
	// Quoted records that Name was, or has to be, written as a quoted-string.
	Quoted bool
	Params Params
}

func parseVisitedNetwork(s string) (VisitedNetwork, error) {
	var v VisitedNetwork
	i := skipWS(s, 0)
	if i < len(s) && s[i] == '"' {
		name, next, ok := parseQuoted(s, i)
		if !ok {
			return VisitedNetwork{}, syntaxError("invalid quoted network identifier")
		}
		v.Name, v.Quoted, i = name, true, next
	} else {
		j := scanClass(s, i, classToken)
		if j == i {
			return VisitedNetwork{}, syntaxError("invalid network identifier")
		}
		v.Name, i = s[i:j], j
	}
	ps, err := parseTrailingParams(s, i)
	if err != nil {
		return VisitedNetwork{}, err
	}
	v.Params = ps
	return v, nil
}

// String writes the network identifier with its parameters.
func (v VisitedNetwork) String() string {
	var b []byte
	if v.Quoted || !isAll(v.Name, classToken) {
		b = appendQuoted(b, v.Name)
	} else {
		b = append(b, v.Name...)
	}
	return string(v.Params.appendHeaderParams(b))
}

// AcceptContact is one element of an Accept-Contact header field (RFC 3841):
// "*" followed by feature parameters and the require and explicit flags.
type AcceptContact struct {
	Params Params
}

func parseAcceptContact(s string) (AcceptContact, error) {
	i := skipWS(s, 0)
	if i >= len(s) || s[i] != '*' {
		return AcceptContact{}, syntaxError("Accept-Contact element must start with *")
	}
	ps, err := parseTrailingParams(s, i+1)
	if err != nil {
		return AcceptContact{}, err
	}
	return AcceptContact{Params: ps}, nil
}

// Require reports the require flag: a contact without the features is not
// acceptable (RFC 3841).
func (a AcceptContact) Require() bool { return a.Params.Has("require") }

// Explicit reports the explicit flag: the contact must have advertised the
// features explicitly (RFC 3841).
func (a AcceptContact) Explicit() bool { return a.Params.Has("explicit") }

// String writes the element.
func (a AcceptContact) String() string {
	return string(a.Params.appendHeaderParams([]byte{'*'}))
}

// Event is the value of an Event header field (RFC 6665 §8.2.1).
type Event struct {
	// Type is the event package with any templates, such as "reg" or
	// "presence.winfo".
	Type   string
	Params Params
}

// ID returns the id parameter, which tells apart subscriptions to the same package
// in one dialog, or "".
func (e Event) ID() string {
	id, _ := e.Params.Get("id")
	return id
}

// String writes the value.
func (e Event) String() string { return tokenParamsString(e.Type, e.Params) }

// SubscriptionState is the value of a Subscription-State header field (RFC 6665
// §8.2.3).
type SubscriptionState struct {
	// State is "active", "pending", "terminated" or an extension.
	State  string
	Params Params
}

func parseSubscriptionState(s string) (SubscriptionState, error) {
	state, ps, err := parseTokenParams(s)
	if err != nil {
		return SubscriptionState{}, err
	}
	for _, name := range []string{"expires", "retry-after"} {
		if v, ok := ps.Get(name); ok {
			if _, ok := parseDelta(v); !ok {
				return SubscriptionState{}, syntaxError("invalid " + name + " parameter")
			}
		}
	}
	return SubscriptionState{State: state, Params: ps}, nil
}

// Expires returns the expires parameter and whether it is present.
func (s SubscriptionState) Expires() (uint32, bool) { return deltaParam(s.Params, "expires") }

// RetryAfter returns the retry-after parameter and whether it is present.
func (s SubscriptionState) RetryAfter() (uint32, bool) {
	return deltaParam(s.Params, "retry-after")
}

// Reason returns the reason parameter of a terminated subscription, or "".
func (s SubscriptionState) Reason() string {
	r, _ := s.Params.Get("reason")
	return r
}

// String writes the value.
func (s SubscriptionState) String() string { return tokenParamsString(s.State, s.Params) }

// SessionExpires is the value of a Session-Expires header field (RFC 4028 §4).
type SessionExpires struct {
	Delta  uint32
	Params Params
}

// Refresher returns "uac" or "uas", or "" when the parameter is absent.
func (s SessionExpires) Refresher() string {
	r, _ := s.Params.Get("refresher")
	return strings.ToLower(r)
}

// String writes the value.
func (s SessionExpires) String() string { return deltaParamsString(s.Delta, s.Params) }

// MinSE is the value of a Min-SE header field (RFC 4028 §5).
type MinSE struct {
	Delta  uint32
	Params Params
}

// String writes the value.
func (m MinSE) String() string { return deltaParamsString(m.Delta, m.Params) }

func parseDeltaParams(s string) (uint32, Params, error) {
	i := skipWS(s, 0)
	j := i
	for j < len(s) && '0' <= s[j] && s[j] <= '9' {
		j++
	}
	n, ok := parseDelta(s[i:j])
	if !ok {
		return 0, nil, syntaxError("invalid delta-seconds")
	}
	ps, err := parseTrailingParams(s, j)
	if err != nil {
		return 0, nil, err
	}
	return n, ps, nil
}

// Reason is one element of a Reason header field (RFC 3326 §2).
type Reason struct {
	// Protocol is "SIP", "Q.850" or another protocol token.
	Protocol string
	Params   Params
}

func parseReason(s string) (Reason, error) {
	proto, ps, err := parseTokenParams(s)
	if err != nil {
		return Reason{}, err
	}
	// Causes are small numbers (SIP status codes, Q.850 causes); bounding them
	// keeps Cause from reporting a present parameter as absent on overflow.
	if v, ok := ps.Get("cause"); ok {
		if n, valid := parseDelta(v); !valid || n >= 1<<31 {
			return Reason{}, syntaxError("invalid cause parameter")
		}
	}
	return Reason{Protocol: proto, Params: ps}, nil
}

// Cause returns the cause parameter and whether it is present.
func (r Reason) Cause() (int, bool) {
	v, ok := r.Params.Get("cause")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	return n, err == nil
}

// Text returns the text parameter, or "".
func (r Reason) Text() string {
	t, _ := r.Params.Get("text")
	return t
}

// String writes the element.
func (r Reason) String() string { return tokenParamsString(r.Protocol, r.Params) }

func deltaParam(ps Params, name string) (uint32, bool) {
	v, ok := ps.Get(name)
	if !ok {
		return 0, false
	}
	n, _ := parseDelta(v)
	return n, true
}

func tokenParamsString(token string, ps Params) string {
	return string(ps.appendHeaderParams(append(make([]byte, 0, len(token)+16), token...)))
}

func deltaParamsString(n uint32, ps Params) string {
	return string(ps.appendHeaderParams(strconv.AppendUint(nil, uint64(n), 10)))
}
