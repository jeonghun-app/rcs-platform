package registrar

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// featureTags are the base feature tags of RFC 3840 §10, which a Contact
// carries without the "+" that marks every other one (§9).
var featureTags = []string{
	"audio", "automata", "class", "duplex", "data", "control", "mobility", "description",
	"events", "priority", "methods", "schemes", "application", "video", "language", "type",
	"isfocus", "actor", "text", "extensions",
}

// expiryLimits are Config's bounds, in seconds as Contact carries them.
type expiryLimits struct {
	def, min, max uint32
}

func limitsOf(cfg Config) expiryLimits {
	s := func(d time.Duration) uint32 { return uint32(d / time.Second) }
	return expiryLimits{def: s(cfg.DefaultExpires), min: s(cfg.MinExpires), max: s(cfg.MaxExpires)}
}

// contactOp is one Contact of a REGISTER, ready to apply to any identity's
// bindings: the binding it adds or refreshes, or with seconds 0 the binding
// it removes.
type contactOp struct {
	b       state.Contact
	uri     sip.URI
	seconds uint32
}

// prepare reads r's contacts into operations, or returns the response that
// refuses r: a malformed or duplicate contact, an expiry below MinExpires
// (423, RFC 3261 §10.3 step 7), or a reg-id the first hop cannot serve (439,
// RFC 5626 §6).
func prepare(r *register, lim expiryLimits) ([]contactOp, *failure) {
	outbound, flow := outboundPath(r.path)
	var ops []contactOp
	for _, c := range r.contacts {
		exp, present, err := c.Expires()
		switch {
		case errors.Is(err, sip.ErrOutOfRange):
			// As for the Expires field: the most there is, capped below.
		case err != nil:
			return nil, refuse(400, "Bad Contact expires")
		case !present && r.hasExpires:
			exp = r.expires
		case !present:
			exp = lim.def
		}
		if exp != 0 && exp < lim.min {
			return nil, &failure{code: 423, fields: [][2]string{{"Min-Expires", strconv.FormatUint(uint64(lim.min), 10)}}}
		}
		b, f := binding(c, r, outbound, flow)
		if f != nil {
			return nil, f
		}
		if !roundTrips(b, r) {
			// Stored, it would break every 200 of the set until it expired.
			return nil, refuse(400, "Contact cannot be written back")
		}
		op := contactOp{b: b, uri: c.URI, seconds: min(exp, lim.max)}
		for _, o := range ops {
			if o.uri.Equal(op.uri) || op.b.InstanceID != "" && sameInstance(o.b, op.b) {
				return nil, refuse(400, "Duplicate Contact")
			}
		}
		ops = append(ops, op)
	}
	return ops, nil
}

// applyDelta returns the bindings after r's operations (RFC 3261 §10.3 steps
// 6 to 8), given an identity's current ones, or the response that refuses r.
// Every identity of an implicit registration set gets the same delta applied
// to its own current bindings, so that REGISTERs of different devices, or
// of different identities of the set, that land at once all take effect. It
// changes nothing it is given. Expired bindings are dropped first.
//
// A contact with +sip.instance replaces every binding of that instance, but
// for another flow of it (another reg-id, RFC 5626 §6); one without replaces
// the bindings without an instance that came from another Call-ID, the UE's
// earlier registrations (TS 24.229 §5.4.1.2.2 4A), and any of its own URI.
func applyDelta(cur []state.Contact, r *register, ops []contactOp, now time.Time) ([]state.Contact, *failure) {
	next := slices.DeleteFunc(slices.Clone(cur), func(c state.Contact) bool { return c.Expired(now) })
	uris := uriCache{}
	// Step 6: an older or repeated REGISTER of the same UA must not undo a
	// newer one, "*" included.
	stale := func(o state.Contact) bool { return o.CallID == r.callID && r.cseq <= o.CSeq }
	if r.star {
		if slices.ContainsFunc(next, stale) {
			return nil, refuse(500, "Out of order REGISTER")
		}
		return nil, nil
	}
	removals, removed := 0, false
	for _, op := range ops {
		covered := func(o state.Contact) bool {
			switch {
			case op.b.InstanceID != "":
				return sameInstance(o, op.b)
			case o.RegID == 0 && uris.equal(o.URI, op.uri):
				// An outbound flow is matched by instance and reg-id only.
				return true
			}
			return op.seconds != 0 && o.InstanceID == "" && o.CallID != r.callID
		}
		if slices.ContainsFunc(next, func(o state.Contact) bool { return covered(o) && stale(o) }) {
			return nil, refuse(500, "Out of order REGISTER")
		}
		n := len(next)
		next = slices.DeleteFunc(next, covered)
		if op.seconds == 0 {
			removals++
			removed = removed || len(next) < n
			continue
		}
		b := op.b
		b.Expires = now.Add(time.Duration(op.seconds) * time.Second)
		next = append(next, b)
	}
	if removals > 0 && removals == len(ops) && !removed {
		// TS 24.229 §5.4.1.4.1: removing only bindings there are none of.
		return nil, refuse(481, "No such binding")
	}
	if len(next) > state.MaxContacts {
		return nil, refuse(403, "Too many contacts")
	}
	return next, nil
}

// sameInstance reports whether b, of an instance, replaces o: the same
// instance, unless both are outbound flows with different reg-ids.
func sameInstance(o, b state.Contact) bool {
	return o.InstanceID == b.InstanceID && (o.RegID == 0 || b.RegID == 0 || o.RegID == b.RegID)
}

// uriCache parses each stored URI once per delta.
type uriCache map[string]*sip.URI

func (c uriCache) equal(stored string, u sip.URI) bool {
	p, ok := c[stored]
	if !ok {
		if v, err := sip.ParseURI(stored); err == nil {
			p = &v
		}
		c[stored] = p
	}
	return p != nil && p.Equal(u)
}

// binding is the stored form of c, without its expiry.
func binding(c sip.Contact, r *register, outbound bool, flow string) (state.Contact, *failure) {
	b := state.Contact{
		URI: c.URI.String(), Q: 1000, Path: slices.Clone(r.path), CallID: r.callID, CSeq: r.cseq,
	}
	q, present, err := c.Q()
	if err != nil {
		return b, refuse(400, "Bad Contact q")
	}
	if present {
		b.Q = q
	}
	b.InstanceID, _ = c.Instance()
	id, present, err := c.RegID()
	if err != nil {
		return b, refuse(400, "Bad Contact reg-id")
	}
	if present {
		// RFC 5626 §6: a reg-id is meaningful only with an instance ID, is
		// never 0 (§4.2), and only over an edge proxy that does outbound,
		// as the "ob" of the first Path says; without one it is ignored,
		// unless the UA needs outbound.
		switch {
		case b.InstanceID == "" || id == 0:
			return b, refuse(400, "reg-id without +sip.instance")
		case !outbound && r.supportsOutbound:
			return b, refuse(439, "First Hop Lacks Outbound Support")
		case outbound:
			b.RegID = id
			b.FlowToken = flow
			b.KeepAlive = true
		}
	}
	for _, p := range c.Params {
		if hasControl(p.Value) {
			// A quoted-pair lets one in (RFC 3261 §25.1), but no header
			// field may carry it written back.
			return b, refuse(400, "Control character in a Contact parameter")
		}
		name := strings.ToLower(p.Name)
		if name == "+sip.instance" || !strings.HasPrefix(name, "+") && !slices.Contains(featureTags, name) {
			continue
		}
		b.FeatureTags = append(b.FeatureTags, paramText(p))
	}
	return b, nil
}

// outboundPath reports whether the edge proxy that added the topmost Path
// entry supports outbound (its "ob" parameter, RFC 5626 §5.1) and returns the
// flow token in its user part (§5.2), which names the client's flow.
func outboundPath(path []string) (bool, string) {
	if len(path) == 0 {
		return false, ""
	}
	a, err := sip.ParseAddress(path[0])
	if err != nil {
		return false, ""
	}
	if _, ok := a.URI.Param("ob"); !ok {
		return false, ""
	}
	return true, a.URI.User
}

// paramText writes p as a Contact carries it. The parser unescapes a
// quoted-string, so it is escaped again here.
func paramText(p sip.Param) string {
	switch {
	case p.Quoted:
		return p.Name + "=" + quoted(p.Value)
	case p.Value != "":
		return p.Name + "=" + p.Value
	}
	return p.Name
}

// contactField is a binding as the 200 lists it (RFC 3261 §10.3 step 8,
// RFC 5626 §6), with the seconds it has left.
func contactField(c state.Contact, now time.Time) string {
	var b strings.Builder
	b.WriteString("<" + c.URI + ">;expires=")
	b.WriteString(strconv.FormatInt(int64(max(c.Expires.Sub(now)/time.Second, 0)), 10))
	if c.InstanceID != "" {
		b.WriteString(";+sip.instance=" + quoted(c.InstanceID))
	}
	if c.RegID != 0 {
		b.WriteString(";reg-id=" + strconv.FormatUint(uint64(c.RegID), 10))
	}
	for _, t := range c.FeatureTags {
		b.WriteString(";" + t)
	}
	return b.String()
}

// quoted writes v as a quoted-string, with a quoted-pair for each double
// quote and backslash (RFC 3261 §25.1).
func quoted(v string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		if v[i] == '"' || v[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	b.WriteByte('"')
	return b.String()
}

// hasControl reports whether v has a control character, which no quoted
// string written back can carry.
func hasControl(v string) bool {
	return strings.ContainsFunc(v, func(c rune) bool { return c < 0x20 || c == 0x7f })
}

// roundTrips reports whether b, written as the 200 lists it, can be added to
// a header and parses back to the same binding.
func roundTrips(b state.Contact, r *register) bool {
	v := contactField(b, time.Time{})
	var h sip.Header
	if h.Add("Contact", v) != nil {
		return false
	}
	back, err := sip.ParseContacts(v)
	if err != nil || len(back) != 1 || back[0].URI.String() != b.URI {
		return false
	}
	if inst, _ := back[0].Instance(); inst != b.InstanceID {
		return false
	}
	again, f := binding(back[0], r, b.RegID != 0, b.FlowToken)
	return f == nil && slices.Equal(again.FeatureTags, b.FeatureTags)
}
