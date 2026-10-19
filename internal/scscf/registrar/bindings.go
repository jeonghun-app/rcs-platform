package registrar

import (
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

// applyContacts returns the bindings after r (RFC 3261 §10.3 steps 6 to 8,
// RFC 5626 §6), given the current ones, or the response that refuses r. It
// changes nothing it is given. Expired bindings are dropped first.
func applyContacts(cur []state.Contact, r *register, now time.Time, lim expiryLimits) ([]state.Contact, *failure) {
	if r.star {
		return nil, nil
	}
	next := slices.DeleteFunc(slices.Clone(cur), func(c state.Contact) bool { return c.Expired(now) })
	outbound, flow := outboundPath(r.path)
	for _, c := range r.contacts {
		exp, present, err := c.Expires()
		switch {
		case err != nil:
			return nil, refuse(400, "Bad Contact expires")
		case !present && r.hasExpires:
			exp = r.expires
		case !present:
			exp = lim.def
		}
		b, f := binding(c, r, outbound, flow)
		if f != nil {
			return nil, f
		}
		i := slices.IndexFunc(next, func(o state.Contact) bool { return sameBinding(o, b) })
		// Step 7: an older or repeated REGISTER of the same UA must not
		// undo a newer one.
		if i >= 0 && next[i].CallID == r.callID && r.cseq <= next[i].CSeq {
			return nil, refuse(500, "Out of order REGISTER")
		}
		if exp == 0 {
			if i >= 0 {
				next = slices.Delete(next, i, i+1)
			}
			continue
		}
		if exp < lim.min {
			return nil, &failure{code: 423, fields: [][2]string{{"Min-Expires", strconv.FormatUint(uint64(lim.min), 10)}}}
		}
		b.Expires = now.Add(time.Duration(min(exp, lim.max)) * time.Second)
		if i >= 0 {
			next[i] = b
		} else {
			next = append(next, b)
		}
	}
	if len(next) > state.MaxContacts {
		return nil, refuse(403, "Too many contacts")
	}
	return next, nil
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
		// RFC 5626 §6: a reg-id is meaningful only with an instance ID,
		// and is never 0 (§4.2).
		if b.InstanceID == "" || id == 0 {
			return b, refuse(400, "reg-id without +sip.instance")
		}
		b.RegID = id
		b.FlowToken = flow
		b.KeepAlive = outbound
	}
	for _, p := range c.Params {
		name := strings.ToLower(p.Name)
		if name == "+sip.instance" || !strings.HasPrefix(name, "+") && !slices.Contains(featureTags, name) {
			continue
		}
		b.FeatureTags = append(b.FeatureTags, paramText(p))
	}
	return b, nil
}

// sameBinding is the RFC 5626 §6 match by instance and reg-id when the new
// binding has both, and the RFC 3261 §10.3 match by URI otherwise.
func sameBinding(old, b state.Contact) bool {
	if b.InstanceID != "" && b.RegID != 0 {
		return old.InstanceID == b.InstanceID && old.RegID == b.RegID
	}
	if old.RegID != 0 {
		return false
	}
	u, err1 := sip.ParseURI(old.URI)
	v, err2 := sip.ParseURI(b.URI)
	return err1 == nil && err2 == nil && u.Equal(v)
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

// paramText writes p as a Contact carries it.
func paramText(p sip.Param) string {
	switch {
	case p.Quoted:
		return p.Name + `="` + p.Value + `"`
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
		b.WriteString(`;+sip.instance="` + c.InstanceID + `"`)
	}
	if c.RegID != 0 {
		b.WriteString(";reg-id=" + strconv.FormatUint(uint64(c.RegID), 10))
	}
	for _, t := range c.FeatureTags {
		b.WriteString(";" + t)
	}
	return b.String()
}
