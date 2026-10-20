package regevent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip/reginfo"
)

// Cause is what changed a registration, and so the event of the contacts it
// ended (RFC 3680 §4.7.2).
type Cause int

// The causes the registrar reports (TS 24.229 §5.4.2.1.2).
const (
	// Registered: a REGISTER added or refreshed bindings; one it removed
	// was unregistered by the UE.
	Registered Cause = iota
	// Unregistered: the UE removed its bindings.
	Unregistered
	// Expired: bindings ran out (the sweep).
	Expired
	// Deactivated: the network ended the registration and the UE may
	// register again (RTR, TS 24.229 §5.4.1.5).
	Deactivated
	// Rejected: the network ended it for good (RTR PERMANENT_TERMINATION).
	Rejected
	// Changed: the set's identities changed (PPR).
	Changed
)

// endEvent is the event of a contact cause ended.
func (c Cause) endEvent() reginfo.Event {
	switch c {
	case Expired:
		return reginfo.Expired
	case Deactivated:
		return reginfo.Deactivated
	case Rejected:
		return reginfo.Rejected
	}
	return reginfo.Unregistered
}

// reason is the Subscription-State reason of a subscription that cause
// ends with its registration (RFC 6665 §4.1.3): rejected when the network
// ended it for good, so that the subscriber does not subscribe again soon,
// and deactivated otherwise.
func (c Cause) reason() string {
	if c == Rejected {
		return "rejected"
	}
	return "deactivated"
}

// bindingKey names a binding across NOTIFYs: its +sip.instance and reg-id,
// or without an instance its URI and flow, so that one URI bound over two
// flows (RFC 5626) is two bindings.
func bindingKey(c state.Contact) string {
	if c.InstanceID != "" {
		return "i|" + c.InstanceID + "|" + strconv.FormatUint(uint64(c.RegID), 10)
	}
	return "u|" + c.URI + "|" + c.FlowToken
}

// idOf is a short, stable id from parts that cannot be confused: the
// RFC 3680 §5.1 ids are scoped to the document, so a contact's comes from
// its binding and its address-of-record.
func idOf(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(strconv.Itoa(len(p)) + ":" + p))
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// document is the registration state of a set (RFC 3680 §5.2) at version,
// full, or partial with only what changed: set as it is now, nil once it
// has ended, and what of before it does not have any more, listed once as
// terminated with cause's event: the contacts no longer live, and the
// identities no longer in the set. A barred identity is never listed
// (TS 24.229 §5.4.1.2.2).
//
// A live contact is refreshed if before had it with another expiry or
// CSeq, and registered otherwise: the notifier keeps no event per contact,
// so one unchanged gets the event it had when it was first listed.
func document(version uint32, before, set *state.Registration, cause Cause, ends map[string]Cause, now time.Time, st reginfo.State) *reginfo.Info {
	info := &reginfo.Info{Version: version, State: st}
	var live []state.Contact
	if set != nil {
		for _, c := range set.Contacts {
			if !c.Expired(now) {
				live = append(live, c)
			}
		}
	}
	var was []state.Contact
	if before != nil {
		was = before.Contacts
	}
	var ended []state.Contact
	for _, c := range was {
		if !hasBinding(live, c) {
			ended = append(ended, c)
		}
	}
	for _, id := range identitiesOf(before, set) {
		reg := reginfo.Registration{AOR: id.IMPU, ID: idOf("reg", id.IMPU), State: reginfo.Terminated}
		if id.current && len(live) > 0 {
			reg.State = reginfo.Active
			for _, c := range live {
				event := reginfo.Registered
				if old, ok := bindingIn(was, c); ok && (old.Expires != c.Expires || old.CSeq != c.CSeq) {
					event = reginfo.Refreshed
				} else if ok && st == reginfo.Partial {
					continue
				}
				left := uint64(c.Expires.Sub(now) / time.Second)
				reg.Contacts = append(reg.Contacts, contactOf(id.IMPU, c, reginfo.ContactActive, event, &left))
			}
		}
		gone := ended
		if !id.current {
			// The identity left the set: all its contacts end with it.
			gone = was
		}
		for _, c := range gone {
			why := cause
			if e, ok := ends[bindingKey(c)]; ok {
				why = e
			}
			reg.Contacts = append(reg.Contacts, contactOf(id.IMPU, c, reginfo.ContactTerminated, why.endEvent(), nil))
		}
		if st == reginfo.Partial && len(reg.Contacts) == 0 && id.current == id.before {
			continue
		}
		info.Registrations = append(info.Registrations, reg)
	}
	return info
}

// listed is an identity a document lists: current if the set has it now,
// before if it had it before the change.
type listed struct {
	IMPU            string
	current, before bool
}

// identitiesOf are the identities to list, not barred, of set and then
// those of before that set no longer has; once the set has ended, before's
// identities, none current.
func identitiesOf(before, set *state.Registration) []listed {
	var out []listed
	seen := map[string]bool{}
	if set != nil {
		for _, id := range set.Identities {
			if !id.Barred {
				out = append(out, listed{IMPU: id.IMPU, current: true, before: before != nil && hasIdentity(before, id.IMPU)})
			}
			seen[id.IMPU] = true
		}
	}
	if before != nil {
		for _, id := range before.Identities {
			if !id.Barred && !seen[id.IMPU] {
				out = append(out, listed{IMPU: id.IMPU, before: true})
			}
		}
	}
	return out
}

// hasIdentity reports whether set has impu, barred or not.
func hasIdentity(set *state.Registration, impu string) bool {
	for _, id := range set.Identities {
		if id.IMPU == impu {
			return true
		}
	}
	return false
}

// body is the reginfo of a NOTIFY at version, within MaxDocumentSize: the
// full document; if that is too large, for a change, a partial one with
// what changed (RFC 3680 §5.2), and for a set that has ended, its
// identities terminated without their contacts, so that the subscriber
// hears of the end whatever the size (#256 code review). A set within the
// store's limits can make a full document too large: 32 identities of 32
// contacts with long URIs. It fails with reginfo.ErrTooLarge if nothing fits.
func body(version uint32, before, set *state.Registration, cause Cause, ends map[string]Cause, now time.Time) ([]byte, error) {
	b, err := document(version, before, set, cause, ends, now, reginfo.Full).Marshal()
	if !errors.Is(err, reginfo.ErrTooLarge) {
		return b, err
	}
	switch {
	case set == nil:
		ends := &reginfo.Info{Version: version, State: reginfo.Full}
		for _, id := range identitiesOf(before, nil) {
			ends.Registrations = append(ends.Registrations, reginfo.Registration{AOR: id.IMPU, ID: idOf("reg", id.IMPU), State: reginfo.Terminated})
		}
		return ends.Marshal()
	case before != nil:
		return document(version, before, set, cause, ends, now, reginfo.Partial).Marshal()
	}
	return nil, err
}

func hasBinding(cs []state.Contact, c state.Contact) bool {
	_, ok := bindingIn(cs, c)
	return ok
}

// bindingIn is the contact of cs with c's binding.
func bindingIn(cs []state.Contact, c state.Contact) (state.Contact, bool) {
	k := bindingKey(c)
	for _, o := range cs {
		if bindingKey(o) == k {
			return o, true
		}
	}
	return state.Contact{}, false
}

// contactOf is c under aor as a reginfo contact, with the parameters a
// subscriber matches bindings by (+sip.instance, reg-id).
func contactOf(aor string, c state.Contact, st reginfo.ContactState, event reginfo.Event, expires *uint64) reginfo.Contact {
	rc := reginfo.Contact{ID: idOf("contact", aor, bindingKey(c)), State: st, Event: event, URI: c.URI, CallID: c.CallID}
	if st == reginfo.ContactActive {
		rc.Expires = expires
		cseq := uint64(c.CSeq)
		rc.CSeq = &cseq
	}
	if c.InstanceID != "" {
		rc.Params = append(rc.Params, reginfo.Param{Name: "+sip.instance", Value: quoted(c.InstanceID)})
		if c.RegID != 0 {
			rc.Params = append(rc.Params, reginfo.Param{Name: "reg-id", Value: strconv.FormatUint(uint64(c.RegID), 10)})
		}
	}
	return rc
}

// quoted writes v as a quoted-string (RFC 3261 §25.1), as a +sip.instance
// value is written (RFC 5626 §4.1).
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
