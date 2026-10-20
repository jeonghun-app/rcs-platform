package regevent

import (
	"crypto/sha256"
	"encoding/hex"
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

// reason is the Subscription-State reason of a subscription cause ends, with
// its registration (RFC 3680 §6.3; RFC 6665 §4.1.3).
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

// document is the full registration state of a set (RFC 3680 §5.2) at
// version: set as it is now, nil once it has ended, and the contacts of
// before that it does not have any more, each listed once as terminated
// with cause's event. A barred identity is never listed (TS 24.229
// §5.4.1.2.2).
func document(version uint32, before, set *state.Registration, cause Cause, now time.Time) *reginfo.Info {
	info := &reginfo.Info{Version: version, State: reginfo.Full}
	ids := set
	if ids == nil {
		ids = before
	}
	if ids == nil {
		return info
	}
	var live, ended []state.Contact
	if set != nil {
		for _, c := range set.Contacts {
			if !c.Expired(now) {
				live = append(live, c)
			}
		}
	}
	if before != nil {
		for _, c := range before.Contacts {
			if !hasBinding(live, c) {
				ended = append(ended, c)
			}
		}
	}
	for _, id := range ids.Identities {
		if id.Barred {
			continue
		}
		reg := reginfo.Registration{AOR: id.IMPU, ID: idOf("reg", id.IMPU), State: reginfo.Terminated}
		if len(live) > 0 {
			reg.State = reginfo.Active
		}
		for _, c := range live {
			event := reginfo.Registered
			if before != nil && hasBinding(before.Contacts, c) {
				event = reginfo.Refreshed
			}
			left := uint64(c.Expires.Sub(now) / time.Second)
			reg.Contacts = append(reg.Contacts, contactOf(id.IMPU, c, reginfo.ContactActive, event, &left))
		}
		for _, c := range ended {
			reg.Contacts = append(reg.Contacts, contactOf(id.IMPU, c, reginfo.ContactTerminated, cause.endEvent(), nil))
		}
		info.Registrations = append(info.Registrations, reg)
	}
	return info
}

func hasBinding(cs []state.Contact, c state.Contact) bool {
	k := bindingKey(c)
	for _, o := range cs {
		if bindingKey(o) == k {
			return true
		}
	}
	return false
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
