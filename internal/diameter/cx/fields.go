package cx

import (
	"bytes"
	"errors"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

// Presence says whether a field read with [Fields] must be in the message:
// {AVP} or [AVP] in the command format.
type Presence bool

// Presence values.
const (
	Optional Presence = false
	Required Presence = true
)

// Fields reads the AVPs of a received message, or of one Grouped AVP, by
// definition. It keeps the first fault as a [*diameter.Error] with the
// Result-Code RFC 6733 §7.1.5 gives it and the Failed-AVP §7.5 asks for, so a
// parse function reads every field in a row and checks [Fields.Err] once. After
// a fault, readers return zero values.
//
// A single-valued field that occurs twice is DIAMETER_AVP_OCCURS_TOO_MANY_TIMES
// rather than "first wins": two Public-Identity AVPs in a UAR make the request
// ambiguous, and a node that guessed would act on an identity the sender may
// not have meant.
type Fields struct {
	avps []*diameter.AVP
	// group is the Grouped AVP these fields came from and parent the fields
	// holding it, or nil at the top level. A fault inside a group is reported
	// inside the AVPs that contain it.
	group  *diameter.AVP
	parent *Fields
	err    *diameter.Error
}

// NewFields returns a reader of avps, normally the AVPs of a message.
func NewFields(avps []*diameter.AVP) *Fields {
	return &Fields{avps: avps}
}

// Err returns the first fault, a [*diameter.Error], or nil.
func (f *Fields) Err() error {
	if r := f.root(); r.err != nil {
		return r.err
	}
	return nil
}

func (f *Fields) root() *Fields {
	for f.parent != nil {
		f = f.parent
	}
	return f
}

func (f *Fields) failed() bool { return f.root().err != nil }

// Fail records a fault found by the caller, such as a value outside its
// range, with failed as the offending AVP. Like the readers' own faults it is
// kept only if it is the first.
func (f *Fields) Fail(resultCode uint32, failed *diameter.AVP, message string) {
	f.fail(&diameter.Error{ResultCode: resultCode, FailedAVP: failed, Message: message})
}

func (f *Fields) fail(e *diameter.Error) {
	r := f.root()
	if r.err != nil {
		return
	}
	for g := f; g.parent != nil && e.FailedAVP != nil; g = g.parent {
		e.FailedAVP = &diameter.AVP{Code: g.group.Code, Flags: g.group.Flags, VendorID: g.group.VendorID,
			Data: diameter.Grouped(e.FailedAVP)}
	}
	r.err = e
}

// Has reports whether the AVP is present.
func (f *Fields) Has(s AVPSpec) bool {
	for _, a := range f.avps {
		if a.Code == s.Code && a.VendorID == s.VendorID {
			return true
		}
	}
	return false
}

// one returns the only instance of the AVP, or nil when it is absent (a fault
// if it is required) or repeated (always a fault).
func (f *Fields) one(s AVPSpec, need Presence) *diameter.AVP {
	if f.failed() {
		return nil
	}
	var found *diameter.AVP
	for _, a := range f.avps {
		if a.Code != s.Code || a.VendorID != s.VendorID {
			continue
		}
		if found != nil {
			// §7.5: Failed-AVP holds the first instance beyond the limit.
			f.fail(&diameter.Error{ResultCode: diameter.ResultAVPOccursTooManyTimes, FailedAVP: a,
				Message: s.Name + " occurs more than once"})
			return nil
		}
		found = a
	}
	if found == nil && need == Required {
		f.fail(&diameter.Error{ResultCode: diameter.ResultMissingAVP,
			FailedAVP: diameter.NewAVP(s.Code, diameter.FlagMandatory, s.VendorID, make([]byte, minPayload(s.Type))),
			Message:   "missing " + s.Name})
	}
	return found
}

// all returns every instance of the AVP.
func (f *Fields) all(s AVPSpec) []*diameter.AVP {
	if f.failed() {
		return nil
	}
	var out []*diameter.AVP
	for _, a := range f.avps {
		if a.Code == s.Code && a.VendorID == s.VendorID {
			out = append(out, a)
		}
	}
	return out
}

// minPayload is the smallest valid payload of t, used for the zero-filled
// example of a missing AVP in Failed-AVP (RFC 6733 §7.5).
func minPayload(t diameter.DataType) int {
	switch t {
	case diameter.TypeInteger32, diameter.TypeUnsigned32, diameter.TypeTime, diameter.TypeEnumerated:
		return 4
	case diameter.TypeInteger64, diameter.TypeUnsigned64:
		return 8
	}
	return 0
}

// invalid records a payload that does not decode as its type. A wrong length
// for a fixed-size type is DIAMETER_INVALID_AVP_LENGTH, anything else
// DIAMETER_INVALID_AVP_VALUE (RFC 6733 §7.1.5).
func (f *Fields) invalid(s AVPSpec, a *diameter.AVP, err error) {
	rc := diameter.ResultInvalidAVPValue
	if errors.Is(err, diameter.ErrAVPLength) {
		rc = diameter.ResultInvalidAVPLength
	}
	f.fail(&diameter.Error{ResultCode: rc, FailedAVP: a, Message: "invalid " + s.Name})
}

// UTF8String reads a UTF8String AVP; absent is "". A required one must not be
// empty either: an empty identity or name is no more usable than a missing
// one.
func (f *Fields) UTF8String(s AVPSpec, need Presence) string {
	a := f.one(s, need)
	if a == nil {
		return ""
	}
	v := f.utf8(s, a)
	if v == "" && need == Required {
		f.fail(&diameter.Error{ResultCode: diameter.ResultInvalidAVPValue, FailedAVP: a, Message: "empty " + s.Name})
	}
	return v
}

func (f *Fields) utf8(s AVPSpec, a *diameter.AVP) string {
	v, err := a.UTF8String()
	if err != nil {
		f.invalid(s, a, err)
	}
	return v
}

// AllUTF8String reads every instance of a UTF8String AVP.
func (f *Fields) AllUTF8String(s AVPSpec) []string {
	var out []string
	for _, a := range f.all(s) {
		out = append(out, f.utf8(s, a))
	}
	if f.failed() {
		return nil
	}
	return out
}

// OctetString reads an OctetString AVP; absent is nil, and a required one
// must not be empty. The result is a copy, so it stays valid whatever happens
// to the message buffer.
func (f *Fields) OctetString(s AVPSpec, need Presence) []byte {
	a := f.one(s, need)
	if a == nil {
		return nil
	}
	if len(a.Data) == 0 && need == Required {
		f.fail(&diameter.Error{ResultCode: diameter.ResultInvalidAVPValue, FailedAVP: a, Message: "empty " + s.Name})
	}
	return bytes.Clone(a.OctetString())
}

// AllOctetString reads every instance of an OctetString AVP.
func (f *Fields) AllOctetString(s AVPSpec) [][]byte {
	var out [][]byte
	for _, a := range f.all(s) {
		out = append(out, bytes.Clone(a.OctetString()))
	}
	return out
}

// Unsigned32 reads an Unsigned32 AVP; absent is 0.
func (f *Fields) Unsigned32(s AVPSpec, need Presence) uint32 {
	a := f.one(s, need)
	if a == nil {
		return 0
	}
	return f.u32(s, a)
}

func (f *Fields) u32(s AVPSpec, a *diameter.AVP) uint32 {
	v, err := a.Unsigned32()
	if err != nil {
		f.invalid(s, a, err)
	}
	return v
}

// AllUnsigned32 reads every instance of an Unsigned32 AVP.
func (f *Fields) AllUnsigned32(s AVPSpec) []uint32 {
	var out []uint32
	for _, a := range f.all(s) {
		out = append(out, f.u32(s, a))
	}
	if f.failed() {
		return nil
	}
	return out
}

// Enumerated reads an Enumerated AVP; absent is 0. Values the specification
// does not list are returned as they are: whether one is acceptable depends on
// the procedure, and newer releases add values.
func (f *Fields) Enumerated(s AVPSpec, need Presence) int32 {
	a := f.one(s, need)
	if a == nil {
		return 0
	}
	return f.enum(s, a)
}

func (f *Fields) enum(s AVPSpec, a *diameter.AVP) int32 {
	v, err := a.Enumerated()
	if err != nil {
		f.invalid(s, a, err)
	}
	return v
}

// AllEnumerated reads every instance of an Enumerated AVP.
func (f *Fields) AllEnumerated(s AVPSpec) []int32 {
	var out []int32
	for _, a := range f.all(s) {
		out = append(out, f.enum(s, a))
	}
	if f.failed() {
		return nil
	}
	return out
}

// DiameterIdentity reads a DiameterIdentity AVP; absent is "".
func (f *Fields) DiameterIdentity(s AVPSpec, need Presence) string {
	a := f.one(s, need)
	if a == nil {
		return ""
	}
	v, err := a.DiameterIdentity()
	if err != nil {
		f.invalid(s, a, err)
	}
	return v
}

// DiameterURI reads a DiameterURI AVP; absent is "".
func (f *Fields) DiameterURI(s AVPSpec, need Presence) string {
	a := f.one(s, need)
	if a == nil {
		return ""
	}
	v, err := a.DiameterURI()
	if err != nil {
		f.invalid(s, a, err)
	}
	return v
}

// Time reads a Time AVP; absent is the zero time.
func (f *Fields) Time(s AVPSpec, need Presence) time.Time {
	a := f.one(s, need)
	if a == nil {
		return time.Time{}
	}
	v, err := a.Time()
	if err != nil {
		f.invalid(s, a, err)
	}
	return v
}

// Grouped returns a reader of the children of a Grouped AVP, or nil when it is
// absent or faulty. Faults found by the returned reader are reported inside
// this AVP.
func (f *Fields) Grouped(s AVPSpec, need Presence) *Fields {
	a := f.one(s, need)
	if a == nil {
		return nil
	}
	return f.child(s, a)
}

func (f *Fields) child(s AVPSpec, a *diameter.AVP) *Fields {
	children, err := a.Grouped()
	if err != nil {
		f.invalid(s, a, err)
		return nil
	}
	return &Fields{avps: children, group: a, parent: f}
}

// AllGrouped returns a reader for each instance of a Grouped AVP.
func (f *Fields) AllGrouped(s AVPSpec) []*Fields {
	var out []*Fields
	for _, a := range f.all(s) {
		if g := f.child(s, a); g != nil {
			out = append(out, g)
		}
	}
	if f.failed() {
		return nil
	}
	return out
}
