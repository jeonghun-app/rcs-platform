package ifc

import (
	"encoding/xml"
	"fmt"
	"strconv"
)

// ParseSubscription parses an IMSSubscription document, normally the
// User-Data of a Cx Server-Assignment-Answer or Push-Profile-Request. It
// returns ErrTooLarge, ErrDTD or an error wrapping ErrMalformed.
//
// The patterns in the criteria are not compiled here; [Compile] does that,
// so that one bad pattern is reported where the criteria are used.
func ParseSubscription(data []byte) (*Subscription, error) {
	data = withoutBOM(data)
	if err := checkDocument(data); err != nil {
		return nil, err
	}
	var w wireSubscription
	if err := xml.Unmarshal(data, &w); err != nil {
		return nil, decodeError(err)
	}
	r := &reader{}
	s := r.subscription(&w)
	if r.err != nil {
		return nil, r.err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// reader converts wire values to the model, keeping the first problem. Its
// messages name the element and its position, never its content.
type reader struct {
	err error
}

func (r *reader) fail(where, format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf("%w: %s: %s", ErrMalformed, where, fmt.Sprintf(format, args...))
	}
}

func at(parent, element string, i int) string {
	return fmt.Sprintf("%s/%s[%d]", parent, element, i+1)
}

// one returns the only value of an element that occurs at most once.
func (r *reader) one(where, name string, values []string, required bool) (string, bool) {
	switch {
	case len(values) > 1:
		r.fail(where, "%s occurs more than once", name)
	case len(values) == 1:
		return values[0], true
	case required:
		r.fail(where, "%s is missing", name)
	}
	return "", false
}

// atMostOne reports an element of a complex type that occurs twice.
func atMostOne[T any](r *reader, where, name string, values []T) *T {
	if len(values) > 1 {
		r.fail(where, "%s occurs more than once", name)
		return nil
	}
	if len(values) == 1 {
		return &values[0]
	}
	return nil
}

func (r *reader) str(where, name string, values []string, required bool) string {
	v, _ := r.one(where, name, values, required)
	return v
}

func (r *reader) uri(where, name string, values []string, required bool) string {
	v, ok := r.one(where, name, values, required)
	v = collapse(v)
	if ok && required && v == "" {
		r.fail(where, "%s is empty", name)
	}
	return v
}

// integer reads an xs:integer limited to [lo, hi].
func (r *reader) integer(where, name, value string, lo, hi int) int {
	n, err := strconv.Atoi(collapse(value))
	if err != nil || n < lo || n > hi {
		r.fail(where, "%s is not an integer from %d to %d", name, lo, hi)
		return 0
	}
	return n
}

func (r *reader) optionalInteger(where, name string, values []string, lo, hi int) (int, bool) {
	v, ok := r.one(where, name, values, false)
	if !ok {
		return 0, false
	}
	return r.integer(where, name, v, lo, hi), true
}

func (r *reader) requiredInteger(where, name string, values []string, lo, hi int) int {
	v, ok := r.one(where, name, values, true)
	if !ok {
		return 0
	}
	return r.integer(where, name, v, lo, hi)
}

// boolean reads a tBool, an xs:boolean: TS 29.228 writes 0 and 1, the schema
// type also allows false and true.
func (r *reader) boolean(where, name string, values []string, required bool) bool {
	v, ok := r.one(where, name, values, required)
	if !ok {
		return false
	}
	switch collapse(v) {
	case "1", "true":
		return true
	case "0", "false":
		return false
	}
	r.fail(where, "%s is not a boolean", name)
	return false
}

const maxInt = int(^uint(0) >> 1)

func (r *reader) subscription(w *wireSubscription) *Subscription {
	const where = "IMSSubscription"
	s := &Subscription{PrivateID: r.uri(where, "PrivateID", w.PrivateID, true)}
	for i := range w.ServiceProfile {
		s.ServiceProfiles = append(s.ServiceProfiles, r.serviceProfile(at(where, "ServiceProfile", i), &w.ServiceProfile[i]))
	}
	return s
}

func (r *reader) serviceProfile(where string, w *wireServiceProfile) ServiceProfile {
	var p ServiceProfile
	for i := range w.PublicIdentity {
		p.PublicIdentities = append(p.PublicIdentities, r.publicIdentity(at(where, "PublicIdentity", i), &w.PublicIdentity[i]))
	}
	if c := atMostOne(r, where, "CoreNetworkServicesAuthorization", w.CoreNetworkServicesAuthorization); c != nil {
		p.CoreNetworkServicesAuthorization = &CoreNetworkServicesAuthorization{}
		if id, ok := r.optionalInteger(where, "SubscribedMediaProfileId", c.SubscribedMediaProfileID, 0, maxInt); ok {
			p.CoreNetworkServicesAuthorization.SubscribedMediaProfileID = &id
		}
	}
	for i := range w.InitialFilterCriteria {
		p.InitialFilterCriteria = append(p.InitialFilterCriteria, r.filterCriteria(at(where, "InitialFilterCriteria", i), &w.InitialFilterCriteria[i]))
	}
	if ext := atMostOne(r, where, "Extension", w.Extension); ext != nil {
		for _, v := range ext.SharedIFCSetID {
			p.SharedIFCSetIDs = append(p.SharedIFCSetIDs, r.integer(where, "SharedIFCSetID", v, 0, maxInt))
		}
	}
	return p
}

func (r *reader) publicIdentity(where string, w *wirePublicIdentity) PublicIdentity {
	id := PublicIdentity{
		BarringIndication: r.boolean(where, "BarringIndication", w.BarringIndication, false),
		Identity:          r.uri(where, "Identity", w.Identity, true),
	}
	ext := atMostOne(r, where, "Extension", w.Extension)
	if ext == nil {
		return id
	}
	if t, ok := r.optionalInteger(where, "IdentityType", ext.IdentityType, int(IdentityPublicUser), int(IdentityWildcardedIMPU)); ok {
		id.IdentityType = IdentityType(t)
	}
	id.WildcardedPSI = r.uri(where, "WildcardedPSI", ext.WildcardedPSI, false)
	ext2 := atMostOne(r, where, "Extension/Extension", ext.Extension)
	if ext2 == nil {
		return id
	}
	id.DisplayName = r.str(where, "DisplayName", ext2.DisplayName, false)
	id.AliasIdentityGroupID = r.str(where, "AliasIdentityGroupID", ext2.AliasIdentityGroupID, false)
	if ext3 := atMostOne(r, where, "Extension/Extension/Extension", ext2.Extension); ext3 != nil {
		id.WildcardedIMPU = r.uri(where, "WildcardedIMPU", ext3.WildcardedIMPU, false)
	}
	return id
}

func (r *reader) filterCriteria(where string, w *wireFilterCriteria) FilterCriteria {
	fc := FilterCriteria{Priority: r.requiredInteger(where, "Priority", w.Priority, 0, maxInt)}
	if tp := atMostOne(r, where, "TriggerPoint", w.TriggerPoint); tp != nil {
		fc.TriggerPoint = r.triggerPoint(where+"/TriggerPoint", tp)
	}
	switch as := atMostOne(r, where, "ApplicationServer", w.ApplicationServer); {
	case as != nil:
		fc.ApplicationServer = r.applicationServer(where+"/ApplicationServer", as)
	case r.err == nil:
		r.fail(where, "ApplicationServer is missing")
	}
	// Wire 0 is REGISTERED and 1 UNREGISTERED; absence is the common part.
	if v, ok := r.optionalInteger(where, "ProfilePartIndicator", w.ProfilePartIndicator, 0, 1); ok {
		fc.ProfilePart = ProfilePartRegistered + ProfilePart(v)
	}
	return fc
}

func (r *reader) triggerPoint(where string, w *wireTriggerPoint) *TriggerPoint {
	tp := &TriggerPoint{ConditionTypeCNF: r.boolean(where, "ConditionTypeCNF", w.ConditionTypeCNF, true)}
	for i := range w.SPT {
		tp.SPTs = append(tp.SPTs, r.spt(at(where, "SPT", i), &w.SPT[i]))
	}
	return tp
}

func (r *reader) spt(where string, w *wireSPT) SPT {
	spt := SPT{ConditionNegated: r.boolean(where, "ConditionNegated", w.ConditionNegated, false)}
	for _, g := range w.Group {
		spt.Groups = append(spt.Groups, r.integer(where, "Group", g, 0, maxInt))
	}
	if n := len(w.RequestURI) + len(w.Method) + len(w.SIPHeader) + len(w.SessionCase) + len(w.SessionDescription); n != 1 {
		r.fail(where, "has %d conditions, want exactly one", n)
		return spt
	}
	switch {
	case len(w.RequestURI) == 1:
		spt.Condition = RequestURI(w.RequestURI[0])
	case len(w.Method) == 1:
		spt.Condition = Method(w.Method[0])
	case len(w.SIPHeader) == 1:
		h := w.SIPHeader[0]
		spt.Condition = SIPHeader{
			Header:  r.str(where, "SIPHeader/Header", h.Header, true),
			Content: r.str(where, "SIPHeader/Content", h.Content, false),
		}
	case len(w.SessionCase) == 1:
		spt.Condition = SessionCase(r.integer(where, "SessionCase", w.SessionCase[0], int(Originating), int(OriginatingCDIV)))
	default:
		d := w.SessionDescription[0]
		spt.Condition = SessionDescription{
			Line:    r.str(where, "SessionDescription/Line", d.Line, true),
			Content: r.str(where, "SessionDescription/Content", d.Content, false),
		}
	}
	if ext := atMostOne(r, where, "Extension", w.Extension); ext != nil {
		// Table E.2 allows two; with three, one kind would be repeated.
		if len(ext.RegistrationType) > 2 {
			r.fail(where, "RegistrationType occurs more than twice")
		}
		for _, v := range ext.RegistrationType {
			spt.RegistrationTypes = append(spt.RegistrationTypes,
				RegistrationType(r.integer(where, "RegistrationType", v, int(InitialRegistration), int(DeRegistration))))
		}
	}
	return spt
}

func (r *reader) applicationServer(where string, w *wireApplicationServer) ApplicationServer {
	as := ApplicationServer{
		ServerName:  r.uri(where, "ServerName", w.ServerName, true),
		ServiceInfo: r.str(where, "ServiceInfo", w.ServiceInfo, false),
	}
	if v, ok := r.optionalInteger(where, "DefaultHandling", w.DefaultHandling, int(SessionContinued), int(SessionTerminated)); ok {
		as.DefaultHandling = DefaultHandling(v)
	}
	if ext := atMostOne(r, where, "Extension", w.Extension); ext != nil {
		if len(ext.IncludeRegisterRequest) > 1 || len(ext.IncludeRegisterResponse) > 1 {
			r.fail(where, "IncludeRegisterRequest or IncludeRegisterResponse occurs more than once")
		}
		as.IncludeRegisterRequest = len(ext.IncludeRegisterRequest) == 1
		as.IncludeRegisterResponse = len(ext.IncludeRegisterResponse) == 1
	}
	return as
}
