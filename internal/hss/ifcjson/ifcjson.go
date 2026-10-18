// Package ifcjson is the JSON form of initial filter criteria that the HSS
// provisioning API accepts and returns, and that the HSS stores with each
// service profile.
//
// TS 29.228 defines iFC only as XML inside the IMSSubscription document
// (Annex B.2.2, Annex E), which package ifc models. The provisioning API
// speaks JSON (ADR 0002: internal HTTP APIs are JSON under /v1/), so this
// package maps the same model to JSON objects whose field and enumeration
// names follow the XML schema's spelling: an operator who knows the XML can
// read the JSON, and Decode rejects exactly what ifc.Compile rejects, so a
// stored profile always compiles in the S-CSCF.
package ifcjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// MaxCriteria bounds the criteria of one service profile. A profile with tens
// of criteria is already unusual; the limit keeps a profile's User-Data well
// inside ifc.MaxDocumentSize together with its public identities.
const MaxCriteria = 64

// MaxSPTs bounds the service point triggers of one trigger point.
const MaxSPTs = 64

// ErrInvalid reports criteria that are not well-formed JSON, use a name this
// package does not know, or fail ifc.Compile. Wrapping errors say which
// criterion and field is wrong but never quote a value, which may be a
// pattern holding a subscriber identity.
var ErrInvalid = errors.New("ifcjson: invalid filter criteria")

// Criterion is one initial filter criterion (tInitialFilterCriteria).
type Criterion struct {
	Priority int `json:"priority"`
	// TriggerPoint is absent for a criterion that always matches.
	TriggerPoint      *TriggerPoint     `json:"trigger_point,omitempty"`
	ApplicationServer ApplicationServer `json:"application_server"`
	// ProfilePartIndicator is "REGISTERED", "UNREGISTERED" or absent (both).
	ProfilePartIndicator string `json:"profile_part_indicator,omitempty"`
}

// TriggerPoint is a tTrigger. CNF is ConditionTypeCNF: conjunctive normal
// form when true, disjunctive otherwise (TS 29.228 Annex C).
type TriggerPoint struct {
	CNF  bool  `json:"condition_type_cnf"`
	SPTs []SPT `json:"spt"`
}

// SPT is one service point trigger (tSePoTri). Exactly one of the condition
// fields is set.
type SPT struct {
	ConditionNegated bool  `json:"condition_negated,omitempty"`
	Groups           []int `json:"group"`

	RequestURI         *string             `json:"request_uri,omitempty"`
	Method             *string             `json:"method,omitempty"`
	SIPHeader          *SIPHeader          `json:"sip_header,omitempty"`
	SessionCase        *string             `json:"session_case,omitempty"`
	SessionDescription *SessionDescription `json:"session_description,omitempty"`

	// RegistrationType narrows a Method "REGISTER" trigger:
	// "INITIAL_REGISTRATION", "RE-REGISTRATION" or "DE-REGISTRATION".
	RegistrationType []string `json:"registration_type,omitempty"`
}

// SIPHeader is a header trigger; an empty Content tests presence only.
type SIPHeader struct {
	Header  string `json:"header"`
	Content string `json:"content,omitempty"`
}

// SessionDescription is an SDP trigger.
type SessionDescription struct {
	Line    string `json:"line"`
	Content string `json:"content,omitempty"`
}

// ApplicationServer is a tApplicationServer.
type ApplicationServer struct {
	ServerName string `json:"server_name"`
	// DefaultHandling is "SESSION_CONTINUED" or "SESSION_TERMINATED"; it is
	// required because TS 29.228 gives no default for it.
	DefaultHandling         string `json:"default_handling"`
	ServiceInfo             string `json:"service_info,omitempty"`
	IncludeRegisterRequest  bool   `json:"include_register_request,omitempty"`
	IncludeRegisterResponse bool   `json:"include_register_response,omitempty"`
}

// Enumeration spellings, from the value lists of TS 29.228 Table E.2.
var (
	sessionCases = map[string]ifc.SessionCase{
		"ORIGINATING_REGISTERED":   ifc.Originating,
		"TERMINATING_REGISTERED":   ifc.TerminatingRegistered,
		"TERMINATING_UNREGISTERED": ifc.TerminatingUnregistered,
		"ORIGINATING_UNREGISTERED": ifc.OriginatingUnregistered,
		"ORIGINATING_CDIV":         ifc.OriginatingCDIV,
	}
	registrationTypes = map[string]ifc.RegistrationType{
		"INITIAL_REGISTRATION": ifc.InitialRegistration,
		"RE-REGISTRATION":      ifc.ReRegistration,
		"DE-REGISTRATION":      ifc.DeRegistration,
	}
	defaultHandlings = map[string]ifc.DefaultHandling{
		"SESSION_CONTINUED":  ifc.SessionContinued,
		"SESSION_TERMINATED": ifc.SessionTerminated,
	}
	profileParts = map[string]ifc.ProfilePart{
		"":             ifc.ProfilePartAny,
		"REGISTERED":   ifc.ProfilePartRegistered,
		"UNREGISTERED": ifc.ProfilePartUnregistered,
	}
)

func nameOf[V comparable](m map[string]V, v V) string {
	for k, mv := range m {
		if mv == v {
			return k
		}
	}
	return ""
}

// FromIFC converts criteria to their JSON form. Values outside the
// enumerations, which ifc.Compile would refuse anyway, become empty names.
func FromIFC(criteria []ifc.FilterCriteria) []Criterion {
	out := make([]Criterion, 0, len(criteria))
	for i := range criteria {
		fc := &criteria[i]
		as := fc.ApplicationServer
		c := Criterion{
			Priority: fc.Priority,
			ApplicationServer: ApplicationServer{
				ServerName:              as.ServerName,
				DefaultHandling:         nameOf(defaultHandlings, as.DefaultHandling),
				ServiceInfo:             as.ServiceInfo,
				IncludeRegisterRequest:  as.IncludeRegisterRequest,
				IncludeRegisterResponse: as.IncludeRegisterResponse,
			},
			ProfilePartIndicator: nameOf(profileParts, fc.ProfilePart),
		}
		if tp := fc.TriggerPoint; tp != nil {
			c.TriggerPoint = &TriggerPoint{CNF: tp.ConditionTypeCNF, SPTs: make([]SPT, 0, len(tp.SPTs))}
			for _, spt := range tp.SPTs {
				c.TriggerPoint.SPTs = append(c.TriggerPoint.SPTs, fromSPT(spt))
			}
		}
		out = append(out, c)
	}
	return out
}

func fromSPT(spt ifc.SPT) SPT {
	s := SPT{ConditionNegated: spt.ConditionNegated, Groups: append([]int(nil), spt.Groups...)}
	if s.Groups == nil {
		s.Groups = []int{}
	}
	for _, t := range spt.RegistrationTypes {
		s.RegistrationType = append(s.RegistrationType, nameOf(registrationTypes, t))
	}
	switch c := spt.Condition.(type) {
	case ifc.RequestURI:
		v := string(c)
		s.RequestURI = &v
	case ifc.Method:
		v := string(c)
		s.Method = &v
	case ifc.SIPHeader:
		s.SIPHeader = &SIPHeader{Header: c.Header, Content: c.Content}
	case ifc.SessionCase:
		v := nameOf(sessionCases, c)
		s.SessionCase = &v
	case ifc.SessionDescription:
		s.SessionDescription = &SessionDescription{Line: c.Line, Content: c.Content}
	}
	return s
}

// ToIFC converts criteria from their JSON form and checks them with
// ifc.Compile, so that what it returns is what an S-CSCF can evaluate.
// Errors wrap ErrInvalid.
func ToIFC(criteria []Criterion) ([]ifc.FilterCriteria, error) {
	out, err := Convert(criteria)
	if err != nil {
		return nil, err
	}
	if _, err := ifc.Compile(out); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	return out, nil
}

// Convert converts criteria from their JSON form, checking only their
// structure (names, one condition per trigger, the counts), not their
// patterns. It is for criteria ToIFC accepted when they were written, such
// as a stored profile: compiling them again on every read would cost the
// HSS milliseconds per SAR for nothing, since it never evaluates them.
// Errors wrap ErrInvalid.
func Convert(criteria []Criterion) ([]ifc.FilterCriteria, error) {
	if len(criteria) > MaxCriteria {
		return nil, fmt.Errorf("%w: more than %d criteria", ErrInvalid, MaxCriteria)
	}
	out := make([]ifc.FilterCriteria, 0, len(criteria))
	for i := range criteria {
		fc, err := criteria[i].toIFC()
		if err != nil {
			return nil, fmt.Errorf("%w: criterion %d: %s", ErrInvalid, i, err)
		}
		out = append(out, fc)
	}
	return out, nil
}

func (c *Criterion) toIFC() (ifc.FilterCriteria, error) {
	part, ok := profileParts[c.ProfilePartIndicator]
	if !ok {
		return ifc.FilterCriteria{}, errors.New("profile_part_indicator is not REGISTERED or UNREGISTERED")
	}
	dh, ok := defaultHandlings[c.ApplicationServer.DefaultHandling]
	if !ok {
		return ifc.FilterCriteria{}, errors.New("application_server.default_handling is not SESSION_CONTINUED or SESSION_TERMINATED")
	}
	fc := ifc.FilterCriteria{
		Priority: c.Priority,
		ApplicationServer: ifc.ApplicationServer{
			ServerName:              c.ApplicationServer.ServerName,
			DefaultHandling:         dh,
			ServiceInfo:             c.ApplicationServer.ServiceInfo,
			IncludeRegisterRequest:  c.ApplicationServer.IncludeRegisterRequest,
			IncludeRegisterResponse: c.ApplicationServer.IncludeRegisterResponse,
		},
		ProfilePart: part,
	}
	if tp := c.TriggerPoint; tp != nil {
		if len(tp.SPTs) > MaxSPTs {
			return ifc.FilterCriteria{}, fmt.Errorf("trigger_point has more than %d spt", MaxSPTs)
		}
		fc.TriggerPoint = &ifc.TriggerPoint{ConditionTypeCNF: tp.CNF}
		for j := range tp.SPTs {
			spt, err := tp.SPTs[j].toIFC()
			if err != nil {
				return ifc.FilterCriteria{}, fmt.Errorf("spt %d: %s", j, err)
			}
			fc.TriggerPoint.SPTs = append(fc.TriggerPoint.SPTs, spt)
		}
	}
	return fc, nil
}

func (s *SPT) toIFC() (ifc.SPT, error) {
	spt := ifc.SPT{ConditionNegated: s.ConditionNegated, Groups: append([]int(nil), s.Groups...)}
	for _, name := range s.RegistrationType {
		t, ok := registrationTypes[name]
		if !ok {
			return ifc.SPT{}, errors.New("registration_type is not INITIAL_REGISTRATION, RE-REGISTRATION or DE-REGISTRATION")
		}
		spt.RegistrationTypes = append(spt.RegistrationTypes, t)
	}
	n := 0
	if s.RequestURI != nil {
		n++
		spt.Condition = ifc.RequestURI(*s.RequestURI)
	}
	if s.Method != nil {
		n++
		spt.Condition = ifc.Method(*s.Method)
	}
	if s.SIPHeader != nil {
		n++
		spt.Condition = ifc.SIPHeader{Header: s.SIPHeader.Header, Content: s.SIPHeader.Content}
	}
	if s.SessionCase != nil {
		n++
		sc, ok := sessionCases[*s.SessionCase]
		if !ok {
			return ifc.SPT{}, errors.New("session_case is not a tDirectionOfRequest name")
		}
		spt.Condition = sc
	}
	if s.SessionDescription != nil {
		n++
		spt.Condition = ifc.SessionDescription{Line: s.SessionDescription.Line, Content: s.SessionDescription.Content}
	}
	if n != 1 {
		return ifc.SPT{}, errors.New("needs exactly one of request_uri, method, sip_header, session_case, session_description")
	}
	return spt, nil
}

// Decode reads a JSON array of criteria strictly (unknown fields and
// trailing data are errors) and converts it with ToIFC.
func Decode(data []byte) ([]ifc.FilterCriteria, error) {
	var criteria []Criterion
	if err := DecodeStrict(data, &criteria); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	return ToIFC(criteria)
}

// Encode writes criteria as a JSON array.
func Encode(criteria []ifc.FilterCriteria) ([]byte, error) {
	return json.Marshal(FromIFC(criteria))
}

// DecodeStrict unmarshals exactly one JSON value into v, refusing unknown
// fields, a key repeated in an object (encoding/json keeps the last, so
// {"acs_managed":false,"acs_managed":true} would read as true while a
// reviewer of the body sees false) and anything after the value. Its errors
// describe the position and the JSON type involved, never the value.
func DecodeStrict(data []byte, v any) error {
	if err := noDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return describe(err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON value")
	}
	return exactKeys(data, reflect.TypeOf(v))
}

// exactKeys fails on an object key that is not spelled exactly as the field
// it fills: encoding/json matches field names without regard to case,
// Unicode folding included (ſ for s, K for k), so {"acs_managed":false,
// "ACS_MANAGED":true} has no repeated key and yet sets acs_managed to true.
// Only the API's own spelling is accepted. data has already decoded into t.
func exactKeys(data []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var obj map[string]json.RawMessage
		if json.Unmarshal(data, &obj) != nil {
			return nil // null, which decoded as the zero value
		}
		fields := map[string]reflect.Type{}
		structFields(t, fields)
		for name, raw := range obj {
			ft, ok := fields[name]
			if !ok {
				return errors.New("a field name is not spelled as the API defines it")
			}
			if err := exactKeys(raw, ft); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil // bytes: a base64 string or an array of numbers
		}
		var items []json.RawMessage
		if json.Unmarshal(data, &items) != nil {
			return nil
		}
		for _, raw := range items {
			if err := exactKeys(raw, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		// Keys of a map are data, not field names.
		var obj map[string]json.RawMessage
		if json.Unmarshal(data, &obj) != nil {
			return nil
		}
		for _, raw := range obj {
			if err := exactKeys(raw, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// structFields collects the JSON names of t's fields, those of embedded
// structs included, as encoding/json does.
func structFields(t reflect.Type, out map[string]reflect.Type) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			ft := f.Type
			if ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				structFields(ft, out)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
}

// noDuplicateKeys walks the tokens of data and fails on an object key that
// occurs twice in one object. Malformed JSON is left to the decoder, which
// describes it.
func noDuplicateKeys(data []byte) error {
	type frame struct {
		object, wantKey bool
		keys            map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*frame
	value := func() {
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].wantKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil
		}
		top := (*frame)(nil)
		if n := len(stack); n > 0 {
			top = stack[n-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if top != nil && top.object {
					top.wantKey = false
				}
				stack = append(stack, &frame{object: true, wantKey: true, keys: map[string]bool{}})
			case '[':
				if top != nil && top.object {
					top.wantKey = false
				}
				stack = append(stack, &frame{})
			default:
				stack = stack[:len(stack)-1]
				value()
			}
		default:
			if top != nil && top.object && top.wantKey {
				key, _ := t.(string)
				if top.keys[key] {
					return errors.New("a key occurs twice in a JSON object")
				}
				top.keys[key] = true
				top.wantKey = false
				continue
			}
			value()
		}
	}
}

// describe reduces a decoding error to what is safe to show: encoding/json
// quotes offending values for some errors.
func describe(err error) error {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return fmt.Errorf("malformed JSON at offset %d", syntax.Offset)
	case errors.As(err, &typ):
		if typ.Field != "" {
			return fmt.Errorf("field %s must not be a JSON %s", typ.Field, typ.Value)
		}
		return fmt.Errorf("a JSON %s is not allowed at offset %d", typ.Value, typ.Offset)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("truncated JSON")
	default:
		// Unknown fields: the message is `json: unknown field "name"`; the
		// name is chosen by the client and may be anything, so leave it out.
		return errors.New("unknown field or invalid JSON")
	}
}
