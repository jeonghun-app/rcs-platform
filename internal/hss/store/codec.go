package store

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/hss/ifcjson"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

// The stored form of a record is a JSON document with a schema number.
// Backends keep the version and the keys they index on beside it, so the
// document can change shape (schema 2, ...) without a table migration, and
// both backends store exactly the same bytes, which the memory backend
// exercises in every unit test.

// recordSchema is the schema number written; decoding refuses others.
const recordSchema = 1

// MaxRecordSize bounds a stored document. A subscription at the model's
// limits is a few KiB and a profile at ifcjson's limits stays well under
// ifc.MaxDocumentSize; DynamoDB allows 400 KiB per item.
const MaxRecordSize = 192 << 10

type subscriptionRecord struct {
	Schema      int                  `json:"schema"`
	IMPI        string               `json:"impi"`
	IMSI        string               `json:"imsi,omitempty"`
	IMPUs       []identityRecord     `json:"impus"`
	AKA         *akaRecord           `json:"aka,omitempty"`
	Digest      []digestRecord       `json:"digest,omitempty"`
	Profile     string               `json:"profile"`
	Charging    *ChargingInformation `json:"charging,omitempty"`
	ACSManaged  bool                 `json:"acs_managed,omitempty"`
	ServerName  string               `json:"server_name,omitempty"`
	AuthPending bool                 `json:"auth_pending,omitempty"`
}

type identityRecord struct {
	IMPU        string            `json:"impu"`
	Barred      bool              `json:"barred,omitempty"`
	Type        ifc.IdentityType  `json:"type,omitempty"`
	ImplicitSet int               `json:"irs,omitempty"`
	State       RegistrationState `json:"state,omitempty"`
}

type akaRecord struct {
	K   []byte  `json:"k"`
	OPc []byte  `json:"opc"`
	AMF [2]byte `json:"amf"`
	SQN uint64  `json:"sqn"`
}

type digestRecord struct {
	Realm     string `json:"realm"`
	HA1MD5    []byte `json:"ha1_md5"`
	HA1SHA256 []byte `json:"ha1_sha256"`
}

type profileRecord struct {
	Schema    int                 `json:"schema"`
	ID        string              `json:"id"`
	Criteria  []ifcjson.Criterion `json:"criteria"`
	Mandatory []uint32            `json:"mandatory_capabilities,omitempty"`
	Optional  []uint32            `json:"optional_capabilities,omitempty"`
}

// EncodeSubscription returns the stored form of s, without its version.
func EncodeSubscription(s *Subscription) ([]byte, error) {
	if err := ValidateSubscription(s); err != nil {
		return nil, err
	}
	r := subscriptionRecord{
		Schema: recordSchema, IMPI: s.IMPI, IMSI: s.IMSI, Profile: s.Profile, ACSManaged: s.ACSManaged,
		ServerName: s.ServerName, AuthPending: s.AuthPending,
		IMPUs: make([]identityRecord, 0, len(s.PublicIdentities)),
	}
	for _, p := range s.PublicIdentities {
		r.IMPUs = append(r.IMPUs, identityRecord{p.IMPU, p.Barred, p.Type, p.ImplicitSet, p.State})
	}
	if a := s.AKA; a != nil {
		r.AKA = &akaRecord{K: a.K, OPc: a.OPc, AMF: a.AMF, SQN: a.SQN}
	}
	for _, d := range s.Digest {
		r.Digest = append(r.Digest, digestRecord{d.Realm, d.HA1MD5, d.HA1SHA256})
	}
	if c := s.Charging; c != nil {
		cc := *c
		r.Charging = &cc
	}
	return marshalRecord(r)
}

// DecodeSubscription reads a stored subscription and checks it as
// ValidateSubscription does; version is the one the backend stored with it.
func DecodeSubscription(data []byte, version int64) (*Subscription, error) {
	var r subscriptionRecord
	if err := unmarshalRecord(data, &r, &r.Schema); err != nil {
		return nil, err
	}
	s := &Subscription{
		IMPI: r.IMPI, IMSI: r.IMSI, Profile: r.Profile, ACSManaged: r.ACSManaged,
		ServerName: r.ServerName, AuthPending: r.AuthPending, Version: version,
	}
	for _, p := range r.IMPUs {
		s.PublicIdentities = append(s.PublicIdentities, PublicIdentity{p.IMPU, p.Barred, p.Type, p.ImplicitSet, p.State})
	}
	if a := r.AKA; a != nil {
		s.AKA = &AKA{K: a.K, OPc: a.OPc, AMF: a.AMF, SQN: a.SQN}
	}
	for _, d := range r.Digest {
		s.Digest = append(s.Digest, DigestCredential{d.Realm, d.HA1MD5, d.HA1SHA256})
	}
	s.Charging = r.Charging
	if err := ValidateSubscription(s); err != nil {
		return nil, err
	}
	return s, nil
}

// EncodeProfile returns the stored form of p, without its version.
func EncodeProfile(p *ServiceProfile) ([]byte, error) {
	if err := ValidateProfile(p); err != nil {
		return nil, err
	}
	return marshalRecord(profileRecord{
		Schema: recordSchema, ID: p.ID, Criteria: ifcjson.FromIFC(p.Criteria),
		Mandatory: p.MandatoryCapabilities, Optional: p.OptionalCapabilities,
	})
}

// DecodeProfile reads a stored profile. Its criteria were compiled when they
// were written (EncodeProfile), so only their structure is checked here: a
// SAR reads the profile, and the HSS only serialises the criteria.
func DecodeProfile(data []byte, version int64) (*ServiceProfile, error) {
	var r profileRecord
	if err := unmarshalRecord(data, &r, &r.Schema); err != nil {
		return nil, err
	}
	criteria, err := ifcjson.Convert(r.Criteria)
	if err != nil {
		return nil, fmt.Errorf("%w: criteria: %s", ErrInvalid, err)
	}
	p := &ServiceProfile{
		ID: r.ID, Criteria: criteria, MandatoryCapabilities: r.Mandatory,
		OptionalCapabilities: r.Optional, Version: version,
	}
	if err := checkProfile(p); err != nil {
		return nil, err
	}
	return p, nil
}

func marshalRecord(r any) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	if len(data) > MaxRecordSize {
		return nil, fmt.Errorf("%w: record larger than %d bytes", ErrInvalid, MaxRecordSize)
	}
	return data, nil
}

func unmarshalRecord(data []byte, r any, schema *int) error {
	if len(data) > MaxRecordSize {
		return fmt.Errorf("%w: record larger than %d bytes", ErrInvalid, MaxRecordSize)
	}
	if err := ifcjson.DecodeStrict(data, r); err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	if *schema != recordSchema {
		return fmt.Errorf("%w: unknown record schema", ErrInvalid)
	}
	return nil
}

// ValidateSubscription checks the structural rules every stored subscription
// keeps. Formats (what an IMPI or IMPU looks like) are the HSS's to check
// before it writes.
func ValidateSubscription(s *Subscription) error {
	fail := func(format string, a ...any) error {
		return fmt.Errorf("%w: subscription: "+format, append([]any{ErrInvalid}, a...)...)
	}
	switch {
	case s.IMPI == "" || len(s.IMPI) > MaxIdentityLength:
		return fail("IMPI is empty or too long")
	case s.Profile == "" || len(s.Profile) > MaxProfileIDLength:
		return fail("profile is empty or too long")
	case len(s.PublicIdentities) == 0 || len(s.PublicIdentities) > MaxPublicIdentities:
		return fail("needs 1 to %d public identities", MaxPublicIdentities)
	case len(s.Digest) > MaxDigestRealms:
		return fail("more than %d Digest realms", MaxDigestRealms)
	case len(s.IMSI) > 15 || strings.Trim(s.IMSI, "0123456789") != "":
		return fail("IMSI is not up to 15 digits")
	}
	seen := map[string]bool{}
	sets := map[int]RegistrationState{}
	for i, p := range s.PublicIdentities {
		switch {
		case p.IMPU == "" || len(p.IMPU) > MaxIdentityLength:
			return fail("public identity %d is empty or too long", i)
		case seen[p.IMPU]:
			return fail("public identity %d is listed twice", i)
		case p.State > Unregistered:
			return fail("public identity %d has an unknown state", i)
		case p.Type != ifc.IdentityPublicUser:
			return fail("public identity %d is not a distinct public user identity", i)
		case p.ImplicitSet < 0:
			return fail("public identity %d has a negative implicit set", i)
		}
		seen[p.IMPU] = true
		// TS 29.228 §6.5.1: the identities of an implicit registration set
		// change state together.
		if st, ok := sets[p.ImplicitSet]; ok && st != p.State {
			return fail("implicit set %d mixes registration states", p.ImplicitSet)
		}
		sets[p.ImplicitSet] = p.State
	}
	if a := s.AKA; a != nil && (len(a.K) == 0 || len(a.OPc) == 0 || a.SQN >= 1<<48) {
		return fail("AKA credentials are incomplete or SQN exceeds 48 bits")
	}
	realms := map[string]bool{}
	for i, d := range s.Digest {
		if d.Realm == "" || realms[d.Realm] || len(d.HA1MD5) == 0 || len(d.HA1SHA256) == 0 {
			return fail("Digest credential %d is incomplete or repeats a realm", i)
		}
		realms[d.Realm] = true
	}
	return nil
}

// ValidateProfile checks the structural rules every stored profile keeps,
// and that its criteria compile (ifc.Compile), unless p.Compiled shows
// they already have. A set of another number of criteria than p has is
// not taken for theirs: it catches a profile whose criteria were added to
// or cut after compiling, at no cost.
func ValidateProfile(p *ServiceProfile) error {
	if err := checkProfile(p); err != nil {
		return err
	}
	if p.Compiled != nil && p.Compiled.Len() == len(p.Criteria) {
		return nil
	}
	if _, err := ifc.Compile(p.Criteria); err != nil {
		return fmt.Errorf("%w: criteria: %s", ErrInvalid, err)
	}
	return nil
}

func checkProfile(p *ServiceProfile) error {
	switch {
	case p.ID == "" || len(p.ID) > MaxProfileIDLength:
		return fmt.Errorf("%w: profile ID is empty or too long", ErrInvalid)
	case len(p.MandatoryCapabilities) > MaxCapabilities || len(p.OptionalCapabilities) > MaxCapabilities:
		return fmt.Errorf("%w: more than %d capabilities", ErrInvalid, MaxCapabilities)
	case len(p.Criteria) > ifcjson.MaxCriteria:
		return fmt.Errorf("%w: more than %d criteria", ErrInvalid, ifcjson.MaxCriteria)
	}
	return nil
}
