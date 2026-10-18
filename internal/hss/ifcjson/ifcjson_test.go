package ifcjson

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

const impu = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"

func every() []ifc.FilterCriteria {
	return []ifc.FilterCriteria{
		{
			Priority: 1,
			TriggerPoint: &ifc.TriggerPoint{ConditionTypeCNF: true, SPTs: []ifc.SPT{
				{Groups: []int{0}, Condition: ifc.Method("REGISTER"), RegistrationTypes: []ifc.RegistrationType{ifc.InitialRegistration, ifc.DeRegistration}},
				{Groups: []int{0, 1}, ConditionNegated: true, Condition: ifc.SIPHeader{Header: "Accept-Contact", Content: "icsi\\.oma\\.cpm"}},
				{Groups: []int{1}, Condition: ifc.SIPHeader{Header: "P-Asserted-Service"}},
				{Groups: []int{2}, Condition: ifc.RequestURI("^conf\\.")},
				{Groups: []int{2}, Condition: ifc.SessionCase(ifc.TerminatingUnregistered)},
				{Groups: []int{3}, Condition: ifc.SessionDescription{Line: "m", Content: "message"}},
				{Groups: []int{3}, Condition: ifc.SessionDescription{Line: "a"}},
			}},
			ApplicationServer: ifc.ApplicationServer{
				ServerName: "sip:rcs-as.rcs.local", DefaultHandling: ifc.SessionTerminated, ServiceInfo: "chat",
				IncludeRegisterRequest: true, IncludeRegisterResponse: true,
			},
			ProfilePart: ifc.ProfilePartRegistered,
		},
		{Priority: 2, ApplicationServer: ifc.ApplicationServer{ServerName: "sip:as.example.org"}, ProfilePart: ifc.ProfilePartUnregistered},
		{Priority: 3, ApplicationServer: ifc.ApplicationServer{ServerName: "sip:as.example.org"}},
	}
}

func TestCriteriaSurviveARoundTripThroughJSON(t *testing.T) {
	want := every()
	data, err := Encode(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode(%s): %v", data, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip changed the criteria:\n got %+v\nwant %+v", got, want)
	}
}

func TestJSONUsesTheSchemaSpelling(t *testing.T) {
	data, err := Encode(every()[:1])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		`"condition_type_cnf":true`, `"registration_type":["INITIAL_REGISTRATION","DE-REGISTRATION"]`,
		`"session_case":"TERMINATING_UNREGISTERED"`, `"default_handling":"SESSION_TERMINATED"`,
		`"profile_part_indicator":"REGISTERED"`, `"condition_negated":true`,
	} {
		if !strings.Contains(string(data), name) {
			t.Errorf("%s not in %s", name, data)
		}
	}
}

func TestDecodeRefusesWhatTheSCSCFCouldNotEvaluate(t *testing.T) {
	as := `"application_server":{"server_name":"sip:as","default_handling":"SESSION_CONTINUED"}`
	tp := func(spt string) string {
		return `[{"priority":1,"trigger_point":{"condition_type_cnf":false,"spt":[` + spt + `]},` + as + `}]`
	}
	many := make([]string, MaxCriteria+1)
	for i := range many {
		many[i] = fmt.Sprintf(`{"priority":%d,%s}`, i, as)
	}
	spts := make([]string, MaxSPTs+1)
	for i := range spts {
		spts[i] = `{"group":[0],"method":"INVITE"}`
	}
	for name, doc := range map[string]string{
		"not JSON":              `[{`,
		"not an array":          `{"priority":1}`,
		"unknown field":         `[{"priority":1,"colour":"red",` + as + `}]`,
		"trailing data":         `[] []`,
		"fractional priority":   `[{"priority":1.5,` + as + `}]`,
		"duplicate priority":    `[{"priority":1,` + as + `},{"priority":1,` + as + `}]`,
		"no default handling":   `[{"priority":1,"application_server":{"server_name":"sip:as"}}]`,
		"bad default handling":  `[{"priority":1,"application_server":{"server_name":"sip:as","default_handling":"MAYBE"}}]`,
		"bad profile part":      `[{"priority":1,"profile_part_indicator":"SOMETIMES",` + as + `}]`,
		"no server name":        `[{"priority":1,"application_server":{"default_handling":"SESSION_CONTINUED"}}]`,
		"no condition":          tp(`{"group":[0]}`),
		"two conditions":        tp(`{"group":[0],"method":"INVITE","request_uri":"x"}`),
		"no group":              tp(`{"method":"INVITE"}`),
		"negative group":        tp(`{"group":[-1],"method":"INVITE"}`),
		"bad session case":      tp(`{"group":[0],"session_case":"SIDEWAYS"}`),
		"bad registration type": tp(`{"group":[0],"method":"REGISTER","registration_type":["ALWAYS"]}`),
		"not a POSIX pattern":   tp(`{"group":[0],"request_uri":"\\d+"}`),
		"empty trigger point":   `[{"priority":1,"trigger_point":{"condition_type_cnf":true,"spt":[]},` + as + `}]`,
		"too many criteria":     "[" + strings.Join(many, ",") + "]",
		"too many spt":          tp(strings.Join(spts, ",")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(doc)); !errors.Is(err, ErrInvalid) {
				t.Errorf("Decode = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestDecodeErrorsDoNotQuoteTheInput(t *testing.T) {
	for _, doc := range []string{
		`[{"priority":1,"trigger_point":{"condition_type_cnf":false,"spt":[{"group":[0],"request_uri":"` + impu + `(\\d"}]},` +
			`"application_server":{"server_name":"sip:as","default_handling":"SESSION_CONTINUED"}}]`,
		`[{"` + impu + `":1}]`,
		`[{"priority":"` + impu + `"}]`,
		`["` + impu,
	} {
		_, err := Decode([]byte(doc))
		if err == nil {
			t.Fatalf("Decode(%s) succeeded", doc)
		}
		if strings.Contains(err.Error(), "15550100001") {
			t.Errorf("error quotes the input: %v", err)
		}
	}
}

func TestEmptyCriteriaAreAnEmptyArray(t *testing.T) {
	data, err := Encode(nil)
	if err != nil || string(data) != "[]" {
		t.Errorf("Encode(nil) = %s, %v", data, err)
	}
	got, err := Decode([]byte("[]"))
	if err != nil || len(got) != 0 {
		t.Errorf("Decode([]) = %v, %v", got, err)
	}
}
