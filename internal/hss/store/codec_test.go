package store_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store/storetest"
	"github.com/jeonghun-app/rcs-platform/internal/ifc"
)

func TestValidateSubscriptionRefusesBrokenRecords(t *testing.T) {
	base := func() *store.Subscription { return storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1) }
	tooMany := base()
	for i := range store.MaxPublicIdentities {
		tooMany.PublicIdentities = append(tooMany.PublicIdentities, store.PublicIdentity{IMPU: fmt.Sprintf("sip:u%d@x", i)})
	}
	for name, mutate := range map[string]func(*store.Subscription){
		"no IMPI":             func(s *store.Subscription) { s.IMPI = "" },
		"long IMPI":           func(s *store.Subscription) { s.IMPI = strings.Repeat("a", store.MaxIdentityLength+1) },
		"no profile":          func(s *store.Subscription) { s.Profile = "" },
		"no identities":       func(s *store.Subscription) { s.PublicIdentities = nil },
		"too many identities": func(s *store.Subscription) { *s = *tooMany },
		"identity twice":      func(s *store.Subscription) { s.PublicIdentities = append(s.PublicIdentities, s.PublicIdentities[0]) },
		"empty identity":      func(s *store.Subscription) { s.PublicIdentities[0].IMPU = "" },
		"unknown state":       func(s *store.Subscription) { s.PublicIdentities[0].State = 7 },
		"PSI":                 func(s *store.Subscription) { s.PublicIdentities[0].Type = ifc.IdentityDistinctPSI },
		"negative set":        func(s *store.Subscription) { s.PublicIdentities[0].ImplicitSet = -1 },
		"letters in IMSI":     func(s *store.Subscription) { s.IMSI = "00101abc" },
		"long IMSI":           func(s *store.Subscription) { s.IMSI = storetest.IMSI1 + "1" },
		"AKA without OPc":     func(s *store.Subscription) { s.AKA = &store.AKA{K: store.Sealed{1}} },
		"SQN beyond 48 bits": func(s *store.Subscription) {
			s.AKA = &store.AKA{K: store.Sealed{1}, OPc: store.Sealed{1}, SQN: 1 << 48}
		},
		"Digest without realm": func(s *store.Subscription) {
			s.Digest = []store.DigestCredential{{HA1MD5: store.Sealed{1}, HA1SHA256: store.Sealed{1}}}
		},
		"Digest realm twice": func(s *store.Subscription) {
			d := store.DigestCredential{Realm: "r", HA1MD5: store.Sealed{1}, HA1SHA256: store.Sealed{1}}
			s.Digest = []store.DigestCredential{d, d}
		},
		"implicit set with two states": func(s *store.Subscription) {
			s.PublicIdentities = append(s.PublicIdentities, store.PublicIdentity{IMPU: storetest.TEL1, State: store.Registered})
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := base()
			mutate(s)
			if err := store.ValidateSubscription(s); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("ValidateSubscription = %v, want ErrInvalid", err)
			}
			if _, err := store.EncodeSubscription(s); !errors.Is(err, store.ErrInvalid) {
				t.Errorf("EncodeSubscription = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestDecodeRefusesForeignDocuments(t *testing.T) {
	good, err := store.EncodeSubscription(storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1))
	if err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"not JSON":         "{",
		"other schema":     strings.Replace(string(good), `"schema":1`, `"schema":2`, 1),
		"unknown field":    strings.Replace(string(good), `"schema":1`, `"schema":1,"extra":true`, 1),
		"broken invariant": strings.Replace(string(good), `"impus":[`, `"impus":[{"impu":"`+storetest.IMPU1+`"},`, 1),
		"too large":        `{"schema":1,"impi":"` + strings.Repeat("a", store.MaxRecordSize) + `"}`,
	} {
		if _, err := store.DecodeSubscription([]byte(doc), 1); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%s: DecodeSubscription = %v, want ErrInvalid", name, err)
		}
	}
	if _, err := store.DecodeProfile([]byte(`{"schema":1,"id":"p","criteria":[{"priority":1}]}`), 1); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("DecodeProfile accepted criteria without an application server: %v", err)
	}
}

func TestStoredFormNeverHoldsTheSealedPlaceholder(t *testing.T) {
	s := storetest.Subscription(storetest.IMPI1, "p", storetest.IMPU1)
	s.AKA = &store.AKA{K: store.Sealed("kkkk"), OPc: store.Sealed("oooo")}
	doc, err := store.EncodeSubscription(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc), "[sealed]") {
		t.Fatalf("the stored form used the log placeholder: %s", doc)
	}
	back, err := store.DecodeSubscription(doc, 3)
	if err != nil || string(back.AKA.K) != "kkkk" || back.Version != 3 {
		t.Fatalf("round trip = %+v, %v", back, err)
	}
}

func TestSealedValuesPrintAsAPlaceholder(t *testing.T) {
	v := store.Sealed("secret bytes")
	for _, s := range []string{fmt.Sprint(v), fmt.Sprintf("%x", v), fmt.Sprintf("%#v", v), fmt.Sprintf("%+v", store.AKA{K: v})} {
		if strings.Contains(s, "secret") || strings.Contains(s, "736563726574") {
			t.Errorf("printed %q", s)
		}
	}
}

func TestRegistrationStatesHaveTheirSpecNames(t *testing.T) {
	for st, want := range map[store.RegistrationState]string{
		store.NotRegistered: "NOT_REGISTERED", store.Registered: "REGISTERED", store.Unregistered: "UNREGISTERED", 9: "RegistrationState(9)",
	} {
		if st.String() != want {
			t.Errorf("%d = %s, want %s", st, st, want)
		}
	}
	if store.NotRegistered.Served() || !store.Registered.Served() || !store.Unregistered.Served() {
		t.Error("Served is wrong")
	}
}

// A stored profile's criteria were compiled when they were written; reading
// it compiles nothing, which this shows with criteria that would not compile.
func TestReadingAProfileDoesNotRecompileItsCriteria(t *testing.T) {
	doc := `{"schema":1,"id":"p","criteria":[{"priority":1,"trigger_point":{"condition_type_cnf":false,` +
		`"spt":[{"group":[0],"request_uri":"\\d+"}]},"application_server":{"server_name":"sip:as","default_handling":"SESSION_CONTINUED"}}]}`
	p, err := store.DecodeProfile([]byte(doc), 1)
	if err != nil {
		t.Fatalf("DecodeProfile = %v", err)
	}
	if _, err := store.EncodeProfile(p); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("EncodeProfile = %v; writing must still compile", err)
	}
}
