package icscf

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

func TestParseSCSCFsReadsTheJSONList(t *testing.T) {
	got, err := ParseSCSCFs([]byte(`[
		{"uri":"sip:scscf.rcs.local:5060;transport=tcp","mandatory":[1],"optional":[2,3]},
		{"uri":"sips:scscf-b.rcs.local"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2", len(got))
	}
	if got[0].URI.String() != scscfURI || !slices.Equal(got[0].Mandatory, []uint32{1}) || !slices.Equal(got[0].Optional, []uint32{2, 3}) {
		t.Errorf("first entry = %s %v %v", got[0].URI.String(), got[0].Mandatory, got[0].Optional)
	}
	if got[1].URI.String() != "sips:scscf-b.rcs.local" || got[1].Mandatory != nil || got[1].Optional != nil {
		t.Errorf("second entry = %s %v %v", got[1].URI.String(), got[1].Mandatory, got[1].Optional)
	}
}

// Decision 1 on #15: a bad URI, a negative capability or an empty list
// stops the service from starting.
func TestParseSCSCFsRefusesWhatCannotBeUsed(t *testing.T) {
	many := "[" + strings.Repeat(`{"uri":"sip:x.rcs.local"},`, MaxSCSCFs) + `{"uri":"sip:x.rcs.local"}]`
	cases := map[string]string{
		"empty list":           `[]`,
		"null":                 `null`,
		"not JSON":             `sip:scscf.rcs.local`,
		"not an array":         `{"uri":"sip:scscf.rcs.local"}`,
		"trailing data":        `[{"uri":"sip:scscf.rcs.local"}] []`,
		"no uri":               `[{"mandatory":[1]}]`,
		"bad uri":              `[{"uri":"sip:"}]`,
		"tel uri":              `[{"uri":"tel:+15550100001"}]`,
		"uri with a user part": `[{"uri":"sip:scscf@rcs.local"}]`,
		"uri with headers":     `[{"uri":"sip:scscf.rcs.local?x=y"}]`,
		"negative capability":  `[{"uri":"sip:scscf.rcs.local","mandatory":[-1]}]`,
		"fractional":           `[{"uri":"sip:scscf.rcs.local","optional":[1.5]}]`,
		"too large":            `[{"uri":"sip:scscf.rcs.local","optional":[4294967296]}]`,
		"unknown field":        `[{"uri":"sip:scscf.rcs.local","weight":1}]`,
		"repeated":             `[{"uri":"sip:scscf.rcs.local"},{"uri":"sip:SCSCF.rcs.local"}]`,
		"too many":             many,
	}
	for name, in := range cases {
		if got, err := ParseSCSCFs([]byte(in)); err == nil {
			t.Errorf("%s: parsed %+v, want an error", name, got)
		}
	}
}

func TestNewRefusesAnIncompleteOrUnsafeConfiguration(t *testing.T) {
	cases := map[string]func(*Config){
		"no HSS":                   func(c *Config) { c.HSS = nil },
		"no S-CSCF":                func(c *Config) { c.SCSCFs = nil },
		"too many S-CSCFs":         func(c *Config) { c.SCSCFs = make([]SCSCF, MaxSCSCFs+1) },
		"an S-CSCF with no URI":    func(c *Config) { c.SCSCFs = []SCSCF{{}} },
		"a tel S-CSCF":             func(c *Config) { c.SCSCFs = []SCSCF{{URI: mustURI(tel1)}} },
		"repeated S-CSCF":          func(c *Config) { c.SCSCFs = []SCSCF{{URI: mustURI(scscfURI)}, {URI: mustURI(scscfURI)}} },
		"no home domain":           func(c *Config) { c.HomeDomain = "" },
		"home domain not a domain": func(c *Config) { c.HomeDomain = "ims home" },
		"negative Retry-After":     func(c *Config) { c.RetryAfter = -time.Second },
		"sub-second Retry-After":   func(c *Config) { c.RetryAfter = 500 * time.Millisecond },
		"fractional Retry-After":   func(c *Config) { c.RetryAfter = 1500 * time.Millisecond },
		"Retry-After over an hour": func(c *Config) { c.RetryAfter = MaxRetryAfter + time.Second },
		"negative timeout":         func(c *Config) { c.RegisterTimeout = -time.Second },
		"timeout past Timer F":     func(c *Config) { c.RegisterTimeout = MaxRegisterTimeout + time.Millisecond },
	}
	for name, mutate := range cases {
		cfg := Config{HSS: &stubHSS{}, SCSCFs: []SCSCF{{URI: mustURI(scscfURI)}}, HomeDomain: home}
		mutate(&cfg)
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted %+v", name, cfg)
		}
	}
}

func TestNewAcceptsTheLimits(t *testing.T) {
	cases := map[string]func(*Config){
		"Retry-After of a second":   func(c *Config) { c.RetryAfter = time.Second },
		"Retry-After of an hour":    func(c *Config) { c.RetryAfter = MaxRetryAfter },
		"timeout at Timer F":        func(c *Config) { c.RegisterTimeout = MaxRegisterTimeout },
		"the most S-CSCFs":          func(c *Config) { c.SCSCFs = manySCSCFs(MaxSCSCFs) },
		"a home domain of one name": func(c *Config) { c.HomeDomain = "localdomain" },
	}
	for name, mutate := range cases {
		cfg := Config{HSS: &stubHSS{}, SCSCFs: []SCSCF{{URI: mustURI(scscfURI)}}, HomeDomain: home}
		mutate(&cfg)
		if _, err := New(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewFillsInTheDefaults(t *testing.T) {
	r, err := New(Config{HSS: &stubHSS{}, SCSCFs: []SCSCF{{URI: mustURI(scscfURI)}}, HomeDomain: home})
	if err != nil {
		t.Fatal(err)
	}
	if r.retryAfter != "10" || r.registerTimeout != DefaultRegisterTimeout || r.metrics == nil || r.log == nil {
		t.Errorf("defaults: Retry-After %q, timeout %v, metrics %v, logger %v", r.retryAfter, r.registerTimeout, r.metrics, r.log)
	}
	if string(r.home) != home {
		t.Errorf("home = %q", r.home)
	}
}

func manySCSCFs(n int) []SCSCF {
	out := make([]SCSCF, n)
	for i := range out {
		out[i] = SCSCF{URI: sip.URI{Scheme: "sip", Host: fmt.Sprintf("scscf-%d.rcs.local", i)}}
	}
	return out
}
