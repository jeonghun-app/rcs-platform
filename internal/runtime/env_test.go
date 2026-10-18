package runtime

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestUnsetAndEmptyVariablesTakeTheDefault(t *testing.T) {
	e := NewEnv("SVC_", envMap{"SVC_EMPTY": ""}.lookup)
	defCIDRs := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, name := range []string{"MISSING", "EMPTY"} {
		if got := e.String(name, "d"); got != "d" {
			t.Errorf("String(%s) = %q", name, got)
		}
		if got := e.Int(name, 7); got != 7 {
			t.Errorf("Int(%s) = %d", name, got)
		}
		if got := e.Bool(name, true); !got {
			t.Errorf("Bool(%s) = false", name)
		}
		if got := e.Duration(name, time.Second); got != time.Second {
			t.Errorf("Duration(%s) = %s", name, got)
		}
		if got := e.List(name, []string{"a"}); !slices.Equal(got, []string{"a"}) {
			t.Errorf("List(%s) = %q", name, got)
		}
		if got := e.CIDRs(name, defCIDRs); !slices.Equal(got, defCIDRs) {
			t.Errorf("CIDRs(%s) = %v", name, got)
		}
	}
	if err := e.Err(); err != nil {
		t.Fatalf("defaults recorded problems: %v", err)
	}
}

func TestTypedValuesAreParsed(t *testing.T) {
	e := NewEnv("SVC_", envMap{
		"SVC_NAME":     "pcscf-1",
		"SVC_COUNT":    "-42",
		"SVC_ON":       "true",
		"SVC_OFF":      "0",
		"SVC_WAIT":     "1m30s",
		"SVC_ZERO":     "0s",
		"SVC_HOSTS":    " a.example , b.example,c",
		"SVC_NETWORKS": "10.0.0.0/8, fd00::/8,192.0.2.1/32",
	}.lookup)
	if got := e.String("NAME", ""); got != "pcscf-1" {
		t.Errorf("String = %q", got)
	}
	if got := e.Int("COUNT", 0); got != -42 {
		t.Errorf("Int = %d", got)
	}
	if !e.Bool("ON", false) || e.Bool("OFF", true) {
		t.Errorf("Bool did not parse true/0")
	}
	if got := e.Duration("WAIT", 0); got != 90*time.Second {
		t.Errorf("Duration = %s", got)
	}
	if got := e.Duration("ZERO", time.Hour); got != 0 {
		t.Errorf("zero Duration = %s", got)
	}
	if got := e.List("HOSTS", nil); !slices.Equal(got, []string{"a.example", "b.example", "c"}) {
		t.Errorf("List = %q", got)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd00::/8"),
		netip.MustParsePrefix("192.0.2.1/32"),
	}
	if got := e.CIDRs("NETWORKS", nil); !slices.Equal(got, want) {
		t.Errorf("CIDRs = %v", got)
	}
	if err := e.Err(); err != nil {
		t.Fatalf("valid values recorded problems: %v", err)
	}
}

func TestUnparseableValuesAreProblemsNotDefaults(t *testing.T) {
	tests := []struct {
		value string
		read  func(e *Env)
		want  string
	}{
		{"yes please", func(e *Env) { e.Bool("X", true) }, "SVC_X: not a boolean"},
		{"yes", func(e *Env) { e.Bool("X", true) }, "SVC_X: not a boolean"},
		{"12abc", func(e *Env) { e.Int("X", 1) }, "SVC_X: not a base-10 integer"},
		{"99999999999999999999", func(e *Env) { e.Int("X", 1) }, "SVC_X: not a base-10 integer"},
		{" 5", func(e *Env) { e.Int("X", 1) }, "SVC_X: not a base-10 integer"},
		{"20", func(e *Env) { e.Duration("X", time.Second) }, "SVC_X: not a duration"},
		{"-5s", func(e *Env) { e.Duration("X", time.Second) }, "SVC_X: negative duration"},
		{"a,,b", func(e *Env) { e.List("X", nil) }, "SVC_X: empty item"},
		{"a,b,", func(e *Env) { e.List("X", nil) }, "SVC_X: empty item"},
		{"10.0.0.0/8,", func(e *Env) { e.CIDRs("X", nil) }, "SVC_X: empty item"},
		{"10.0.0.0/8,10.0.0.1", func(e *Env) { e.CIDRs("X", nil) }, "SVC_X: item 2 is not a CIDR prefix"},
		{"10.0.0.1/8", func(e *Env) { e.CIDRs("X", nil) }, "SVC_X: item 1 has host bits set"},
		{"fe80::1%eth0/64", func(e *Env) { e.CIDRs("X", nil) }, "SVC_X: item 1 is not a CIDR prefix"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			e := NewEnv("SVC_", envMap{"SVC_X": tt.value}.lookup)
			tt.read(e)
			var ce *ConfigError
			if !errors.As(e.Err(), &ce) || len(ce.Problems) != 1 {
				t.Fatalf("Err() = %v, want one problem", e.Err())
			}
			if !strings.HasPrefix(ce.Problems[0], tt.want) {
				t.Fatalf("problem %q, want prefix %q", ce.Problems[0], tt.want)
			}
		})
	}
}

func TestEveryProblemIsReportedTogether(t *testing.T) {
	e := NewEnv("SVC_", envMap{
		"SVC_A": "maybe",
		"SVC_B": "ten",
		"SVC_C": "soon",
	}.lookup)
	e.Bool("A", false)
	e.Int("B", 0)
	e.Duration("C", 0)
	e.RequiredString("D")
	e.Invalid("E", "port out of range")
	err := e.Err()
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("Err() = %v", err)
	}
	var names []string
	for _, p := range ce.Problems {
		names = append(names, p[:strings.Index(p, ":")])
	}
	if want := []string{"SVC_A", "SVC_B", "SVC_C", "SVC_D", "SVC_E"}; !slices.Equal(names, want) {
		t.Fatalf("problems for %q, want %q", names, want)
	}
	for _, name := range []string{"SVC_A", "SVC_B", "SVC_C", "SVC_D", "SVC_E"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("Error() %q does not mention %s", err.Error(), name)
		}
	}
}

func TestProblemsNeverRepeatTheValue(t *testing.T) {
	const secret = "s3cr3t-token-value"
	e := NewEnv("SVC_", envMap{"SVC_FLAG": secret, "SVC_N": secret, "SVC_D": secret, "SVC_NETS": secret}.lookup)
	e.Bool("FLAG", false)
	e.Int("N", 0)
	e.Duration("D", 0)
	e.CIDRs("NETS", nil)
	if err := e.Err(); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("Err() = %v", err)
	}
}

func TestWithPrefixSharesTheProblemList(t *testing.T) {
	shared := NewEnv("RCS_", envMap{"RCS_X": "bad", "SVC_Y": "bad"}.lookup)
	svc := shared.WithPrefix("SVC_")
	shared.Int("X", 0)
	svc.Int("Y", 0)
	var ce *ConfigError
	if !errors.As(svc.Err(), &ce) || len(ce.Problems) != 2 {
		t.Fatalf("svc.Err() = %v, want both problems", svc.Err())
	}
	if shared.Err().Error() != svc.Err().Error() {
		t.Fatalf("the two views disagree: %v / %v", shared.Err(), svc.Err())
	}
}

func TestRequiredStringRejectsUnsetAndEmpty(t *testing.T) {
	e := NewEnv("SVC_", envMap{"SVC_EMPTY": "", "SVC_SET": "x"}.lookup)
	if got := e.RequiredString("SET"); got != "x" {
		t.Fatalf("RequiredString(SET) = %q", got)
	}
	e.RequiredString("EMPTY")
	e.RequiredString("MISSING")
	var ce *ConfigError
	if !errors.As(e.Err(), &ce) || !slices.Equal(ce.Problems, []string{"SVC_EMPTY: required", "SVC_MISSING: required"}) {
		t.Fatalf("Err() = %v", e.Err())
	}
}

func TestErrIsASnapshot(t *testing.T) {
	e := NewEnv("SVC_", envMap{}.lookup)
	e.Invalid("A", "bad")
	var ce *ConfigError
	errors.As(e.Err(), &ce)
	e.Invalid("B", "bad")
	if len(ce.Problems) != 1 {
		t.Fatalf("an earlier error grew to %v", ce.Problems)
	}
}
