package runtime

import (
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// FuzzEnvValues feeds one value to every typed getter and checks the contract
// services rely on: a getter either parses the value or records exactly one
// problem and returns the default, never panics, and never repeats the value in
// the problem.
func FuzzEnvValues(f *testing.F) {
	for _, s := range []string{
		"", "true", "yes please", "0", "-1", "99999999999999999999", "1h30m", "-5s", "1e9",
		"a,b", "a,,b", " , ", "10.0.0.0/8", "10.0.0.1/8", "fd00::/8, 192.0.2.0/24", "::ffff:10.0.0.0/104",
		"fe80::1%eth0/64", "\x00", "ü,ö",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		getters := []struct {
			name string
			read func(e *Env) (parsedOK bool)
		}{
			{"Bool", func(e *Env) bool { e.Bool("V", false); return true }},
			{"Int", func(e *Env) bool { e.Int("V", 0); return true }},
			{"Duration", func(e *Env) bool { return e.Duration("V", 0) >= 0 }},
			{"List", func(e *Env) bool {
				for _, item := range e.List("V", nil) {
					if item == "" || item != strings.TrimSpace(item) || strings.Contains(item, ",") {
						return false
					}
				}
				return true
			}},
			{"CIDRs", func(e *Env) bool {
				for _, p := range e.CIDRs("V", nil) {
					if !p.IsValid() || p != p.Masked() {
						return false
					}
				}
				return true
			}},
		}
		for _, g := range getters {
			e := NewEnv("FZ_", func(string) (string, bool) { return v, true })
			if !g.read(e) {
				t.Fatalf("%s(%q) returned a value breaking its contract", g.name, v)
			}
			err := e.Err()
			if err == nil {
				continue
			}
			var ce *ConfigError
			if !errors.As(err, &ce) || len(ce.Problems) != 1 || !strings.HasPrefix(ce.Problems[0], "FZ_V: ") {
				t.Fatalf("%s(%q): Err() = %v", g.name, v, err)
			}
			// Every reason is fixed text (apart from an item number), so none
			// can carry the value.
			reason := itemNumber.ReplaceAllString(strings.TrimPrefix(ce.Problems[0], "FZ_V: "), "item N ")
			if !knownReasons[reason] {
				t.Fatalf("%s(%q): unexpected problem %q", g.name, v, reason)
			}
		}
	})
}

// FuzzAdminAddr checks that any accepted RCS_ADMIN_ADDR can be listened on as
// given and yields a probe URL for the same port on an IP address.
func FuzzAdminAddr(f *testing.F) {
	for _, s := range []string{":8080", "0.0.0.0:1", "[::]:65535", "[::1]:80", "10.0.0.1:8080", ":0", "host:80", "[fe80::1%eth0]:80", "::1:80", ":+80", ":８０"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		a, ok := parseAdminAddr(v)
		if !ok {
			return
		}
		host, port, err := net.SplitHostPort(a.listen)
		if err != nil || a.listen != v {
			t.Fatalf("%q accepted but listen address is %q", v, a.listen)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			t.Fatalf("%q accepted with port %q", v, port)
		}
		if host != "" && net.ParseIP(host) == nil {
			t.Fatalf("%q accepted with host %q", v, host)
		}
		u, err := url.Parse(a.probeURL)
		if err != nil || u.Scheme != "http" || u.Path != "/healthz" || u.Port() != port || net.ParseIP(u.Hostname()) == nil {
			t.Fatalf("%q gave probe URL %q", v, a.probeURL)
		}
	})
}

var itemNumber = regexp.MustCompile(`^item [0-9]+ `)

var knownReasons = map[string]bool{
	"not a boolean (want true or false)":                        true,
	"not a base-10 integer in range":                            true,
	`not a duration (want a number with a unit, such as "20s")`: true,
	"negative duration":                                         true,
	"empty item in comma-separated list":                        true,
	"item N is not a CIDR prefix":                               true,
	"item N has host bits set":                                  true,
}
