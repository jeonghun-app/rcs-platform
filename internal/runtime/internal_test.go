package runtime

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestPrivateHostsAreRFC1918ULAAndNamesInTheNamespace(t *testing.T) {
	for host, want := range map[string]bool{
		"10.0.3.7": true, "172.16.0.1": true, "192.168.1.1": true, "fd00::1": true, "fc00::1": true,
		"::ffff:10.0.0.1": true,
		"hss.rcs.local":   true, "HSS.RCS.LOCAL.": true, "rcs-as.prod.rcs.local": true,
		// ADR 0007 §5 refuses these.
		"127.0.0.1": false, "::1": false, "169.254.169.254": false, "169.254.170.2": false,
		"fe80::1": false, "fe80::1%eth0": false, "2001:db8::1": false,
		"8.8.8.8": false, "172.32.0.1": false, "::ffff:8.8.8.8": false,
		"hss.example.com": false, "rcs.local": false, "evilrcs.local": false, "hss.evil-rcs.local": false,
		"localhost": false, "": false,
	} {
		if got := IsPrivateHost(host, "rcs.local"); got != want {
			t.Errorf("IsPrivateHost(%q) = %t, want %t", host, got, want)
		}
	}
	if IsPrivateHost("hss.rcs.local", "") {
		t.Error("a name is private without a namespace")
	}
	if !InServiceNamespace("rcs-as.rcs.internal", "RCS.Internal.") {
		t.Error("the namespace is compared without regard to case or a trailing dot")
	}
}

func TestPrivateInternalURLsNeedAnHTTPSchemeAndAPrivateHost(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://hss.rcs.local:8081/v1":       true,
		"https://10.0.1.5/":                  true,
		"http://[fd00::5]:8080":              true,
		"http://169.254.169.254/latest/meta": false,
		"http://127.0.0.1:8080":              false,
		"http://hss.example.com":             false,
		"ftp://10.0.1.5/":                    false,
		"http://user@hss.evilrcs.local":      false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := IsPrivateInternalURL(u, "rcs.local"); got != want {
			t.Errorf("IsPrivateInternalURL(%q) = %t, want %t", raw, got, want)
		}
	}
	if IsPrivateInternalURL(nil, "rcs.local") {
		t.Error("nil URL is private")
	}
}

func TestInternalClientsDoNotFollowRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the redirect was followed, carrying %q", r.Header.Get("Authorization"))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirect.Close()
	client := &http.Client{CheckRedirect: RefuseRedirects}
	req, _ := http.NewRequest(http.MethodGet, redirect.URL, nil)
	req.Header.Set("Authorization", "Bearer token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the redirect itself", resp.StatusCode)
	}
}

func TestServiceNamespaceIsAValidatedSharedSetting(t *testing.T) {
	for v, want := range map[string]string{
		"":                "",
		"rcs.local":       "rcs.local",
		"RCS.Prod.Local.": "rcs.prod.local",
		"prod-1.internal": "prod-1.internal",
		"x":               "x",
	} {
		e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_SERVICE_NAMESPACE": v}.lookup)
		loadShared(e)
		if err := e.Err(); err != nil {
			t.Errorf("%q refused: %v", v, err)
		}
		if got := (&Settings{Shared: e}).ServiceNamespace(); got != want {
			t.Errorf("ServiceNamespace() for %q = %q, want %q", v, got, want)
		}
	}
	for _, v := range []string{"rcs_local", "-rcs.local", "rcs-.local", "rcs..local", ".", strings.Repeat("a", 64) + ".local", "rcs.local/x", "rcs local"} {
		e := NewEnv("RCS_", envMap{"RCS_ENV": "dev", "RCS_SERVICE_NAMESPACE": v}.lookup)
		loadShared(e)
		if err := e.Err(); err == nil || !strings.Contains(err.Error(), "RCS_SERVICE_NAMESPACE") {
			t.Errorf("%q accepted: %v", v, err)
		}
		if got := (&Settings{Shared: e}).ServiceNamespace(); got != "" {
			t.Errorf("ServiceNamespace() for invalid %q = %q", v, got)
		}
	}
}
