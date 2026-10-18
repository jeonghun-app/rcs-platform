package ftserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip/digest"
)

const impu = "sip:+15550100001@ims.mnc001.mcc001.3gppnetwork.org"

func TestStaticCredentialsKnowTheirUsers(t *testing.T) {
	s := NewStaticCredentials(map[string]string{alice: password})
	c, err := s.Lookup(t.Context(), alice, digest.SHA256)
	if err != nil || c.Owner != alice {
		t.Fatalf("Lookup = %+v, %v", c, err)
	}
	if _, err := s.Lookup(t.Context(), bob, digest.SHA256); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown user = %v", err)
	}
}

// hss is a fake HSS provisioning API.
type hss struct {
	*httptest.Server
	paths   []string
	headers []http.Header
	answer  func(w http.ResponseWriter, r *http.Request)
}

func newHSS(t *testing.T, answer func(w http.ResponseWriter, r *http.Request)) *hss {
	h := &hss{answer: answer}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.paths = append(h.paths, r.URL.RequestURI())
		h.headers = append(h.headers, r.Header.Clone())
		h.answer(w, r)
	}))
	t.Cleanup(h.Close)
	return h
}

func ha1Of(t *testing.T, alg digest.Algorithm, user string) string {
	t.Helper()
	h, err := digest.ComputeHA1(alg, user, realm, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func credentialJSON(t *testing.T, alg digest.Algorithm, user string) string {
	return fmt.Sprintf(`{"impi":%q,"impu":%q,"realm":%q,"algorithm":%q,"ha1":%q}`, user, impu, realm, alg, ha1Of(t, alg, user))
}

func TestHSSCredentialsVerifyAnUpload(t *testing.T) {
	h := newHSS(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, credentialJSON(t, digest.Algorithm(r.URL.Query().Get("algorithm")), alice))
	})
	src := NewHSSCredentials(mustURL(h.URL+"/hss/"), "provisioning-token", realm, time.Second, 4)
	e := newEnv(t, func(o *Options) { o.Credentials = src })
	doc := e.user(alice).uploadFile("via-hss", "content")
	if len(doc.Infos) != 1 {
		t.Fatal("no file info")
	}
	r, err := e.meta.GetByTID(t.Context(), impu, "via-hss")
	if err != nil {
		t.Fatalf("the file is not owned by the IMPU the HSS returned: %v", err)
	}
	if r.Owner != impu {
		t.Fatalf("owner = %q", r.Owner)
	}
	want := "/hss/v1/subscriptions/" + alice + "/ft-credential?algorithm=SHA-256"
	if h.paths[0] != want {
		t.Fatalf("HSS request = %q, want %q", h.paths[0], want)
	}
	if got := h.headers[0].Get("Authorization"); got != "Bearer provisioning-token" {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestHSSRequestEscapesTheIMPIAsOnePathSegment(t *testing.T) {
	h := newHSS(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	src := NewHSSCredentials(mustURL(h.URL), "t", realm, time.Second, 4)
	for _, name := range []string{"a/../../admin", "a?b#c", "a%2Fb", "."} {
		_, err := src.Lookup(t.Context(), name, digest.MD5)
		if !errors.Is(err, ErrUnknownUser) {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, p := range h.paths {
		if !strings.HasPrefix(p, "/v1/subscriptions/") || strings.Count(p, "/") != 4 {
			t.Errorf("request path %q escaped its segment", p)
		}
	}
}

func TestHSSAnswersOtherThanACredentialFail(t *testing.T) {
	for name, c := range map[string]struct {
		status  int
		body    string
		unknown bool
	}{
		"not found":       {404, "", true},
		"server error":    {500, "", false},
		"unauthorised":    {401, "", false},
		"not json":        {200, "<html>", false},
		"another realm":   {200, `{"impi":"` + alice + `","impu":"` + impu + `","realm":"other","algorithm":"SHA-256","ha1":"00"}`, false},
		"other algorithm": {200, `{"impi":"` + alice + `","impu":"` + impu + `","realm":"` + realm + `","algorithm":"MD5","ha1":"00"}`, false},
		"no impu":         {200, `{"impi":"` + alice + `","realm":"` + realm + `","algorithm":"SHA-256","ha1":"00"}`, false},
		"bad ha1":         {200, `{"impi":"` + alice + `","impu":"` + impu + `","realm":"` + realm + `","algorithm":"SHA-256","ha1":"xyz"}`, false},
		"no impi":         {200, `{"impu":"` + impu + `","realm":"` + realm + `","algorithm":"SHA-256","ha1":"00"}`, true},
		"respelt impi":    {200, `{"impi":"` + strings.ToUpper(alice) + `","impu":"` + impu + `","realm":"` + realm + `","algorithm":"SHA-256","ha1":"00"}`, true},
		"too large":       {200, `{"impu":"` + strings.Repeat("x", maxHSSResponse) + `"}`, false},
		"redirect":        {302, "", false},
	} {
		h := newHSS(t, func(w http.ResponseWriter, _ *http.Request) {
			if c.status == 302 {
				w.Header().Set("Location", "https://elsewhere.example/")
			}
			w.WriteHeader(c.status)
			fmt.Fprint(w, c.body)
		})
		_, err := NewHSSCredentials(mustURL(h.URL), "t", realm, time.Second, 4).Lookup(t.Context(), alice, digest.SHA256)
		if err == nil || errors.Is(err, ErrUnknownUser) != c.unknown {
			t.Errorf("%s: %v", name, err)
		}
		// A 200 that cannot be used is the subscriber's record at fault (a
		// 401 for the client); any other status is the HSS (a 503).
		if record := c.status == 200 && !c.unknown; errors.Is(err, ErrBadCredentialRecord) != record {
			t.Errorf("%s: %v, want an unusable-record error: %v", name, err, record)
		}
		if err != nil && strings.Contains(err.Error(), "001010000000001") {
			t.Errorf("%s: the error names the IMPI: %v", name, err)
		}
	}
}

func TestUnreachableHSSIsAnErrorWithoutTheURL(t *testing.T) {
	h := newHSS(t, nil)
	h.Close()
	_, err := NewHSSCredentials(mustURL(h.URL), "t", realm, time.Second, 4).Lookup(context.Background(), alice, digest.SHA256)
	if err == nil || strings.Contains(err.Error(), "subscriptions") {
		t.Fatalf("err = %v", err)
	}
}

func TestSecretsDoNotPrint(t *testing.T) {
	c := Config{HSSToken: secret{"token-value"}, NonceKey: secret{"nonce-key"}, StaticUsers: map[string]secret{"u": {"pw"}}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, c); strings.Contains(out, "token-value") || strings.Contains(out, "nonce-key") || strings.Contains(out, "pw}") {
			t.Fatalf("%s printed a secret: %s", verb, out)
		}
	}
}
