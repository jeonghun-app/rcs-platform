package maap

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
	"github.com/jeonghun-app/rcs-platform/internal/runtime/runtimetest"
)

var issuedAt = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

// credentialAPIOver is chatbotAPIOver with the credential routes over r's
// credentials, drawing from random.
func credentialAPIOver(t *testing.T, r *store.MemoryRegistry, random func() []byte) (*internalAPI, *runtimetest.Harness) {
	a, h := chatbotAPIOver(t, r, r.Credentials())
	a.mountCredentials(&credentialAPI{
		registry: r, creds: r.Credentials(), now: func() time.Time { return issuedAt.Add(700 * time.Millisecond) },
		random: readerFunc(random),
	})
	return a, h
}

type readerFunc func() []byte

func (f readerFunc) Read(p []byte) (int, error) { return copy(p, f()), nil }

func randomBytes() []byte { return []byte(rand.Text() + rand.Text()) }

func issue(t *testing.T, a *internalAPI, want int) issued {
	t.Helper()
	rec := operator(a, "POST", "/v1/chatbots/cb-1/credentials", "")
	var got issued
	if rec.Code != want || (want == http.StatusCreated && json.Unmarshal(rec.Body.Bytes(), &got) != nil) {
		t.Fatalf("issue = %d %s, want %d", rec.Code, rec.Body, want)
	}
	return got
}

func TestIssueShowsTheSecretOnceAndKeepsOnlyItsDigest(t *testing.T) {
	r := store.NewMemoryRegistry()
	drawn := make([]byte, 48)
	for i := range drawn {
		drawn[i] = byte(i)
	}
	a, h := credentialAPIOver(t, r, func() []byte { return drawn })
	registered(t, a, "")
	got := issue(t, a, http.StatusCreated)
	keyID, secret, _ := strings.Cut(got.Token, ".")
	if got.KeyID != "AAAQEAYEAUDAOCAJBIFQYDIOB4" || keyID != got.KeyID || !got.Created.Equal(issuedAt) ||
		secret != base64.RawURLEncoding.EncodeToString(drawn[16:]) || len(secret) != 43 {
		t.Fatalf("issued %+v", got)
	}
	stored, err := r.Credentials().Credential(context.Background(), keyID)
	if err != nil || stored.Digest != sha256.Sum256([]byte(secret)) || stored.Chatbot != "cb-1" || stored.Registration == "" {
		t.Fatalf("stored %+v, %v", stored, err)
	}
	// After the issue, no answer and no log line carries the secret or its
	// digest, in any common spelling.
	list := operator(a, "GET", "/v1/chatbots/cb-1/credentials", "")
	read := operator(a, "GET", "/v1/chatbots/cb-1", "")
	if list.Code != http.StatusOK || list.Body.String() != `{"credentials":[{"key_id":"`+keyID+`","created":"2026-11-09T10:00:00Z"}]}`+"\n" {
		t.Fatalf("list = %d %s", list.Code, list.Body)
	}
	d := stored.Digest[:]
	for _, never := range []string{secret, hex.EncodeToString(d), base64.StdEncoding.EncodeToString(d), base64.RawURLEncoding.EncodeToString(d)} {
		for where, text := range map[string]string{"list": list.Body.String(), "read": read.Body.String(), "log": h.Output()} {
			if strings.Contains(text, never) {
				t.Errorf("the %s holds %q:\n%s", where, never, text)
			}
		}
	}
	audited(t, h, 1, `"operation":"issue_credential"`, `"status":201`, `"chatbot":"cb-1"`, `"key_id":"`+keyID+`"`)
}

// audited checks that the request's audit line, the nth, holds every want.
func audited(t *testing.T, h *runtimetest.Harness, n int, want ...string) {
	t.Helper()
	line := mustJSON(t, h.Logs("audit: internal request")[n])
	for _, w := range want {
		if !strings.Contains(line, w) {
			t.Errorf("audit line lacks %s: %s", w, line)
		}
	}
}

func TestAThirdCredentialIs409UntilOneIsRevoked(t *testing.T) {
	r := store.NewMemoryRegistry()
	a, h := credentialAPIOver(t, r, randomBytes)
	registered(t, a, "")
	first, _ := issue(t, a, http.StatusCreated), issue(t, a, http.StatusCreated)
	issue(t, a, http.StatusConflict)
	if rec := operator(a, "DELETE", "/v1/chatbots/cb-1/credentials/"+first.KeyID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
	}
	if _, err := r.Credentials().Credential(context.Background(), first.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the revoked credential reads %v", err)
	}
	issue(t, a, http.StatusCreated)
	audited(t, h, 4, `"operation":"revoke_credential"`, `"status":204`, `"chatbot":"cb-1"`, `"key_id":"`+first.KeyID+`"`)
	for _, path := range []string{first.KeyID, "AAAAAAAAAAAAAAAAAAAAAAAAA%0D", strings.ToLower(first.KeyID)} {
		if rec := operator(a, "DELETE", "/v1/chatbots/cb-1/credentials/"+path, ""); rec.Code != http.StatusNotFound {
			t.Errorf("revoke of %s = %d", path, rec.Code)
		}
	}
	if strings.Contains(h.Output(), "AAAAAAAAAAAAAAAAAAAAAAAAA") {
		t.Errorf("a malformed key ID reached the log:\n%s", h.Output())
	}
}

func TestCredentialsOfAGoneChatbotAre404AndStoreFailures503(t *testing.T) {
	r := store.NewMemoryRegistry()
	a, _ := credentialAPIOver(t, r, randomBytes)
	issue(t, a, http.StatusNotFound)
	registered(t, a, "")
	if rec := operator(a, "DELETE", "/v1/chatbots/cb-1", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", rec.Code)
	}
	issue(t, a, http.StatusNotFound)
	if rec := operator(a, "GET", "/v1/chatbots/cb-1/credentials", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("list = %d", rec.Code)
	}
	// An issue that meets the deletion is refused by the store's check of
	// the registration read.
	bare := func(ca *credentialAPI) *internalAPI {
		a, _ := testAPI(t, 2)
		ca.random, ca.now = cmp.Or[io.Reader](ca.random, readerFunc(randomBytes)), time.Now
		a.mountCredentials(ca)
		return a
	}
	m := store.NewMemoryRegistry()
	ch, err := m.Register(context.Background(), store.Chatbot{ID: "cb-1", URI: botURI, State: store.Active})
	if err != nil {
		t.Fatal(err)
	}
	a = bare(&credentialAPI{registry: staleRegistry{m, ch}, creds: m.Credentials()})
	_ = m.DeleteChatbot(context.Background(), "cb-1")
	issue(t, a, http.StatusNotFound)
	a = bare(&credentialAPI{registry: failingRegistry{errors.New("awsstore: get chatbot: InternalServerError")}})
	if rec := operator(a, "POST", "/v1/chatbots/cb-1/credentials", ""); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "1" {
		t.Fatalf("issue over a failing registry = %d", rec.Code)
	}
	// A reader that fails draws no credential.
	a = bare(&credentialAPI{registry: r, creds: r.Credentials(), random: iotest.ErrReader(errors.New("no entropy"))})
	if _, err := r.Register(context.Background(), store.Chatbot{ID: "cb-2", URI: "sip:bot-2@" + botDomain, State: store.Active}); err != nil {
		t.Fatal(err)
	}
	if rec := operator(a, "POST", "/v1/chatbots/cb-2/credentials", ""); rec.Code != http.StatusInternalServerError || !bytes.Contains(rec.Body.Bytes(), []byte("random")) {
		t.Fatalf("issue without randomness = %d %s", rec.Code, rec.Body)
	}
}

// staleRegistry answers the chatbot as read before a deletion.
type staleRegistry struct {
	store.Registry
	read store.Chatbot
}

func (s staleRegistry) Chatbot(context.Context, string) (store.Chatbot, error) { return s.read, nil }
