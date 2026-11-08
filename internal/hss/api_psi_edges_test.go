package hss

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
	"github.com/jeonghun-app/rcs-platform/internal/pii"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
)

// racingPSIStore lets another task write the PSI between a request's read
// and its write, once, as a second hss task would.
type racingPSIStore struct {
	store.Store
	rival *store.WildcardedPSI
	puts  int
}

func (s *racingPSIStore) PutWildcardedPSI(ctx context.Context, old, p *store.WildcardedPSI) (*store.WildcardedPSI, error) {
	s.puts++
	if rival := s.rival; rival != nil {
		s.rival = nil
		cur, err := s.Store.WildcardedPSI(ctx)
		if errors.Is(err, store.ErrNotFound) {
			cur = nil
		} else if err != nil {
			return nil, err
		}
		if _, err := s.Store.PutWildcardedPSI(ctx, cur, rival); err != nil {
			return nil, err
		}
	}
	return s.Store.PutWildcardedPSI(ctx, old, p)
}

func newChatbotAPIEnvOn(t *testing.T, st store.Store) *apiEnv {
	t.Helper()
	a := &apiEnv{env: newEnvWith(t, st), notifier: newRecorder(), now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	a.api = a.h.NewAPI(APIOptions{
		Tokens:         Tokens{Admin: TokenPair{secret.NewString(adminToken), secret.NewString(adminTokenNext)}},
		Notifier:       a.notifier,
		DefaultProfile: DefaultProfileID,
		ChatbotDomain:  testChatbotDomain(t),
		ChatbotASName:  chatbotAS,
	})
	t.Cleanup(func() { _ = a.api.Close(context.Background()) })
	return a
}

// A first write that loses to another task's first write (ErrExists), and
// a replacement that loses to another task's replacement (ErrConflict),
// both read again and replace what the other task wrote.
func TestAPSIWriteThatLosesARaceReadsAgainAndReplacesTheWinner(t *testing.T) {
	rivalPSI := "sip:!rival[a-z]*!@" + botDomain
	for _, c := range []struct {
		name   string
		stored bool
	}{{"lost create", false}, {"lost replace", true}} {
		t.Run(c.name, func(t *testing.T) {
			st := &racingPSIStore{Store: store.NewMemory()}
			a := newChatbotAPIEnvOn(t, st)
			want := int64(2)
			if c.stored {
				if code, body, _ := a.do("PUT", "/v1/chatbot-psi", adminToken, psiBody(chatbotPSI)); code != http.StatusCreated {
					t.Fatalf("first PUT = %d %v", code, body)
				}
				want = 3
			}
			st.rival = &store.WildcardedPSI{PSI: rivalPSI, ServerName: chatbotAS, Active: true}
			st.puts = 0
			code, body, h := a.do("PUT", "/v1/chatbot-psi", adminToken, psiBody(chatbotPSI))
			if code != http.StatusOK || body["psi"] != chatbotPSI || body["version"] != float64(want) || h.Get("ETag") != etag(want) {
				t.Fatalf("PUT that lost a race = %d %v, ETag %q", code, body, h.Get("ETag"))
			}
			if st.puts != 2 {
				t.Errorf("%d writes, want the lost one and one more", st.puts)
			}
			if got, err := st.Store.WildcardedPSI(t.Context()); err != nil || got.PSI != chatbotPSI || got.Version != want {
				t.Errorf("stored %+v, %v", got, err)
			}
		})
	}
}

// If-Match names a version that must be stored: with none stored, the write
// is 412 and stores nothing, rather than creating the PSI.
func TestAnIfMatchWithNoPSIStoredIsRefusedAndStoresNothing(t *testing.T) {
	a := newChatbotAPIEnv(t)
	if code, body, _ := a.do("PUT", "/v1/chatbot-psi", adminToken, psiBody(chatbotPSI), "If-Match", `"1"`); code != http.StatusPreconditionFailed {
		t.Fatalf("PUT with If-Match and nothing stored = %d %v, want 412", code, body)
	}
	if _, err := a.store.WildcardedPSI(t.Context()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("after the refused write: %v, want not found", err)
	}
}

// With a keyed redactor, as in prod (RCS_PII_HMAC_KEY), the masked values
// carry hints, so the audit line shows which PSI was replaced by which. The
// unkeyed test redactor masks every PSI the same way and cannot show it.
func TestTheAuditLineTellsThePSIBeforeFromTheOneAfter(t *testing.T) {
	keyed := pii.NewRedactor([]byte("hss-audit-test-key-0123456789abc"))
	pii.SetDefault(keyed)
	t.Cleanup(func() { pii.SetDefault(nil) })
	a := newChatbotAPIEnv(t)
	one, two := "sip:!one[a-z]*!@"+botDomain, "sip:!two[a-z]*!@"+botDomain
	for _, psi := range []string{one, two} {
		if code, body, _ := a.do("PUT", "/v1/chatbot-psi", adminToken, psiBody(psi)); code != http.StatusOK && code != http.StatusCreated {
			t.Fatalf("PUT = %d %v", code, body)
		}
	}
	masked := func(v string) string { return keyed.URI("k", v).Value.String() }
	if masked(one) == masked(two) {
		t.Fatal("the keyed redactor masks both PSIs the same way")
	}
	audits := a.psiAudits()
	if len(audits) != 2 {
		t.Fatalf("%d audit records, want 2", len(audits))
	}
	if r := audits[0]; r["psi_before"] != "" || r["psi_after"] != masked(one) {
		t.Errorf("first write's audit = %v", r)
	}
	if r := audits[1]; r["psi_before"] != masked(one) || r["psi_after"] != masked(two) {
		t.Errorf("replacement's audit = %v", r)
	}
}
