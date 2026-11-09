package storetest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/maap/store"
)

// Credential returns a fresh credential of c, with a random key ID and
// the digest of a random secret, issued at created.
func Credential(c store.Chatbot, created time.Time) store.Credential {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return store.Credential{
		KeyID:   base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id),
		Chatbot: c.ID, Registration: c.Registration, Digest: sha256.Sum256([]byte(rand.Text())), Created: created,
	}
}

// RunCredentials runs every credential check against the registries and
// their credentials from newStores.
func RunCredentials(t *testing.T, newStores func(t *testing.T) (store.Registry, store.Credentials)) {
	for _, tc := range []struct {
		name  string
		check func(*testing.T, store.Registry, store.Credentials)
	}{
		{"ACredentialReadsBackUntilRevoked", credentialsReadBack},
		{"IssueNeedsTheChatbotsRegistration", issueNeedsRegistration},
		{"DeletingTheChatbotDeletesItsCredentials", deleteDeletesCredentials},
		{"ConcurrentIssuesKeepTheLimit", concurrentIssues},
		{"AnIssueRacingADeleteLeavesNoCredential", issueRacingDelete},
		{"UseIsRecordedOnLiveCredentialsOnly", recordsUse},
	} {
		t.Run(tc.name, func(t *testing.T) { r, c := newStores(t); tc.check(t, r, c) })
	}
}

var at = time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC)

func register(t *testing.T, r store.Registry) store.Chatbot {
	t.Helper()
	c, err := r.Register(context.Background(), Chatbot())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func keyIDs(t *testing.T, cs store.Credentials, chatbotID string) []string {
	t.Helper()
	got, err := cs.ChatbotCredentials(context.Background(), chatbotID)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, c := range got {
		ids = append(ids, c.KeyID)
	}
	return ids
}

func credentialsReadBack(t *testing.T, r store.Registry, cs store.Credentials) {
	ctx := context.Background()
	c := register(t, r)
	older, newer := Credential(c, at.Add(500*time.Millisecond)), Credential(c, at.Add(time.Hour))
	for _, cred := range []store.Credential{newer, older} {
		if err := cs.Issue(ctx, cred); err != nil {
			t.Fatal(err)
		}
	}
	got, err := cs.Credential(ctx, older.KeyID)
	older.Created = at
	if err != nil || !reflect.DeepEqual(got, older) {
		t.Fatalf("Credential = %+v, %v\nwant %+v", got, err, older)
	}
	if ids := keyIDs(t, cs, c.ID); !reflect.DeepEqual(ids, []string{older.KeyID, newer.KeyID}) {
		t.Fatalf("ChatbotCredentials = %v", ids)
	}
	third := Credential(c, at)
	if err := cs.Issue(ctx, third); !errors.Is(err, store.ErrTooMany) {
		t.Fatalf("a third Issue = %v", err)
	}
	if _, err := cs.Credential(ctx, third.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the refused credential reads %v", err)
	}
	// Only the chatbot's own key ID is revoked.
	other := register(t, r)
	if err := cs.Revoke(ctx, other.ID, older.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Revoke by another chatbot = %v", err)
	}
	if err := cs.Revoke(ctx, c.ID, older.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Credential(ctx, older.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a revoked credential reads %v", err)
	}
	if err := cs.Revoke(ctx, c.ID, older.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second Revoke = %v", err)
	}
	// Revoking frees a place for the next.
	if err := cs.Issue(ctx, third); err != nil {
		t.Fatalf("Issue after a revoke = %v", err)
	}
	if ids := keyIDs(t, cs, c.ID); !reflect.DeepEqual(ids, []string{third.KeyID, newer.KeyID}) {
		t.Fatalf("ChatbotCredentials = %v", ids)
	}
	if ids := keyIDs(t, cs, "nobody"); len(ids) != 0 {
		t.Fatalf("ChatbotCredentials of nobody = %v", ids)
	}
}

func issueNeedsRegistration(t *testing.T, r store.Registry, cs store.Credentials) {
	ctx := context.Background()
	c := register(t, r)
	forged := c
	forged.Registration = "another"
	nobody := Chatbot()
	nobody.Registration = c.Registration
	for _, cb := range []store.Chatbot{forged, nobody} {
		if err := cs.Issue(ctx, Credential(cb, at)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("Issue to %s/%s = %v", cb.ID, cb.Registration, err)
		}
	}
	bad := Credential(c, at)
	bad.KeyID = "AAAAAAAAAAAAAAAAAAAAAAAAA."
	if err := cs.Issue(ctx, bad); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("Issue of a malformed key ID = %v", err)
	}
	if err := r.DeleteChatbot(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := cs.Issue(ctx, Credential(c, at)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Issue after the delete = %v", err)
	}
	if ids := keyIDs(t, cs, c.ID); len(ids) != 0 {
		t.Fatalf("credentials of the deleted chatbot: %v", ids)
	}
}

func deleteDeletesCredentials(t *testing.T, r store.Registry, cs store.Credentials) {
	ctx := context.Background()
	for _, d := range []store.ChatbotDeleter{r, cs} {
		c := register(t, r)
		creds := []store.Credential{Credential(c, at), Credential(c, at)}
		for _, cred := range creds {
			if err := cs.Issue(ctx, cred); err != nil {
				t.Fatal(err)
			}
		}
		for range 2 {
			if err := d.DeleteChatbot(ctx, c.ID); err != nil {
				t.Fatal(err)
			}
		}
		for _, cred := range creds {
			if _, err := cs.Credential(ctx, cred.KeyID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("%T: a deleted chatbot's credential reads %v", d, err)
			}
		}
		if ids := keyIDs(t, cs, c.ID); len(ids) != 0 {
			t.Errorf("%T: credentials left: %v", d, ids)
		}
	}
}

func concurrentIssues(t *testing.T, r store.Registry, cs store.Credentials) {
	c := register(t, r)
	errs := race(8, func(int) error { return cs.Issue(context.Background(), Credential(c, at)) })
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrTooMany) && !errors.Is(err, store.ErrConflict):
			t.Errorf("a losing Issue = %v", err)
		}
	}
	if ids := keyIDs(t, cs, c.ID); won != store.MaxCredentials || len(ids) != won {
		t.Fatalf("%d issues won, %d credentials stored", won, len(ids))
	}
}

func issueRacingDelete(t *testing.T, r store.Registry, cs store.Credentials) {
	ctx := context.Background()
	for range 4 {
		c := register(t, r)
		creds := make([]store.Credential, 4)
		errs := race(len(creds)+1, func(i int) error {
			if i == len(creds) {
				return r.DeleteChatbot(ctx, c.ID)
			}
			creds[i] = Credential(c, at)
			return cs.Issue(ctx, creds[i])
		})
		if errs[len(creds)] != nil {
			t.Fatalf("DeleteChatbot = %v", errs[len(creds)])
		}
		for i, cred := range creds {
			if _, err := cs.Credential(ctx, cred.KeyID); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a credential issued with %v outlived the delete: %v", errs[i], err)
			}
		}
	}
}

func recordsUse(t *testing.T, r store.Registry, cs store.Credentials) {
	ctx := context.Background()
	c := register(t, r)
	cred := Credential(c, at)
	if err := cs.Issue(ctx, cred); err != nil {
		t.Fatal(err)
	}
	used := at.Add(90*time.Minute + 300*time.Millisecond).In(time.FixedZone("KST", 9*3600))
	if err := cs.Used(ctx, cred.KeyID, used); err != nil {
		t.Fatal(err)
	}
	if got, err := cs.Credential(ctx, cred.KeyID); err != nil || !got.LastUsed.Equal(at.Add(90*time.Minute)) || got.LastUsed.Location() != time.UTC {
		t.Fatalf("LastUsed = %v, %v", got.LastUsed, err)
	}
	if err := cs.Revoke(ctx, c.ID, cred.KeyID); err != nil {
		t.Fatal(err)
	}
	if err := cs.Used(ctx, cred.KeyID, used); err != nil {
		t.Fatalf("Used of a revoked credential = %v", err)
	}
	if _, err := cs.Credential(ctx, cred.KeyID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Used brought a revoked credential back: %v", err)
	}
}
