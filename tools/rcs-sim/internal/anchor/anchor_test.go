package anchor_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/msrp"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/anchor"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestBindingsAreAllocatedCompletedAndReleasedOnTheRealRelay(t *testing.T) {
	r := simtest.StartRelay(t, 2855)
	c := &anchor.Control{HTTP: http.DefaultClient, URL: r.Control, Token: anchor.NewToken(simtest.RelayToken)}
	client, _ := msrp.ParseURI("msrp://rcs-sim.invalid:9/cl1ent;tcp")
	b, err := c.Allocate(ctx(t), anchor.Paths{Client: client}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if b.ID == "" || b.ClientPath.SessionID == "" || b.CoreLocal.SessionID == "" || b.ClientPath.Host != "127.0.0.1" || time.Until(b.ExpiresAt) <= 0 {
		t.Fatalf("binding %+v", b)
	}
	core, _ := msrp.ParseURI("msrp://127.0.0.1:2855/c0re;tcp")
	if err := c.Complete(ctx(t), b.ID, anchor.Paths{Core: core}, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	other, _ := msrp.ParseURI("msrp://127.0.0.1:2855/an0ther;tcp")
	if err := c.Complete(ctx(t), b.ID, anchor.Paths{Core: other}, 0); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("a second core path = %v, want 409", err)
	}
	if err := c.Release(ctx(t), b.ID); err != nil {
		t.Fatal(err)
	}
	if err := c.Release(ctx(t), b.ID); err == nil {
		t.Fatal("released twice")
	}
}

func TestAWrongTokenIsRefusedAndNeverPrinted(t *testing.T) {
	r := simtest.StartRelay(t, 2855)
	c := &anchor.Control{HTTP: http.DefaultClient, URL: r.Control, Token: anchor.NewToken("wrong-token-wrong-token-wrong-token-wrong-to")}
	_, err := c.Allocate(ctx(t), anchor.Paths{}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("Allocate = %v, want 401", err)
	}
	if s := fmt.Sprintf("%v %+v %#v", c, c, c.Token); strings.Contains(s, "wrong-token") {
		t.Fatalf("the token was printed: %s", s)
	}
}

func TestMalformedAnswersAndTransportFailuresAreErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		if strings.Contains(r.URL.RawQuery, "garbage") || r.Header.Get("X-Garbage") != "" {
			_, _ = w.Write([]byte("{"))
			return
		}
		_, _ = w.Write([]byte(`{"id":"x","client_path":"nope","core_path_local":"nope","expires_at":"soon"}`))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := &anchor.Control{HTTP: srv.Client(), URL: u, Token: anchor.NewToken("t")}
	if _, err := c.Allocate(ctx(t), anchor.Paths{}, time.Minute); err == nil {
		t.Fatal("a malformed answer was accepted")
	}
	srv.Close()
	if _, err := c.Allocate(ctx(t), anchor.Paths{}, time.Minute); err == nil || strings.Contains(err.Error(), "Bearer") {
		t.Fatalf("Allocate on a closed server = %v", err)
	}
}
