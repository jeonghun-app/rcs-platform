package cxclient

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
	"github.com/jeonghun-app/rcs-platform/internal/diameter/cx"
	"github.com/jeonghun-app/rcs-platform/internal/hss"
	"github.com/jeonghun-app/rcs-platform/internal/hss/keyring"
	"github.com/jeonghun-app/rcs-platform/internal/hss/store"
)

// adminToken is a test bearer token of the provisioning API, long enough for
// any environment's rule.
var adminToken = strings.Repeat("t", hss.MinTokenLength)

// hssTask is an HSS task in process: the real Cx server over a store the tasks
// share, on an in-process listener.
type hssTask struct {
	node   *diameter.Node
	ln     *pipeListener
	pusher *hss.Pusher
}

func startRealHSS(t *testing.T, net *network, h *hss.HSS, addr, host string) *hssTask {
	t.Helper()
	ln := newPipeListener()
	n, err := diameter.NewNode(diameter.Config{
		OriginHost: host, OriginRealm: realm,
		HostIPAddresses:    []netip.Addr{netip.MustParseAddr(addr)},
		Applications:       []diameter.Application{cx.Application},
		SupportedVendorIDs: []uint32{cx.Vendor3GPP, cx.VendorETSI},
		Dictionary:         dictionary(t),
		Accept:             []diameter.PeerRule{{HostPattern: "scscf-*.rcs.local"}},
		Logger:             slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.ServeCx(n, 0)
	go func() { _ = n.Serve(ln) }()
	net.add(addr, ln)
	task := &hssTask{node: n, ln: ln, pusher: hss.NewPusher(n, hss.PusherOptions{SCSCFHostPattern: "scscf-*.rcs.local"})}
	t.Cleanup(func() { task.kill() })
	return task
}

func (h *hssTask) kill() {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = h.node.Shutdown(ctx)
	_ = h.ln.Close()
}

// provision creates a subscription with a SIP Digest password through the
// provisioning API, as an operator would, and no AKA keys.
func provision(t *testing.T, h *hss.HSS, st store.Store) {
	t.Helper()
	if _, err := st.CreateProfile(context.Background(), hss.DefaultRCSProfile(hss.DefaultProfileID, "sip:rcs-as.rcs.local")); err != nil {
		t.Fatal(err)
	}
	api := h.NewAPI(hss.APIOptions{Tokens: hss.Tokens{Admin: hss.TokenPair{Current: adminToken}}, DefaultProfile: hss.DefaultProfileID})
	t.Cleanup(func() { _ = api.Close(context.Background()) })
	call := func(method, path string, body any) {
		t.Helper()
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body)
		}
	}
	call(http.MethodPost, "/v1/subscriptions", map[string]any{
		"impi": impi1, "public_identities": []map[string]string{{"impu": impu1}},
	})
	call(http.MethodPost, "/v1/subscriptions/"+impi1+"/digest-credential", nil)
}

// TestAgainstTwoHSSTasks runs the S-CSCF's registration against the real HSS,
// two tasks sharing one store: UAR, MAR with the AKA-then-Digest fallback,
// SAR, LIR, failover when a task dies, and an RTR the surviving task pushes.
func TestAgainstTwoHSSTasks(t *testing.T) {
	st := store.NewMemory()
	keys, err := keyring.NewLocal(bytes.Repeat([]byte{0x42}, keyring.DataKeySize), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newHSS := func() *hss.HSS {
		h, err := hss.New(hss.Options{Store: st, Keys: keys, IMSRealm: realm, ServerNames: []string{scscfName}, Rand: rand.Reader,
			Logger: slog.New(slog.DiscardHandler)})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	taskA, taskB := newHSS(), newHSS()
	provision(t, taskA, st)

	var mu sync.Mutex
	var rtrs []*cx.RTR
	e := newEnv(t, func(c *Config) {
		c.OnRTR = func(_ context.Context, r *cx.RTR) cx.Result {
			mu.Lock()
			rtrs = append(rtrs, r)
			mu.Unlock()
			return cx.ResultCode(diameter.ResultSuccess)
		}
	})
	a := startRealHSS(t, e.net, taskA, "192.0.2.1", "hss-a.rcs.local")
	b := startRealHSS(t, e.net, taskB, "192.0.2.2", "hss-b.rcs.local")
	e.refresh("192.0.2.1", "192.0.2.2")

	uaa, err := e.client.UAR(ctx(t), uar())
	if err != nil || uaa.Result != cx.ExperimentalResult(cx.FirstRegistration) {
		t.Fatalf("UAR: %+v, %v", uaa, err)
	}
	schemes, _ := Schemes("", nil)
	maa, err := e.client.Authenticate(ctx(t), &cx.MAR{UserName: impi1, PublicIdentity: impu1, NumberAuthItems: 1}, schemes)
	if err != nil || !maa.Result.IsSuccess() || maa.AuthDataItems[0].Digest == nil {
		t.Fatalf("MAR: %+v, %v", maa, err)
	}
	saa, err := e.client.SAR(ctx(t), &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.Registration})
	if err != nil || !saa.Result.IsSuccess() || !bytes.Contains(saa.UserData, []byte(impu1)) {
		t.Fatalf("SAR: %+v, %v", saa, err)
	}
	lia, err := e.client.LIR(ctx(t), &cx.LIR{PublicIdentity: impu1})
	if err != nil || lia.ServerName != scscfName {
		t.Fatalf("LIR: %+v, %v", lia, err)
	}

	// Task A dies; every request goes to B.
	a.kill()
	eventually(t, "task A to be unavailable", func() bool {
		for _, p := range e.client.Peers() {
			if p.Address == netip.MustParseAddr("192.0.2.1") && p.Available {
				return false
			}
		}
		return true
	})
	for range 3 {
		if _, err := e.client.SAR(ctx(t), &cx.SAR{UserName: impi1, PublicIdentities: []string{impu1}, AssignmentType: cx.ReRegistration}); err != nil {
			t.Fatalf("after task A died: %v", err)
		}
	}

	// B pushes an administrative deregistration over the connection the
	// client opened to it (ADR 0005).
	if err := b.pusher.Deregister(ctx(t), &cx.RTR{UserName: impi1, DeregistrationReason: cx.DeregistrationReason{Code: cx.PermanentTermination}}); err != nil {
		t.Fatalf("RTR: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(rtrs) != 1 || rtrs[0].UserName != impi1 {
		t.Fatalf("the client got %d RTRs", len(rtrs))
	}
}
