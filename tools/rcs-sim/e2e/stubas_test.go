//go:build e2ecompose

package e2e

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/proxy"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// The stub application servers' SIP ports on this container: the first
// of the chain, and the one after it.
const (
	stubASPort     = "5080"
	nextStubASPort = "5081"
)

// stubAS is an application server acting as a SIP proxy in the originating
// session case (TS 24.229 §5.7.4): it takes what scscf sends it and sends
// it on along its Route, which leads back to scscf with the iFC position
// scscf signed (odi), and counts the requests that came with one, and
// those that had passed through the stub on port after first, by its Via.
type stubAS struct {
	uri       sip.URI
	after     string
	withODI   atomic.Int64
	requests  atomic.Int64
	afterPrev atomic.Int64
}

// startStubAS runs a stub on this container's address on the compose
// network, at port, until the test ends; after, if not "", is the port of
// the stub before it in the chain.
func startStubAS(t *testing.T, self, port, after string) *stubAS {
	t.Helper()
	s := &stubAS{uri: sip.URI{Scheme: "sip", Host: self, Port: mustPort(t, port)}, after: after}
	s.uri.Params.Set("transport", "tcp")
	var p atomic.Pointer[proxy.Proxy]
	tr, err := transport.New(transport.Config{}, func(in transport.Inbound) {
		if px := p.Load(); px != nil {
			px.Receive(in)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	if _, err := tr.Listen(transport.ListenerConfig{Name: "as", Network: transport.TCP, Addr: net.JoinHostPort(self, port), AdvertisedHost: self}); err != nil {
		t.Fatal(err)
	}
	router := proxy.RouterFunc(func(_ context.Context, r *proxy.Request) proxy.Decision {
		s.requests.Add(1)
		if s.after != "" {
			for _, v := range r.Message.Header.Values("Via") {
				if strings.Contains(v, ":"+s.after+";") || strings.HasSuffix(v, ":"+s.after) {
					s.afterPrev.Add(1)
					break
				}
			}
		}
		if routes, err := r.Message.Header.Route(); err == nil {
			for _, rt := range routes {
				if _, ok := rt.URI.Param("odi"); ok {
					s.withODI.Add(1)
				}
			}
		}
		return proxy.Forward(r)
	})
	px, err := proxy.New(tr, proxy.Config{
		Self: []sip.URI{s.uri}, Router: router,
		// scscf's Route names it by its service name, in rcs.local.
		Resolver: &proxy.DNSResolver{Namespace: "rcs.local"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(px.Close)
	p.Store(px)
	return s
}

func mustPort(t *testing.T, s string) int {
	t.Helper()
	u, err := sip.ParseURI("sip:x:" + s)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port
}

// stubProfileID names the service profile that sends the client's
// originating OPTIONS through the stub.
const stubProfileID = "e2e-originating-stub-as"

// throughStubAS gives the client subscriber a service profile that is
// hss's default with a criterion before the others for each of ases: an
// OPTIONS in the originating session case goes to each in turn,
// SESSION_TERMINATED, so a stub that drops it fails the request. The
// default comes back when the test ends, as stack-seed also puts it back
// at every make up.
func throughStubAS(ctx context.Context, t *testing.T, ases []sip.URI, impi string) {
	t.Helper()
	token := env(t, "HSS_ADMIN_TOKEN")
	var profile map[string]any
	if status := callJSON(ctx, t, http.MethodGet, hssAPI+"/v1/service-profiles/rcs-default", token, nil, &profile); status != http.StatusOK {
		t.Fatalf("hss: reading the default service profile answered %d", status)
	}
	criteria, _ := profile["initial_filter_criteria"].([]any)
	var stubs []any
	for i, as := range ases {
		stubs = append(stubs, map[string]any{
			"priority": 5 + i,
			"trigger_point": map[string]any{
				"condition_type_cnf": true,
				"spt": []map[string]any{
					{"group": []int{0}, "method": "OPTIONS"},
					{"group": []int{1}, "session_case": "ORIGINATING_REGISTERED"},
				},
			},
			"application_server": map[string]any{"server_name": as.String(), "default_handling": "SESSION_TERMINATED"},
		})
	}
	body := map[string]any{"id": stubProfileID, "initial_filter_criteria": append(stubs, criteria...)}
	switch status := callJSON(ctx, t, http.MethodPost, hssAPI+"/v1/service-profiles", token, body, nil); status {
	case http.StatusCreated:
	case http.StatusConflict:
		// An earlier run's, whose AS address may differ.
		if status := callJSON(ctx, t, http.MethodPut, hssAPI+"/v1/service-profiles/"+stubProfileID, token, body, nil); status != http.StatusOK {
			t.Fatalf("hss: putting the stub's service profile answered %d", status)
		}
	default:
		t.Fatalf("hss: creating the stub's service profile answered %d", status)
	}
	putProfile(ctx, t, impi, stubProfileID)
	t.Cleanup(func() { putProfile(context.Background(), t, impi, "") })
}

// putProfile gives the client subscriber the service profile id, or hss's
// default with "". It puts the subscription back as it reads it, but for
// the profile and the fields the API reports and does not take, so that
// whatever stack-seed provisions stays as it is (#473 QA).
func putProfile(ctx context.Context, t *testing.T, impi, id string) {
	t.Helper()
	token := env(t, "HSS_ADMIN_TOKEN")
	var sub map[string]any
	if status := callJSON(ctx, t, http.MethodGet, hssAPI+"/v1/subscriptions/"+url.PathEscape(impi), token, nil, &sub); status != http.StatusOK {
		t.Fatalf("hss: reading the client's subscription answered %d", status)
	}
	put := map[string]any{}
	for _, k := range []string{"impi", "imsi", "public_identities", "charging_information", "acs_managed"} {
		if v, ok := sub[k]; ok {
			put[k] = v
		}
	}
	if ids, ok := put["public_identities"].([]any); ok {
		for _, x := range ids {
			if id, ok := x.(map[string]any); ok {
				delete(id, "registration_state")
			}
		}
	}
	if id != "" {
		put["service_profile"] = id
	}
	if status := callJSON(ctx, t, http.MethodPut, hssAPI+"/v1/subscriptions/"+url.PathEscape(impi), token, put, nil); status != http.StatusOK {
		t.Errorf("hss: putting the client's service profile %q answered %d", id, status)
	}
}
