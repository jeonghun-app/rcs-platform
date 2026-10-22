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

// stubASPort is the stub application server's SIP port on this container.
const stubASPort = "5080"

// stubAS is an application server acting as a SIP proxy in the originating
// session case (TS 24.229 §5.7.4): it takes what scscf sends it and sends
// it on along its Route, which leads back to scscf with the iFC position
// scscf signed (odi), and counts the requests that came with one.
type stubAS struct {
	uri      sip.URI
	withODI  atomic.Int64
	requests atomic.Int64
}

// startStubAS runs the stub on this container's address on the compose
// network until the test ends.
func startStubAS(t *testing.T, self string) *stubAS {
	t.Helper()
	s := &stubAS{uri: sip.URI{Scheme: "sip", Host: self, Port: mustPort(t, stubASPort)}}
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
	if _, err := tr.Listen(transport.ListenerConfig{Name: "as", Network: transport.TCP, Addr: net.JoinHostPort(self, stubASPort), AdvertisedHost: self}); err != nil {
		t.Fatal(err)
	}
	router := proxy.RouterFunc(func(_ context.Context, r *proxy.Request) proxy.Decision {
		s.requests.Add(1)
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
// hss's default with one criterion before the others: an OPTIONS in the
// originating session case goes to as first, SESSION_TERMINATED, so a
// stub that drops it fails the request. The default comes back when the
// test ends, as stack-seed also puts it back at every make up.
func throughStubAS(ctx context.Context, t *testing.T, as sip.URI, impi, sipIMPU, telIMPU string) {
	t.Helper()
	token := env(t, "HSS_ADMIN_TOKEN")
	var profile map[string]any
	if status := callJSON(ctx, t, http.MethodGet, hssAPI+"/v1/service-profiles/rcs-default", token, nil, &profile); status != http.StatusOK {
		t.Fatalf("hss: reading the default service profile answered %d", status)
	}
	criteria, _ := profile["initial_filter_criteria"].([]any)
	stub := map[string]any{
		"priority": 5,
		"trigger_point": map[string]any{
			"condition_type_cnf": true,
			"spt": []map[string]any{
				{"group": []int{0}, "method": "OPTIONS"},
				{"group": []int{1}, "session_case": "ORIGINATING_REGISTERED"},
			},
		},
		"application_server": map[string]any{"server_name": as.String(), "default_handling": "SESSION_TERMINATED"},
	}
	body := map[string]any{"id": stubProfileID, "initial_filter_criteria": append([]any{stub}, criteria...)}
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
	putProfile(ctx, t, impi, sipIMPU, telIMPU, stubProfileID)
	t.Cleanup(func() { putProfile(context.Background(), t, impi, sipIMPU, telIMPU, "") })
}

// putProfile gives the client subscriber the service profile id, or hss's
// default with "", putting its subscription again as stack-seed does.
func putProfile(ctx context.Context, t *testing.T, impi, sipIMPU, telIMPU, id string) {
	t.Helper()
	sub := map[string]any{
		"impi": impi, "imsi": strings.SplitN(impi, "@", 2)[0], "acs_managed": true,
		"public_identities": []map[string]any{{"impu": sipIMPU, "implicit_set": 0}, {"impu": telIMPU, "implicit_set": 0}},
	}
	if id != "" {
		sub["service_profile"] = id
	}
	if status := callJSON(ctx, t, http.MethodPut, hssAPI+"/v1/subscriptions/"+url.PathEscape(impi), env(t, "HSS_ADMIN_TOKEN"), sub, nil); status != http.StatusOK {
		t.Errorf("hss: putting the client's service profile %q answered %d", id, status)
	}
}
