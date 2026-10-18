package transaction

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// waitFor bounds how long a test waits for a message to cross the loopback
// interface. It is a failure deadline, not a delay.
const waitFor = 5 * time.Second

// endpoint is a transport and a transaction layer on the loopback interface,
// with a TU that answers INVITE with 180 and 200 and MESSAGE with 200.
type endpoint struct {
	tr      *transport.Transport
	layer   *Layer
	addr    netip.AddrPort
	network transport.Network
	acks    chan *sip.Request
	got     chan *sip.Request
}

func newEndpoint(t *testing.T, network transport.Network, cfg transport.Config) *endpoint {
	t.Helper()
	e := &endpoint{network: network, acks: make(chan *sip.Request, 4), got: make(chan *sip.Request, 4)}
	var layer *Layer
	tr, err := transport.New(cfg, func(in transport.Inbound) { layer.Receive(in) })
	if err != nil {
		t.Fatal(err)
	}
	layer = New(tr, e, Config{})
	e.tr, e.layer = tr, layer
	e.addr, err = tr.Listen(transport.ListenerConfig{Network: network, Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		layer.Close()
		tr.Close()
	})
	return e
}

func (e *endpoint) Request(tx *ServerTransaction) {
	req := tx.Request()
	e.got <- req
	if req.Method == "INVITE" {
		if res, err := sip.NewResponse(req, 180, "", "bob-tag"); err == nil {
			tx.Respond(res)
		}
	}
	res, err := sip.NewResponse(req, 200, "", "bob-tag")
	if err != nil {
		return
	}
	if req.Method == "INVITE" {
		res.Header.Add("Contact", "<sip:bob@bob.example.com;transport="+string(e.network)+">")
	}
	tx.Respond(res)
}

func (e *endpoint) Stray(in transport.Inbound) {
	if req, ok := in.Message.(*sip.Request); ok && req.Method == "ACK" {
		e.acks <- req
	}
}

func (e *endpoint) ServerFailed(*ServerTransaction, error) {}

// newOutgoing builds a request the way a UA core would, with a placeholder sent-by
// the transport replaces with its own (RFC 3261 §18.1.1).
func newOutgoing(t *testing.T, network transport.Network, method, branch, toTag string, cseq int) *sip.Request {
	t.Helper()
	uri, err := sip.ParseURI("sip:bob@example.com")
	if err != nil {
		t.Fatal(err)
	}
	req := &sip.Request{Method: method, URI: uri}
	to := "<sip:bob@example.com>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	for _, f := range [][2]string{
		{"Via", "SIP/2.0/" + string(network) + " placeholder.invalid;branch=" + branch},
		{"Max-Forwards", "70"},
		{"To", to},
		{"From", "<sip:alice@example.com>;tag=alice-tag"},
		{"Call-ID", "integration-" + string(network) + "@example.com"},
		{"CSeq", strconv.Itoa(cseq) + " " + method},
	} {
		if err := req.Header.Add(f[0], f[1]); err != nil {
			t.Fatal(err)
		}
	}
	return req
}

func awaitResponse(t *testing.T, ch <-chan *sip.Response, code int) *sip.Response {
	t.Helper()
	deadline := time.After(waitFor)
	for {
		select {
		case res := <-ch:
			if res.StatusCode == code {
				return res
			}
		case <-deadline:
			t.Fatalf("no %d response", code)
			return nil
		}
	}
}

func awaitRequest(t *testing.T, ch <-chan *sip.Request) *sip.Request {
	t.Helper()
	select {
	case req := <-ch:
		return req
	case <-time.After(waitFor):
		t.Fatal("no request arrived")
		return nil
	}
}

func TestEndpointsExchangeInviteAckAndMessageOverEveryTransport(t *testing.T) {
	serverTLS, clientTLS := testTLS(t)
	for _, network := range []transport.Network{transport.UDP, transport.TCP, transport.TLS} {
		t.Run(string(network), func(t *testing.T) {
			cfg := transport.Config{TLS: serverTLS, TLSClient: clientTLS}
			alice := newEndpoint(t, network, cfg)
			bob := newEndpoint(t, network, cfg)
			dst := transport.Destination{Network: network, Addr: bob.addr, ServerName: "sip.example.com"}

			responses := make(chan *sip.Response, 8)
			collect := func(res *sip.Response, err error) {
				if err != nil {
					t.Errorf("client transaction failed: %v", err)
					return
				}
				responses <- res
			}

			invite := newOutgoing(t, network, "INVITE", "z9hG4bKinv-"+string(network), "", 1)
			if _, err := alice.layer.Request(invite, dst, collect); err != nil {
				t.Fatal(err)
			}
			if got := awaitRequest(t, bob.got); got.Method != "INVITE" {
				t.Fatalf("bob got %s", got.Method)
			}
			awaitResponse(t, responses, 180)
			ok := awaitResponse(t, responses, 200)
			to, err := ok.Header.To()
			if err != nil || to.Tag() != "bob-tag" {
				t.Fatalf("200 To = %v, %v", to, err)
			}

			// The ACK for a 2xx is a request of its own, sent by the UA core
			// straight through the transport (RFC 3261 §13.2.2.4).
			ack := newOutgoing(t, network, "ACK", "z9hG4bKack-"+string(network), to.Tag(), 1)
			if _, err := alice.tr.SendRequest(ack, dst); err != nil {
				t.Fatal(err)
			}
			if got := awaitRequest(t, bob.acks); got.Header.Get("Call-ID") != invite.Header.Get("Call-ID") {
				t.Fatal("bob's TU got an ACK for another call")
			}

			msg := newOutgoing(t, network, "MESSAGE", "z9hG4bKmsg-"+string(network), to.Tag(), 2)
			msg.Header.Add("Content-Type", "text/plain")
			msg.Body = []byte("hello over " + string(network))
			if _, err := alice.layer.Request(msg, dst, collect); err != nil {
				t.Fatal(err)
			}
			if got := awaitRequest(t, bob.got); got.Method != "MESSAGE" || string(got.Body) != "hello over "+string(network) {
				t.Fatalf("bob got %s %q", got.Method, got.Body)
			}
			awaitResponse(t, responses, 200)
		})
	}
}

// testTLS returns a server configuration with a self-signed certificate for
// sip.example.com and a client configuration that trusts it.
func testTLS(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sip.example.com"},
		DNSNames:     []string{"sip.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	server = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	client = &tls.Config{RootCAs: pool, ServerName: "sip.example.com", MinVersion: tls.VersionTLS12}
	return server, client
}
