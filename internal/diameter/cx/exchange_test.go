package cx

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/diameter"
)

// realWait bounds how long the test waits for the nodes' goroutines. It is a
// guard against hangs, not a protocol timer.
const realWait = 5 * time.Second

// pipeListener hands one end of a net.Pipe to Node.Serve per dial.
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

func (l *pipeListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// connectedNodes starts an HSS that serves Cx and an S-CSCF connected to it.
func connectedNodes(t *testing.T) (hss *diameter.Node, peer *diameter.Peer, scscf *diameter.Node) {
	t.Helper()
	ln := &pipeListener{conns: make(chan net.Conn), closed: make(chan struct{})}
	config := func(host string) diameter.Config {
		return diameter.Config{
			OriginHost:         host,
			OriginRealm:        realm,
			HostIPAddresses:    []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			Applications:       []diameter.Application{Application},
			SupportedVendorIDs: []uint32{Vendor3GPP, VendorETSI},
			Dictionary:         testDictionary(t),
			Accept:             []diameter.PeerRule{{Realm: realm}},
			Dial:               ln.dial,
		}
	}
	hss = must(diameter.NewNode(config(hssHost)))
	scscf = must(diameter.NewNode(config(scscfHost)))
	go func() { _ = hss.Serve(ln) }()
	peer = must(scscf.Connect(diameter.PeerConfig{Address: "hss:3868", Host: hssHost}))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), realWait)
		defer cancel()
		_ = scscf.Shutdown(ctx)
		_ = hss.Shutdown(ctx)
		_ = ln.Close()
	})
	deadline := time.Now().Add(realWait)
	for !peer.Available() {
		if time.Now().After(deadline) {
			t.Fatal("capabilities exchange did not complete")
		}
		time.Sleep(time.Millisecond)
	}
	return hss, peer, scscf
}

func TestCxRequestsAndAnswersCrossARealConnection(t *testing.T) {
	hss, peer, scscf := connectedNodes(t)
	hss.SetErrorAVPs(ApplicationID, ErrorAVPs)
	hss.HandleFunc(ApplicationID, CodeMultimediaAuth, func(_ context.Context, _ *diameter.Peer, req *diameter.Message) (*diameter.Message, error) {
		mar, err := ParseMAR(req)
		if err != nil {
			return nil, err // answered by the node with the fault's Result-Code
		}
		maa := &MAA{
			Answer:          Answer{Result: ResultCode(diameter.ResultSuccess)},
			UserName:        mar.UserName,
			PublicIdentity:  mar.PublicIdentity,
			NumberAuthItems: 1,
			AuthDataItems:   []AuthDataItem{{ItemNumber: 1, Scheme: SchemeDigestAKAv1MD5, Authenticate: seq(32, 1)}},
		}
		return maa.Message(hss, req)
	})
	ctx, cancel := context.WithTimeout(context.Background(), realWait)
	defer cancel()

	mar := &MAR{
		Request:         Request{DestinationRealm: realm},
		UserName:        impi,
		PublicIdentity:  impu,
		AuthDataItem:    AuthDataItem{Scheme: SchemeDigestAKAv1MD5},
		NumberAuthItems: 1,
		ServerName:      scscfName,
	}
	ans, err := peer.Send(ctx, must(mar.Message(scscf)))
	if err != nil {
		t.Fatal(err)
	}
	maa, err := ParseMAA(ans)
	if err != nil {
		t.Fatal(err)
	}
	if maa.Result != ResultCode(diameter.ResultSuccess) || len(maa.AuthDataItems) != 1 || maa.OriginHost != hssHost {
		t.Errorf("MAA = %+v", maa)
	}

	// A MAR without User-Name is answered by the node from the parse error,
	// with the AVPs ErrorAVPs supplies.
	bad := scscf.NewRequest(CodeMultimediaAuth, ApplicationID, scscf.NewSessionID(""),
		append(ApplicationAVPs(Application), specDestinationRealm.UTF8String(realm))...)
	ans, err = peer.Send(ctx, bad)
	if err != nil {
		t.Fatal(err)
	}
	maa, err = ParseMAA(ans)
	if err != nil {
		t.Fatal(err)
	}
	if maa.Result != ResultCode(diameter.ResultMissingAVP) {
		t.Errorf("result = %v, want DIAMETER_MISSING_AVP", maa.Result)
	}
	checkApplicationAVPs(t, ans)
	if ans.Find(diameter.AVPFailedAVP, 0) == nil {
		t.Error("no Failed-AVP")
	}
}
