//go:build e2ecompose

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
)

// The compose stack as deploy/docker-compose.yml names it: the test runs on
// its network (make e2e-compose), with deploy/compose.env as its
// environment. The subscriber is the one stack-seed provisions.
const (
	// composeDomain is fixed: acs derives it from the IMSI's MCC and MNC.
	composeDomain = "ims.mnc001.mcc001.3gppnetwork.org"
	composeIMSI   = "001010000000001"
	composeMSISDN = "+15550100001"
	// The peer, stack-seed's second subscriber.
	composePeerIMSI   = "001010000000002"
	composePeerMSISDN = "+15550100002"
	hssAPI            = "http://hss:8081"
	acsURL            = "http://acs:8080"
	relayControl      = "http://msrp-relay:8082"
)

func TestE2EComposeStack(t *testing.T) {
	domain := composeDomain
	ftBase := env(t, "FT_PUBLIC_BASE")
	impi := composeIMSI + "@" + domain
	impu := "sip:" + composeMSISDN + "@" + domain
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	for _, svc := range []string{"hss", "ft-server", "msrp-relay", "icscf", "scscf", "pcscf", "rcs-as-a"} {
		waitReady(ctx, t, "http://"+svc+":8080/readyz")
	}
	waitReady(ctx, t, acsURL+"/readyz")

	// acs: what a device is told points at this stack (stack-seed's
	// overrides, docs/local-stack.md).
	doc := acsConfiguration(ctx, t, env(t, "ACS_ADMIN_TOKEN"))
	for _, want := range []struct{ characteristic, parm, value string }{
		// The identities acs hands out are the ones hss holds.
		{"APPLICATION", "Private_User_Identity", impi},
		{"APPLICATION", "Home_network_domain_name", domain},
		{"Public_User_Identity", "Public_User_Identity", impu},
		{"FT", "ftHTTPCSURI", ftBase + "/ft"},
		{"FT", "ftHTTPDLURI", ftBase + "/dl"},
		{"LBO_P-CSCF_Address", "Address", env(t, "PCSCF_PUBLIC_HOST")},
		// The same as acs's default until rcs-as names its own, so this
		// would not catch a mistyped override key (docs/local-stack.md).
		{"CHAT", "ConfFctyURI", "sip:conf-factory@" + domain},
	} {
		if got := doc.value(want.characteristic, want.parm); got != want.value {
			t.Errorf("acs provisions %s %s = %q, want %q", want.characteristic, want.parm, got, want.value)
		}
	}
	uploadURL := doc.value("FT", "ftHTTPCSURI")

	// hss: the number's SIP and tel IMPUs in one implicit registration set
	// (docs/architecture.md §4, #282), so a terminating request to the tel
	// form reaches the client, which the options scenario sends below.
	// Both subscribers stack-seed provisions, the client and the peer.
	for _, sub := range []struct{ imsi, msisdn string }{{composeIMSI, composeMSISDN}, {composePeerIMSI, composePeerMSISDN}} {
		checkImplicitSet(ctx, t, sub.imsi+"@"+domain, "sip:"+sub.msisdn+"@"+domain, "tel:"+sub.msisdn)
	}

	// acs 1.4.0 cannot provision ftHTTPCSUser and ftHTTPCSPwd yet
	// (auto-configuration-server#69), so the test issues the FT password
	// from hss itself, as acs will.
	var issued struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if status := callJSON(ctx, t, http.MethodPost, hssAPI+"/v1/subscriptions/"+url.PathEscape(impi)+"/ft-credential",
		env(t, "HSS_ADMIN_TOKEN"), nil, &issued); status != http.StatusCreated || issued.Username != impi || issued.Password == "" {
		t.Fatalf("hss: issuing the FT credential answered %d", status)
	}

	// rcs-sim: file transfer through ft-server on S3Mock and DynamoDB Local
	// with its credentials looked up in hss, and chat through msrp-relay on
	// DynamoDB Local, rcs-sim standing in for pcscf and rcs-as: it has no
	// chat over SIP yet (#135). The relay connects to the stand-in on this
	// container's address.
	bin := build(t, "./tools/rcs-sim")
	self := ownAddress(t)
	cmd := exec.CommandContext(ctx, filepath.Join(bin, "rcs-sim"),
		"-ft-upload-url", uploadURL, "-ft-user", impi,
		"-relay-control", relayControl,
		"-core-listen", net.JoinHostPort(self, "2855"), "-core-advertise", self,
		"-msrp-keepalive", "300ms", "-idle-wait", "1500ms",
		"all")
	cmd.Env = append(os.Environ(), "RCS_SIM_FT_PASSWORD="+issued.Password, "RCS_SIM_RELAY_TOKEN="+env(t, "RELAY_PCSCF_TOKEN"))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	t.Logf("rcs-sim output:\n%s%s", stdout.String(), stderr.String())
	if err != nil {
		t.Errorf("rcs-sim: %v", err)
	}
	checkResults(t, stdout.String(), stderr.String(), []string{
		"ft/upload", "ft/download", "ft/download-range", "ft/download-resume", "ft/download-thumbnail",
		"ft-resume/interrupted-upload", "ft-resume/get_upload_info", "ft-resume/resume", "ft-resume/download",
		"chat-client-originated/client-to-core", "chat-client-originated/keep-alive", "chat-client-originated/release",
		"chat-core-originated/connect-then-answer", "chat-core-originated/core-sends-first", "chat-core-originated/release",
	}, issued.Password, env(t, "RELAY_PCSCF_TOKEN"), impi, self)

	// rcs-sim over SIP (#14 PR F2): both subscribers register with IMS AKA,
	// with the keys stack-seed gave hss, at the P-CSCF acs provisions,
	// through pcscf, icscf and scscf. reg-event watches the client's own
	// registration; options sends the peer a query to its tel URI and a
	// capability query, both through scscf's originating and terminating
	// iFC chains, where the default profile's criterion sends the capability
	// query through rcs-as, which passes it on. pager-message sends the peer
	// a MESSAGE, which the default profile takes to rcs-as: rcs-as stores it
	// and delivers it to the peer, the peer's delivery notification goes
	// back the same way, and a message to the peer unregistered waits in
	// rcs-as's queue until it registers again (#135).
	// The client's default profile first: a run cut short before it put
	// it back would leave the stub's, whose AS is gone, and fail the
	// first OPTIONS with a 500 that says nothing of why (#473 code review).
	putProfile(ctx, t, impi, "")
	pcscf := doc.value("LBO_P-CSCF_Address", "Address")
	sipCmd := exec.CommandContext(ctx, filepath.Join(bin, "rcs-sim"),
		"-sip-proxy", net.JoinHostPort(pcscf, "5060"), "-sip-transport", "tcp",
		"-sip-impi", impi, "-sip-peer-impi", composePeerIMSI+"@"+domain,
		"reg-event", "options", "pager-message")
	var sipOut, sipErr bytes.Buffer
	sipCmd.Stdout, sipCmd.Stderr = &sipOut, &sipErr
	err = sipCmd.Run()
	t.Logf("rcs-sim SIP output:\n%s%s", sipOut.String(), sipErr.String())
	if err != nil {
		t.Errorf("rcs-sim over SIP: %v", err)
	}
	sipResults := checkResults(t, sipOut.String(), sipErr.String(), []string{
		"reg-event/register", "reg-event/subscribe", "reg-event/re-register", "reg-event/refresh", "reg-event/unsubscribe",
		"reg-event/unregister",
		"options/register", "options/tel-uri", "options/capabilities",
		"pager-message/register", "pager-message/message", "pager-message/receive",
		"pager-message/delivery-notification", "pager-message/peer-offline",
	}, env(t, "RCS_SIM_AKA_K"), env(t, "RCS_SIM_AKA_OPC"), env(t, "RCS_SIM_PEER_AKA_K"), env(t, "RCS_SIM_PEER_AKA_OPC"),
		composeIMSI, composePeerIMSI)
	// rcs-as took both messages: it answers 202 to one it has stored, which
	// the peer's own client never does (it answers 200), so a MESSAGE that
	// went to the peer past rcs-as would have the peer's 200. The second,
	// to the peer unregistered, reached it once it registered again.
	// #563: a subscriber that takes its route set from the first NOTIFY
	// (RFC 6665 §4.4.1), as sipua does, refreshes and ends its subscription
	// along it, through pcscf and scscf, each answered 200.
	for _, step := range []string{"reg-event/refresh", "reg-event/unsubscribe"} {
		if r := sipResults[step]; r.Detail["status"] != 200 {
			t.Errorf("%s was answered %d, not 200", step, r.Detail["status"])
		}
	}
	if r := sipResults["pager-message/message"]; r.Detail["status"] != 202 {
		t.Errorf("the MESSAGE was answered %d, not rcs-as's 202", r.Detail["status"])
	}
	if r := sipResults["pager-message/peer-offline"]; r.Detail["status"] != 202 || r.Detail["stored"] != 1 {
		t.Errorf("the MESSAGE to the unregistered peer was answered %d (stored and delivered: %d), want rcs-as's 202 and its delivery once the peer registered",
			r.Detail["status"], r.Detail["stored"])
	}

	// The originating iFC chain through more than one application server
	// (#14 PR F2): two stubs on this container, in criteria ahead of the
	// default profile's, take the client's OPTIONS in turn, as an AS acting
	// as a proxy does, and send them back to scscf, which goes on along the
	// chain, through rcs-as, to icscf and the peer.
	as := startStubAS(t, self, stubASPort, "")
	next := startStubAS(t, self, nextStubASPort, stubASPort)
	throughStubAS(ctx, t, []sip.URI{as.uri, next.uri}, impi)
	asCmd := exec.CommandContext(ctx, filepath.Join(bin, "rcs-sim"),
		"-sip-proxy", net.JoinHostPort(pcscf, "5060"), "-sip-transport", "tcp",
		"-sip-impi", impi, "-sip-peer-impi", composePeerIMSI+"@"+domain,
		"options")
	var asOut, asErr bytes.Buffer
	asCmd.Stdout, asCmd.Stderr = &asOut, &asErr
	err = asCmd.Run()
	t.Logf("rcs-sim through the stub AS:\n%s%s", asOut.String(), asErr.String())
	if err != nil {
		t.Errorf("rcs-sim through the stub AS: %v", err)
	}
	checkResults(t, asOut.String(), asErr.String(), []string{"options/register", "options/tel-uri", "options/capabilities"},
		env(t, "RCS_SIM_AKA_K"), env(t, "RCS_SIM_AKA_OPC"), env(t, "RCS_SIM_PEER_AKA_K"), env(t, "RCS_SIM_PEER_AKA_OPC"),
		composeIMSI, composePeerIMSI)
	// Both OPTIONS went through the stub, each with scscf's iFC position.
	if n, odi := as.requests.Load(), as.withODI.Load(); n != 2 || odi != 2 {
		t.Errorf("the stub AS took %d requests, %d with an iFC position; want both OPTIONS with one", n, odi)
	}
	// And scscf went on from that position to the next criterion: the
	// second stub took both, each after the first. A request whose
	// position scscf ignored would have been routed as terminating, past
	// the second stub (#473 QA).
	if n, odi, after := next.requests.Load(), next.withODI.Load(), next.afterPrev.Load(); n != 2 || odi != 2 || after != 2 {
		t.Errorf("the second stub AS took %d requests, %d with an iFC position, %d after the first; want both OPTIONS so", n, odi, after)
	}
}

// checkImplicitSet checks that hss lists sip and tel in one implicit
// registration set of impi's subscription.
func checkImplicitSet(ctx context.Context, t *testing.T, impi, sip, tel string) {
	t.Helper()
	var sub struct {
		PublicIdentities []struct {
			IMPU        string `json:"impu"`
			ImplicitSet int    `json:"implicit_set"`
		} `json:"public_identities"`
	}
	if status := callJSON(ctx, t, http.MethodGet, hssAPI+"/v1/subscriptions/"+url.PathEscape(impi), env(t, "HSS_ADMIN_TOKEN"), nil, &sub); status != http.StatusOK {
		t.Fatalf("hss: reading a test subscription answered %d", status)
	}
	sets := map[string]int{}
	for _, p := range sub.PublicIdentities {
		sets[p.IMPU] = p.ImplicitSet
	}
	sipSet, okSIP := sets[sip]
	telSet, okTel := sets[tel]
	if !okSIP || !okTel || sipSet != telSet {
		t.Errorf("hss lists the identities %+v, want %s and %s in one implicit set", sub.PublicIdentities, sip, tel)
	}
}

// env returns a setting of deploy/compose.env, which make e2e-compose passes.
func env(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: run this through make e2e-compose, after make up", name)
	}
	return v
}

// waitReady polls target until it answers 200: make up waits for the
// processes (/healthz); their stores may take a moment longer.
func waitReady(ctx context.Context, t *testing.T, target string) {
	t.Helper()
	var last string
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s is not ready (%s): is the stack up (make up)?", target, last)
		case <-time.After(time.Second):
		}
	}
}

// callJSON sends body (none when nil) with a bearer token and decodes a
// JSON answer into out (when not nil). It returns the status.
func callJSON(ctx context.Context, t *testing.T, method, target, token string, body, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(out); err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
	}
	return resp.StatusCode
}

// provisioningDoc is the part of an OMA-CP document the test reads.
type provisioningDoc struct {
	Characteristics []characteristic `xml:"characteristic"`
}

type characteristic struct {
	Type            string           `xml:"type,attr"`
	Parms           []parm           `xml:"parm"`
	Characteristics []characteristic `xml:"characteristic"`
}

type parm struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// value returns the first parm called name in a characteristic of type
// typ, anywhere in the document.
func (d provisioningDoc) value(typ, name string) string {
	var walk func([]characteristic) (string, bool)
	walk = func(cs []characteristic) (string, bool) {
		for _, c := range cs {
			if c.Type == typ {
				for _, p := range c.Parms {
					if p.Name == name {
						return p.Value, true
					}
				}
			}
			if v, ok := walk(c.Characteristics); ok {
				return v, true
			}
		}
		return "", false
	}
	v, _ := walk(d.Characteristics)
	return v
}

// acsConfiguration fetches the test subscriber's configuration the way
// acs's own deployment check does (scripts/verify_stack.py): a token issued
// through the admin API, presented in an RCC.14 configuration request.
func acsConfiguration(ctx context.Context, t *testing.T, adminToken string) provisioningDoc {
	t.Helper()
	var issued struct {
		Token string `json:"token"`
	}
	if status := callJSON(ctx, t, http.MethodPost, acsURL+"/admin/subscribers/"+composeIMSI+"/issue-token", adminToken, nil, &issued); status != http.StatusOK || issued.Token == "" {
		t.Fatalf("acs: issuing a provisioning token answered %d", status)
	}
	q := url.Values{
		"vers": {"0"}, "IMSI": {composeIMSI}, "msisdn": {composeMSISDN}, "token": {issued.Token},
		"terminal_vendor": {"RCSSIM"}, "terminal_model": {"rcs-sim"}, "terminal_sw_version": {"1"},
		"client_vendor": {"RCSSIM"}, "client_version": {"1.0"}, "rcs_version": {"9.0"}, "rcs_profile": {"UP_2.4"},
		"rcs_state": {"0"}, "default_sms_app": {"1"}, "provisioning_version": {"1"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, acsURL+"/?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/xml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("acs: configuration request: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("acs: configuration request answered %d (%v)", resp.StatusCode, err)
	}
	var doc provisioningDoc
	dec := xml.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("acs: configuration document: %v", err)
	}
	return doc
}

// ownAddress is this container's address on the compose network, where the
// relay reaches the rcs-as stand-in.
func ownAddress(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() != nil && !ip.IP.IsLoopback() {
			return ip.IP.String()
		}
	}
	t.Fatal("no IPv4 address on the compose network")
	return ""
}
