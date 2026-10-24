package bridge

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transaction"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/simtest"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// coreHarness is a bridge whose SIP side is the real one (NewSIP), against
// rcs-sim's in-process IMS core stand-in, which authenticates with Digest:
// fakeHSS gives "car" slot 000 and "phone" slot 001, with their passwords.
func coreHarness(t *testing.T, offline simtest.Offline) (*harness, *simtest.IMSCore) {
	t.Helper()
	core := simtest.StartIMSCore(t, testDomain, map[string]string{
		testIMPI("car"): "password-000", testIMPI("phone"): "password-001",
	})
	core.Offline = offline
	sipNet, err := NewSIP(SIPConfig{Proxy: core.Addr.String(), Domain: testDomain})
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *Config) { c.SIP = sipNet })
	return h, core
}

func TestOverSIPAMessageAndItsNotificationsGoBetweenTwoEndpoints(t *testing.T) {
	h, core := coreHarness(t, simtest.Refuse)
	ev := h.events()
	h.online("car")
	h.online("phone")
	impu := "sip:" + msisdnPrefix + "000@" + testDomain
	if !core.Registered(impu) || !core.Registered("sip:"+msisdnPrefix+"001@"+testDomain) {
		t.Fatal("the endpoints are not registered at the core")
	}
	status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{
		"to": "phone", "content_type": "text/plain;charset=utf-8", "body": "안녕 over SIP", "message_id": "sip-1", "imdn": []string{"delivery", "display"},
	})
	// The phone's own 200: the stand-in core keeps nothing.
	if status != http.StatusOK || out["sip_status"] != float64(200) {
		t.Fatalf("send answered %d %v", status, out)
	}
	m := ev.await("message", "phone")
	if m["from"] != impu || m["from_endpoint"] != "car" || m["body"] != "안녕 over SIP" || m["content_type"] != "text/plain;charset=utf-8" || m["message_id"] != "sip-1" {
		t.Fatalf("message event %v", m)
	}
	if d := ev.await("imdn", "car"); d["status"] != "delivered" || d["from_endpoint"] != "phone" || d["message_id"] != "sip-1" {
		t.Fatalf("imdn event %v", d)
	}
	if status, out := h.call(http.MethodPost, "/v1/endpoints/phone/imdn", map[string]any{"to": "car", "message_id": "sip-1", "status": "displayed"}); status != http.StatusOK || out["sip_status"] != float64(200) {
		t.Fatalf("imdn answered %d %v", status, out)
	}
	if d := ev.await("imdn", "car"); d["status"] != "displayed" || d["from_endpoint"] != "phone" {
		t.Fatalf("imdn event %v", d)
	}
	// Offline is a de-registration the core sees.
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	if core.Registered("sip:" + msisdnPrefix + "001@" + testDomain) {
		t.Fatal("the phone is still registered at the core")
	}
	if status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "x"}); status != http.StatusOK || out["sip_status"] != float64(480) {
		t.Fatalf("a send to the unregistered phone answered %d %v, want sip_status 480", status, out)
	}
}

func TestOverSIPAStoredMessageArrivesOnceTheReceiverRegistersAgain(t *testing.T) {
	h, _ := coreHarness(t, simtest.StoreAndForward)
	ev := h.events()
	h.online("car")
	h.online("phone")
	h.call(http.MethodPut, "/v1/endpoints/phone", map[string]bool{"online": false})
	status, out := h.call(http.MethodPost, "/v1/endpoints/car/messages", map[string]any{"to": "phone", "body": "kept", "message_id": "kept-1"})
	if status != http.StatusOK || out["sip_status"] != float64(202) {
		t.Fatalf("send answered %d %v, want the core's 202", status, out)
	}
	h.online("phone")
	if m := ev.await("message", "phone"); m["message_id"] != "kept-1" || m["body"] != "kept" || m["from_endpoint"] != "car" {
		t.Fatalf("message event %v", m)
	}
}

func TestATimedOutTransactionIs408AndAFailedFlowAnError(t *testing.T) {
	if code, err := finalStatus(nil, fmt.Errorf("sipua: %w", transaction.ErrTimeout)); code != 408 || err != nil {
		t.Fatalf("a timeout = %d %v, want 408", code, err)
	}
	if code, err := finalStatus(nil, sipua.ErrFlowFailed); code != 0 || !errors.Is(err, sipua.ErrFlowFailed) {
		t.Fatalf("a failed flow = %d %v", code, err)
	}
	if code, err := finalStatus(&sip.Response{StatusCode: 202}, nil); code != 202 || err != nil {
		t.Fatalf("a 202 = %d %v", code, err)
	}
}
