package bridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jeonghun-app/rcs-platform/internal/milenage"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/secret"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// The bridge's subscribers, in the MCC 001 / MNC 01 test network
// (.github/allowed-test-identifiers.txt): slot n has the IMSI imsiPrefix
// and n in three digits, and the MSISDN msisdnPrefix and the same three
// digits. +1 555 010 is no real number: NANP central office codes never
// start with 0. The slots are apart from stack-seed's two subscribers.
const (
	imsiPrefix   = "001010000872"
	msisdnPrefix = "+15550108"
	slots        = 1000
)

// impiPrefix starts every IMPI the bridge provisions. The rest is a hash
// of the endpoint's name, so that the bridge finds an endpoint's
// subscription again after a restart, by name, without keeping any state
// of its own; and an IMPI says nothing of the name.
const impiPrefix = "rcs-bridge-"

// HSSConfig configures NewHSS.
type HSSConfig struct {
	// URL is hss's provisioning API, such as http://hss:8081.
	URL string
	// Token is a token of the operator, the caller that may create
	// subscriptions and set their keys (docs/api/hss-scopes.md).
	Token secret.Key
	// Domain is the home network domain, of the IMPIs and the SIP IMPUs.
	Domain string
	// Client is the HTTP client; nil is one with a 10 s timeout.
	Client *http.Client
	// Rand supplies the AKA keys; nil is crypto/rand.
	Rand io.Reader
}

// NewHSS returns the Provisioner that keeps the bridge's subscribers in
// hss.
func NewHSS(c HSSConfig) (Provisioner, error) {
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("bridge: the hss URL must be an http(s) URL")
	}
	if c.Token.IsZero() || c.Domain == "" {
		return nil, errors.New("bridge: hss needs a token and the home domain")
	}
	if c.Client == nil {
		c.Client = &http.Client{Timeout: 10 * time.Second, CheckRedirect: runtime.RefuseRedirects}
	}
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	c.URL = strings.TrimSuffix(c.URL, "/")
	return &hssProvisioner{cfg: c}, nil
}

type hssProvisioner struct{ cfg HSSConfig }

// subscription is the part of hss's Subscription the bridge writes and
// reads (docs/api/hss.yaml).
type subscription struct {
	IMPI             string     `json:"impi"`
	IMSI             string     `json:"imsi"`
	PublicIdentities []identity `json:"public_identities"`
}

type identity struct {
	IMPU        string `json:"impu"`
	ImplicitSet int    `json:"implicit_set"`
}

// Provision finds the endpoint's subscription in hss, or creates it in the
// first free slot from one its name picks, and gives it fresh AKA keys.
// The keys are made here, sent once to hss and kept only inside the
// Subscriber's credentials. A subscription found again, after a restart of
// the bridge, keeps its identities and its SQN and is given new keys: hss
// never returns the old ones.
func (h *hssProvisioner) Provision(ctx context.Context, name string) (Subscriber, error) {
	impi := impiOf(name, h.cfg.Domain)
	sub, found, err := h.get(ctx, impi)
	if err != nil {
		return Subscriber{}, err
	}
	if !found {
		if sub, err = h.create(ctx, name, impi); err != nil {
			return Subscriber{}, err
		}
	}
	impu, tel, err := h.identities(sub)
	if err != nil {
		return Subscriber{}, err
	}
	var k, opc [milenage.KeySize]byte
	for k == opc {
		if _, err := io.ReadFull(h.cfg.Rand, k[:]); err != nil {
			return Subscriber{}, err
		}
		if _, err := io.ReadFull(h.cfg.Rand, opc[:]); err != nil {
			return Subscriber{}, err
		}
	}
	keys := map[string]string{"k": hex.EncodeToString(k[:]), "opc": hex.EncodeToString(opc[:])}
	status, err := h.call(ctx, http.MethodPut, "/v1/subscriptions/"+url.PathEscape(impi)+"/aka", keys, nil)
	switch {
	case err != nil:
		return Subscriber{}, fmt.Errorf("hss: set AKA keys: %w", err)
	case status != http.StatusNoContent:
		return Subscriber{}, fmt.Errorf("hss: set AKA keys answered %d", status)
	}
	creds, err := sipua.AKACredentials(impi, k, opc)
	if err != nil {
		return Subscriber{}, err
	}
	return Subscriber{IMPI: impi, IMPU: impu, Tel: tel, Credentials: creds, InstanceID: instanceOf(impi)}, nil
}

// create makes the subscription in the first free slot from the one
// name's hash picks. hss answers 409 for an IMPU another subscription
// has, which is a slot taken, or for the IMPI itself, which another
// creation made meanwhile.
func (h *hssProvisioner) create(ctx context.Context, name, impi string) (subscription, error) {
	sum := sha256.Sum256([]byte(name))
	start := int(binary.BigEndian.Uint32(sum[:4]) % slots)
	for i := range slots {
		n := (start + i) % slots
		digits := fmt.Sprintf("%03d", n)
		sub := subscription{
			IMPI: impi,
			IMSI: imsiPrefix + digits,
			// The SIP IMPU first, the set's default identity (TS 29.228
			// §6.5.1.1), and the tel URI of the number with it, as
			// stack-seed provisions its subscribers.
			PublicIdentities: []identity{
				{IMPU: "sip:" + msisdnPrefix + digits + "@" + h.cfg.Domain},
				{IMPU: "tel:" + msisdnPrefix + digits},
			},
		}
		body := map[string]any{"impi": sub.IMPI, "imsi": sub.IMSI, "public_identities": sub.PublicIdentities}
		status, err := h.call(ctx, http.MethodPost, "/v1/subscriptions", body, nil)
		switch {
		case err != nil:
			return subscription{}, fmt.Errorf("hss: create subscription: %w", err)
		case status == http.StatusCreated:
			return sub, nil
		case status != http.StatusConflict:
			return subscription{}, fmt.Errorf("hss: create subscription answered %d", status)
		}
		got, found, err := h.get(ctx, impi)
		if err != nil {
			return subscription{}, err
		}
		if found {
			return got, nil
		}
	}
	return subscription{}, errors.New("hss: every subscriber slot of the bridge is taken")
}

func (h *hssProvisioner) get(ctx context.Context, impi string) (subscription, bool, error) {
	var sub subscription
	status, err := h.call(ctx, http.MethodGet, "/v1/subscriptions/"+url.PathEscape(impi), nil, &sub)
	switch {
	case err != nil:
		return subscription{}, false, fmt.Errorf("hss: read subscription: %w", err)
	case status == http.StatusNotFound:
		return subscription{}, false, nil
	case status != http.StatusOK:
		return subscription{}, false, fmt.Errorf("hss: read subscription answered %d", status)
	}
	return sub, true, nil
}

// identities are the SIP IMPU and the tel URI of a bridge subscription,
// which must be a slot's.
func (h *hssProvisioner) identities(sub subscription) (sip.URI, sip.URI, error) {
	var impu, tel sip.URI
	for _, id := range sub.PublicIdentities {
		u, err := sip.ParseURI(id.IMPU)
		if err != nil {
			continue
		}
		n, ok := numberOf(u)
		if !ok || !strings.HasPrefix(n, msisdnPrefix) || len(n) != len(msisdnPrefix)+3 {
			continue
		}
		switch {
		case u.IsSIP() && impu.Scheme == "":
			impu = u
		case u.Scheme == "tel" && tel.Scheme == "":
			tel = u
		}
	}
	if impu.Scheme == "" || tel.Scheme == "" || !sameUser(impu, tel) {
		return sip.URI{}, sip.URI{}, errors.New("hss: the subscription is not one of the bridge's slots")
	}
	return impu, tel, nil
}

// call sends body as JSON (none when nil) with the token and decodes a 2xx
// answer into out (when not nil). Errors name the operation and the
// status, never a body: hss's never quote the request, and a key is in
// one.
func (h *hssProvisioner) call(ctx context.Context, method, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.cfg.URL+path, rd)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+h.cfg.Token.RevealString())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := h.cfg.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	r := io.LimitReader(res.Body, 64<<10)
	if out != nil && res.StatusCode/100 == 2 {
		if err := json.NewDecoder(r).Decode(out); err != nil {
			return 0, errors.New("the answer is not the JSON expected")
		}
	}
	_, _ = io.Copy(io.Discard, r)
	return res.StatusCode, nil
}

// impiOf is the IMPI of the endpoint called name (TS 23.003 §13.3: an
// ISIM's IMPI is any NAI in the home domain): impiPrefix and 96 bits of a
// hash of the name, at the domain.
func impiOf(name, domain string) string {
	sum := sha256.Sum256([]byte("rcs-bridge endpoint\x00" + name))
	return impiPrefix + hex.EncodeToString(sum[:12]) + "@" + domain
}

// instanceOf is the +sip.instance of an IMPI's flows, the same for every
// flow, so that a flow after a restart replaces the earlier one's binding
// rather than adding another (RFC 5626 §6): a version 8 UUID from a hash of
// the IMPI (RFC 9562 §5.8).
func instanceOf(impi string) string {
	sum := sha256.Sum256([]byte("rcs-bridge instance\x00" + impi))
	b := sum[:16]
	b[6] = b[6]&0x0f | 0x80
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
