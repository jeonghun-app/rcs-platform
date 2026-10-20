package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// seedConfig is the test subscribers and where to provision them.
type seedConfig struct {
	hssAPI, hssToken string
	acsURL, acsToken string
	// subscribers are rcs-sim's client and its peer (#135, #236), each
	// with its own AKA keys.
	subscribers []subscriber
	imsDomain   string
	// overrides are acs per-subscriber parameter overrides: acs 1.4.0 has
	// no deployment-wide setting for these values (docs/local-stack.md).
	overrides map[string]string
	// retryFor bounds how long a busy or unreachable service is asked
	// again; poll is the pause between attempts.
	retryFor, poll time.Duration
}

// The acs catalogue keys (path/parm) of the values that must point at the
// local stack, in OMA-CP and, for the P-CSCF, in OMA-DM too.
const (
	keyPCSCF       = "APPLICATION:ap2001/LBO_P-CSCF_Address/Address"
	keyPCSCFDM     = "./3GPP_IMS/1/LBO_P-CSCF_Address/1/Address"
	keyFTUpload    = "APPLICATION:ap2002/MESSAGING/FT/ftHTTPCSURI"
	keyFTDownload  = "APPLICATION:ap2002/MESSAGING/FT/ftHTTPDLURI"
	keyConfFactory = "APPLICATION:ap2002/MESSAGING/CHAT/ConfFctyURI"
)

// subscriber is one test subscriber: its identities, and the K and OPc,
// 32 hex digits each, that hss gets for it. name is what the output calls
// it, never an identity.
type subscriber struct {
	name, imsi, msisdn string
	k, opc             string
}

// The variables the subscribers' keys come from: the ones rcs-sim reads,
// so deploy/compose.env gives both the same values (scripts/compose-env.sh
// generates them).
var keyVars = [2][2]string{
	{"RCS_SIM_AKA_K", "RCS_SIM_AKA_OPC"},
	{"RCS_SIM_PEER_AKA_K", "RCS_SIM_PEER_AKA_OPC"},
}

func readSeedConfig(e environment) (seedConfig, error) {
	c := seedConfig{
		hssAPI: e.get("STACK_HSS_API", "http://hss:8081"),
		acsURL: e.get("STACK_ACS_URL", "http://acs:8080"),
		subscribers: []subscriber{
			{name: "client", imsi: e.get("STACK_IMSI", "001010000000001"), msisdn: e.get("STACK_MSISDN", "+15550100001")},
			{name: "peer", imsi: e.get("STACK_PEER_IMSI", "001010000000002"), msisdn: e.get("STACK_PEER_MSISDN", "+15550100002")},
		},
		retryFor:  time.Minute,
		poll:      time.Second,
		overrides: map[string]string{},
	}
	var errs []error
	for i := range c.subscribers {
		for j, dst := range []*string{&c.subscribers[i].k, &c.subscribers[i].opc} {
			v, err := e.required(keyVars[i][j])
			if err == nil && !isKey(v) {
				err = &configError{msg: keyVars[i][j] + " is not 32 hexadecimal digits"}
			}
			errs = append(errs, err)
			*dst = strings.ToLower(v)
		}
	}
	a, b := c.subscribers[0], c.subscribers[1]
	switch {
	case a.imsi == b.imsi || a.msisdn == b.msisdn:
		errs = append(errs, &configError{msg: "the two test subscribers need their own IMSI and MSISDN"})
	case a.k != "" && (a.k == b.k || a.opc == b.opc):
		// One secret shared by two subscribers would hide a client that
		// answers with the other's (#236).
		errs = append(errs, &configError{msg: "the two test subscribers need their own K and OPc"})
	}
	for _, r := range []struct {
		name string
		dst  *string
	}{
		{"HSS_ADMIN_TOKEN", &c.hssToken}, {"ACS_ADMIN_TOKEN", &c.acsToken}, {"RCS_IMS_DOMAIN", &c.imsDomain},
	} {
		v, err := e.required(r.name)
		errs = append(errs, err)
		*r.dst = v
	}
	pcscf := e.get("STACK_PCSCF_ADDRESS", "pcscf")
	upload, err1 := e.required("FT_UPLOAD_URI")
	download, err2 := e.required("FT_DOWNLOAD_URI")
	errs = append(errs, err1, err2)
	if err := errors.Join(errs...); err != nil {
		return c, &configError{msg: err.Error()}
	}
	for _, u := range []string{c.hssAPI, c.acsURL} {
		if p, err := url.Parse(u); err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
			return c, &configError{msg: "STACK_HSS_API and STACK_ACS_URL must be http(s) URLs"}
		}
	}
	c.overrides[keyPCSCF] = pcscf
	c.overrides[keyPCSCFDM] = pcscf
	c.overrides[keyFTUpload] = upload
	c.overrides[keyFTDownload] = download
	c.overrides[keyConfFactory] = e.get("STACK_CONF_FACTORY_URI", "sip:conf-factory@"+c.imsDomain)
	return c, nil
}

// isKey reports whether v is 32 hexadecimal digits, a 128-bit K or OPc.
func isKey(v string) bool {
	b, err := hex.DecodeString(v)
	return err == nil && len(b) == 16
}

// impi and impu are a test subscriber's identities, as acs derives them
// from the IMSI and MSISDN.
func (c seedConfig) impi(s subscriber) string { return s.imsi + "@" + c.imsDomain }
func (c seedConfig) impu(s subscriber) string { return "sip:" + s.msisdn + "@" + c.imsDomain }

// seed provisions each test subscriber: the subscription in hss, managed
// by acs as ADR 0006 has it, with its own AKA keys, and the subscriber in
// acs with the overrides that point its configuration at the local stack.
// Passwords are not issued here; whoever needs one (make e2e-compose)
// issues a fresh one. The output names the subscribers "client" and
// "peer", never by an identity, and never shows a key.
func seed(ctx context.Context, c seedConfig, out io.Writer) error {
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	for _, s := range c.subscribers {
		if err := seedOne(ctx, client, c, s, out); err != nil {
			return fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return nil
}

func seedOne(ctx context.Context, client *http.Client, c seedConfig, s subscriber, out io.Writer) error {
	sub := map[string]any{
		"impi":              c.impi(s),
		"imsi":              s.imsi,
		"public_identities": []map[string]any{{"impu": c.impu(s)}},
		"acs_managed":       true,
	}
	status, err := call(ctx, client, c, http.MethodPost, c.hssAPI+"/v1/subscriptions", c.hssToken, sub)
	switch {
	case err != nil:
		return fmt.Errorf("hss: create subscription: %w", err)
	case status == http.StatusCreated:
		fmt.Fprintf(out, "hss: %s test subscription created\n", s.name)
	case status == http.StatusConflict:
		fmt.Fprintf(out, "hss: %s test subscription exists\n", s.name)
	default:
		return fmt.Errorf("hss: create subscription: HTTP %d", status)
	}
	// Set every time: a run with new keys in deploy/compose.env re-keys
	// the subscription, and hss keeps its SQN (PUT /aka).
	aka := map[string]any{"k": s.k, "opc": s.opc}
	status, err = call(ctx, client, c, http.MethodPut, c.hssAPI+"/v1/subscriptions/"+url.PathEscape(c.impi(s))+"/aka", c.hssToken, aka)
	switch {
	case err != nil:
		return fmt.Errorf("hss: set AKA keys: %w", err)
	case status != http.StatusNoContent:
		return fmt.Errorf("hss: set AKA keys: HTTP %d", status)
	}
	fmt.Fprintf(out, "hss: %s AKA keys set\n", s.name)
	subscriber := map[string]any{
		"msisdn":      s.msisdn,
		"entitled":    true,
		"rcs_profile": "UP_2.4",
		"overrides":   c.overrides,
	}
	status, err = call(ctx, client, c, http.MethodPut, c.acsURL+"/admin/subscribers/"+url.PathEscape(s.imsi), c.acsToken, subscriber)
	switch {
	case err != nil:
		return fmt.Errorf("acs: put subscriber: %w", err)
	case status != http.StatusOK:
		return fmt.Errorf("acs: put subscriber: HTTP %d", status)
	}
	fmt.Fprintf(out, "acs: %s test subscriber provisioned with the local stack's addresses\n", s.name)
	return nil
}

// call sends body as JSON with token and returns the status. A 503 or a
// failed connection is asked again until c.retryFor has passed: compose
// starts this once the services' processes run, and their stores may not
// be ready yet.
func call(ctx context.Context, client *http.Client, c seedConfig, method, target, token string, body any) (int, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}
	deadline := time.Now().Add(c.retryFor)
	for {
		req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payload))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		status := 0
		if err == nil {
			status = resp.StatusCode
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
			if status != http.StatusServiceUnavailable {
				return status, nil
			}
		}
		if time.Now().After(deadline) {
			if err != nil {
				return 0, errors.New("not reachable: " + reason(err))
			}
			return status, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(c.poll):
		}
	}
}

// reason keeps a transport failure's cause and drops the URL, which names
// the method and target but nothing the caller does not know.
func reason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return strings.TrimSpace(err.Error())
}
