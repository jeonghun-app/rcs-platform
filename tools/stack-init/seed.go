package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// seedConfig is the test subscriber and where to provision it.
type seedConfig struct {
	hssAPI, hssToken string
	acsURL, acsToken string
	imsi, msisdn     string
	imsDomain        string
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

func readSeedConfig(e environment) (seedConfig, error) {
	c := seedConfig{
		hssAPI:    e.get("STACK_HSS_API", "http://hss:8081"),
		acsURL:    e.get("STACK_ACS_URL", "http://acs:8080"),
		imsi:      e.get("STACK_IMSI", "001010000000001"),
		msisdn:    e.get("STACK_MSISDN", "+15550100001"),
		retryFor:  time.Minute,
		poll:      time.Second,
		overrides: map[string]string{},
	}
	var errs []error
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

// impi and impu are the test subscriber's identities, as acs derives them
// from the IMSI and MSISDN.
func (c seedConfig) impi() string { return c.imsi + "@" + c.imsDomain }
func (c seedConfig) impu() string { return "sip:" + c.msisdn + "@" + c.imsDomain }

// seed provisions the test subscriber: the subscription in hss, managed by
// acs as ADR 0006 has it, and the subscriber in acs with the overrides that
// point its configuration at the local stack. Credentials are not issued
// here; whoever needs one (make e2e-compose) issues a fresh one.
func seed(ctx context.Context, c seedConfig, out io.Writer) error {
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	sub := map[string]any{
		"impi":              c.impi(),
		"imsi":              c.imsi,
		"public_identities": []map[string]any{{"impu": c.impu()}},
		"acs_managed":       true,
	}
	status, err := call(ctx, client, c, http.MethodPost, c.hssAPI+"/v1/subscriptions", c.hssToken, sub)
	switch {
	case err != nil:
		return fmt.Errorf("hss: create subscription: %w", err)
	case status == http.StatusCreated:
		fmt.Fprintln(out, "hss: test subscription created")
	case status == http.StatusConflict:
		fmt.Fprintln(out, "hss: test subscription exists")
	default:
		return fmt.Errorf("hss: create subscription: HTTP %d", status)
	}
	subscriber := map[string]any{
		"msisdn":      c.msisdn,
		"entitled":    true,
		"rcs_profile": "UP_2.4",
		"overrides":   c.overrides,
	}
	status, err = call(ctx, client, c, http.MethodPut, c.acsURL+"/admin/subscribers/"+url.PathEscape(c.imsi), c.acsToken, subscriber)
	switch {
	case err != nil:
		return fmt.Errorf("acs: put subscriber: %w", err)
	case status != http.StatusOK:
		return fmt.Errorf("acs: put subscriber: HTTP %d", status)
	}
	fmt.Fprintln(out, "acs: test subscriber provisioned with the local stack's addresses")
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
