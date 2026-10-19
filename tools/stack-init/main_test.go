package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	hssToken = "hss-admin-token-for-tests-only-0123456789abcdef"
	acsToken = "acs-admin-token-for-tests-only-0123456789abcdef"
	domain   = "ims.mnc001.mcc001.3gppnetwork.org"
)

func env(kv ...string) func(string) (string, bool) {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func runCmd(t *testing.T, lookup func(string) (string, bool), args ...string) (int, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, lookup, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestUsageAndMissingSettingsExitWithTwo(t *testing.T) {
	for _, tt := range []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"no command", nil, nil, "usage"},
		{"two commands", nil, []string{"tables", "seed"}, "usage"},
		{"unknown command", nil, []string{"nope"}, "usage"},
		{"tables without endpoints", nil, []string{"tables"}, "STACK_DYNAMODB_ENDPOINT is required"},
		{"tables without a bucket", []string{"STACK_DYNAMODB_ENDPOINT", "http://ddb:8000", "STACK_S3_ENDPOINT", "http://s3:9090"}, []string{"tables"}, "FT_S3_BUCKET is required"},
		{"seed without tokens", []string{"RCS_IMS_DOMAIN", domain}, []string{"seed"}, "HSS_ADMIN_TOKEN is required"},
		{"seed with a bad URL", []string{"HSS_ADMIN_TOKEN", "x", "ACS_ADMIN_TOKEN", "y", "RCS_IMS_DOMAIN", domain,
			"FT_UPLOAD_URI", "u", "FT_DOWNLOAD_URI", "d", "STACK_ACS_URL", "acs:8080"}, []string{"seed"}, "http(s) URLs"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code, _, errOut := runCmd(t, env(tt.env...), tt.args...)
			if code != exitUsage || !strings.Contains(errOut, tt.want) {
				t.Fatalf("exit %d, stderr %q; want 2 and %q", code, errOut, tt.want)
			}
		})
	}
}

func TestTablesDefaultToTheServicesOwnNames(t *testing.T) {
	c, err := readTablesConfig(environment{lookup: env("STACK_DYNAMODB_ENDPOINT", "http://ddb:8000", "STACK_S3_ENDPOINT", "http://s3:9090",
		"FT_S3_BUCKET", "ft-content", "FT_DYNAMODB_TABLE", "ft-files")})
	if err != nil {
		t.Fatal(err)
	}
	if c.hss.SubscribersTable != "subscribers" || c.hss.ProfilesTable != "service-profiles" || c.relayTable != "msrp-bindings" || c.ftTable != "ft-files" {
		t.Fatalf("config %+v", c)
	}
}

// fakes is an hss and an acs that record what they were sent.
type fakes struct {
	mu        sync.Mutex
	hssStatus []int // answered in turn; the last repeats
	acsStatus int
	hssCalls  int
	hssBody   map[string]any
	acsBody   map[string]any
	acsPath   string
	hss, acs  *httptest.Server
}

func newFakes(t *testing.T, hssStatus []int, acsStatus int) *fakes {
	f := &fakes{hssStatus: hssStatus, acsStatus: acsStatus}
	f.hss = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+hssToken || r.Method != http.MethodPost || r.URL.Path != "/v1/subscriptions" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&f.hssBody)
		st := f.hssStatus[min(f.hssCalls, len(f.hssStatus)-1)]
		f.hssCalls++
		w.WriteHeader(st)
	}))
	f.acs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+acsToken || r.Method != http.MethodPut {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.acsPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&f.acsBody)
		w.WriteHeader(f.acsStatus)
	}))
	t.Cleanup(f.hss.Close)
	t.Cleanup(f.acs.Close)
	return f
}

func (f *fakes) config(t *testing.T) seedConfig {
	t.Helper()
	c, err := readSeedConfig(environment{lookup: env(
		"STACK_HSS_API", f.hss.URL, "STACK_ACS_URL", f.acs.URL,
		"HSS_ADMIN_TOKEN", hssToken, "ACS_ADMIN_TOKEN", acsToken, "RCS_IMS_DOMAIN", domain,
		"FT_UPLOAD_URI", "http://ft-server:8081/ft", "FT_DOWNLOAD_URI", "http://ft-server:8081/dl")})
	if err != nil {
		t.Fatal(err)
	}
	c.retryFor, c.poll = 2*time.Second, time.Millisecond
	return c
}

func TestSeedProvisionsTheSubscriberInBothServices(t *testing.T) {
	f := newFakes(t, []int{http.StatusCreated}, http.StatusOK)
	var out bytes.Buffer
	if err := seed(context.Background(), f.config(t), &out); err != nil {
		t.Fatal(err)
	}
	ids, _ := f.hssBody["public_identities"].([]any)
	first, _ := ids[0].(map[string]any)
	if f.hssBody["impi"] != "001010000000001@"+domain || f.hssBody["imsi"] != "001010000000001" ||
		first["impu"] != "sip:+15550100001@"+domain || f.hssBody["acs_managed"] != true {
		t.Fatalf("hss got %v", f.hssBody)
	}
	o, _ := f.acsBody["overrides"].(map[string]any)
	if f.acsPath != "/admin/subscribers/001010000000001" || f.acsBody["msisdn"] != "+15550100001" ||
		o[keyFTUpload] != "http://ft-server:8081/ft" || o[keyFTDownload] != "http://ft-server:8081/dl" ||
		o[keyPCSCF] != "pcscf" || o[keyPCSCFDM] != "pcscf" || o[keyConfFactory] != "sip:conf-factory@"+domain {
		t.Fatalf("acs got %s %v", f.acsPath, f.acsBody)
	}
	if strings.Contains(out.String(), hssToken) || strings.Contains(out.String(), acsToken) {
		t.Fatal("the output carries a token")
	}
}

func TestSeedIsIdempotentAndWaitsForABusyService(t *testing.T) {
	// The HSS store is not ready yet (503), then the subscription exists.
	f := newFakes(t, []int{http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusConflict}, http.StatusOK)
	var out bytes.Buffer
	if err := seed(context.Background(), f.config(t), &out); err != nil {
		t.Fatal(err)
	}
	if f.hssCalls != 3 || !strings.Contains(out.String(), "exists") {
		t.Fatalf("%d calls, output %q", f.hssCalls, out.String())
	}
}

func TestSeedFailsOnARefusalWithoutNamingTheToken(t *testing.T) {
	f := newFakes(t, []int{http.StatusCreated}, http.StatusBadRequest)
	err := seed(context.Background(), f.config(t), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || strings.Contains(err.Error(), acsToken) {
		t.Fatalf("seed = %v", err)
	}
	c := f.config(t)
	c.hssAPI = "http://127.0.0.1:1"
	c.retryFor = 10 * time.Millisecond
	if err := seed(context.Background(), c, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("seed = %v", err)
	}
}

func TestSeedRunsFromTheCommandLine(t *testing.T) {
	f := newFakes(t, []int{http.StatusCreated}, http.StatusForbidden)
	code, _, errOut := runCmd(t, env("STACK_HSS_API", f.hss.URL, "STACK_ACS_URL", f.acs.URL,
		"HSS_ADMIN_TOKEN", hssToken, "ACS_ADMIN_TOKEN", acsToken, "RCS_IMS_DOMAIN", domain,
		"FT_UPLOAD_URI", "u", "FT_DOWNLOAD_URI", "d"), "seed")
	if code != exitFailed || !strings.Contains(errOut, "HTTP 403") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}
