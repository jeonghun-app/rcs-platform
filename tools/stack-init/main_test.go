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

// Made-up test keys, one pair per subscriber, not a SIM's.
const (
	clientK, clientOPc = "00112233445566778899aabbccddeeff", "ffeeddccbbaa99887766554433221100"
	peerK, peerOPc     = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
)

// keyEnv is the four key variables, with the made-up keys.
var keyEnv = []string{"RCS_SIM_AKA_K", clientK, "RCS_SIM_AKA_OPC", clientOPc, "RCS_SIM_PEER_AKA_K", peerK, "RCS_SIM_PEER_AKA_OPC", peerOPc}

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
		{"seed with a bad URL", append([]string{"HSS_ADMIN_TOKEN", "x", "ACS_ADMIN_TOKEN", "y", "RCS_IMS_DOMAIN", domain,
			"FT_UPLOAD_URI", "u", "FT_DOWNLOAD_URI", "d", "STACK_ACS_URL", "acs:8080"}, keyEnv...), []string{"seed"}, "http(s) URLs"},
		{"seed without keys", []string{"HSS_ADMIN_TOKEN", "x", "ACS_ADMIN_TOKEN", "y", "RCS_IMS_DOMAIN", domain,
			"FT_UPLOAD_URI", "u", "FT_DOWNLOAD_URI", "d"}, []string{"seed"}, "RCS_SIM_AKA_K is required"},
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

// fakes is an hss and an acs that record what they were sent: the
// subscriptions in order, and the AKA keys and acs subscribers by path.
type fakes struct {
	mu        sync.Mutex
	hssStatus []int // answered in turn to POST /v1/subscriptions; the last repeats
	akaStatus int
	acsStatus int
	hssCalls  int
	hssBodies []map[string]any
	akaBodies map[string]map[string]any
	acsBodies map[string]map[string]any
	hss, acs  *httptest.Server
}

func newFakes(t *testing.T, hssStatus []int, acsStatus int) *fakes {
	f := &fakes{hssStatus: hssStatus, akaStatus: http.StatusNoContent, acsStatus: acsStatus,
		akaBodies: map[string]map[string]any{}, acsBodies: map[string]map[string]any{}}
	f.hss = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		switch {
		case r.Header.Get("Authorization") != "Bearer "+hssToken:
			w.WriteHeader(http.StatusUnauthorized)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/subscriptions":
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.hssBodies = append(f.hssBodies, body)
			st := f.hssStatus[min(f.hssCalls, len(f.hssStatus)-1)]
			f.hssCalls++
			w.WriteHeader(st)
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/aka"):
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.akaBodies[r.URL.Path] = body
			w.WriteHeader(f.akaStatus)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	f.acs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+acsToken || r.Method != http.MethodPut {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.acsBodies[r.URL.Path] = body
		w.WriteHeader(f.acsStatus)
	}))
	t.Cleanup(f.hss.Close)
	t.Cleanup(f.acs.Close)
	return f
}

func (f *fakes) config(t *testing.T) seedConfig {
	t.Helper()
	c, err := readSeedConfig(environment{lookup: env(append([]string{
		"STACK_HSS_API", f.hss.URL, "STACK_ACS_URL", f.acs.URL,
		"HSS_ADMIN_TOKEN", hssToken, "ACS_ADMIN_TOKEN", acsToken, "RCS_IMS_DOMAIN", domain,
		"FT_UPLOAD_URI", "http://ft-server:8081/ft", "FT_DOWNLOAD_URI", "http://ft-server:8081/dl"}, keyEnv...)...)})
	if err != nil {
		t.Fatal(err)
	}
	c.retryFor, c.poll = 2*time.Second, time.Millisecond
	return c
}

func TestSeedProvisionsBothSubscribersInBothServices(t *testing.T) {
	f := newFakes(t, []int{http.StatusCreated}, http.StatusOK)
	var out bytes.Buffer
	if err := seed(context.Background(), f.config(t), &out); err != nil {
		t.Fatal(err)
	}
	for i, want := range []struct{ imsi, msisdn, k, opc string }{
		{"001010000000001", "+15550100001", clientK, clientOPc},
		{"001010000000002", "+15550100002", peerK, peerOPc},
	} {
		impi := want.imsi + "@" + domain
		body := f.hssBodies[i]
		ids, _ := body["public_identities"].([]any)
		first, _ := ids[0].(map[string]any)
		if body["impi"] != impi || body["imsi"] != want.imsi || first["impu"] != "sip:"+want.msisdn+"@"+domain || body["acs_managed"] != true {
			t.Fatalf("hss got %v", body)
		}
		// Each subscriber its own keys (#236).
		if aka := f.akaBodies["/v1/subscriptions/"+impi+"/aka"]; aka["k"] != want.k || aka["opc"] != want.opc {
			t.Fatalf("hss AKA for %s got %v", want.imsi, aka)
		}
		acs := f.acsBodies["/admin/subscribers/"+want.imsi]
		o, _ := acs["overrides"].(map[string]any)
		if acs["msisdn"] != want.msisdn ||
			o[keyFTUpload] != "http://ft-server:8081/ft" || o[keyFTDownload] != "http://ft-server:8081/dl" ||
			o[keyPCSCF] != "pcscf" || o[keyPCSCFDM] != "pcscf" || o[keyConfFactory] != "sip:conf-factory@"+domain {
			t.Fatalf("acs got %v for %s", acs, want.imsi)
		}
	}
	for _, secret := range []string{hssToken, acsToken, clientK, clientOPc, peerK, peerOPc, "001010000000001", "+15550100002"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("the output carries %q: %s", secret, out.String())
		}
	}
}

func TestSeedNeedsEachSubscribersOwnKeys(t *testing.T) {
	// Keys from the environment, 32 hex digits, and never one pair for
	// both subscribers (#236). The error names variables, never values.
	base := []string{"HSS_ADMIN_TOKEN", hssToken, "ACS_ADMIN_TOKEN", acsToken, "RCS_IMS_DOMAIN", domain,
		"FT_UPLOAD_URI", "u", "FT_DOWNLOAD_URI", "d"}
	for name, tc := range map[string]struct {
		keys []string
		want string
	}{
		"peer's K missing": {[]string{"RCS_SIM_AKA_K", clientK, "RCS_SIM_AKA_OPC", clientOPc, "RCS_SIM_PEER_AKA_OPC", peerOPc}, "RCS_SIM_PEER_AKA_K is required"},
		"not hex":          {[]string{"RCS_SIM_AKA_K", "zz" + clientK[2:], "RCS_SIM_AKA_OPC", clientOPc, "RCS_SIM_PEER_AKA_K", peerK, "RCS_SIM_PEER_AKA_OPC", peerOPc}, "RCS_SIM_AKA_K is not 32 hexadecimal digits"},
		"shared K":         {[]string{"RCS_SIM_AKA_K", clientK, "RCS_SIM_AKA_OPC", clientOPc, "RCS_SIM_PEER_AKA_K", strings.ToUpper(clientK), "RCS_SIM_PEER_AKA_OPC", peerOPc}, "the two test subscribers need their own K and OPc"},
		"shared OPc":       {[]string{"RCS_SIM_AKA_K", clientK, "RCS_SIM_AKA_OPC", clientOPc, "RCS_SIM_PEER_AKA_K", peerK, "RCS_SIM_PEER_AKA_OPC", clientOPc}, "the two test subscribers need their own K and OPc"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := readSeedConfig(environment{lookup: env(append(append([]string{}, base...), tc.keys...)...)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("readSeedConfig = %v, want %q", err, tc.want)
			}
			for _, v := range []string{clientK, clientOPc, peerK, peerOPc} {
				if strings.Contains(strings.ToLower(err.Error()), v) {
					t.Fatalf("the error carries a key: %v", err)
				}
			}
		})
	}
}

func TestSeedNamesTheSubscriberWhoseKeysAreRefused(t *testing.T) {
	f := newFakes(t, []int{http.StatusCreated}, http.StatusOK)
	f.akaStatus = http.StatusBadRequest
	err := seed(context.Background(), f.config(t), &bytes.Buffer{})
	if err == nil || err.Error() != "client: hss: set AKA keys: HTTP 400" {
		t.Fatalf("seed = %v", err)
	}
}

func TestSeedIsIdempotentAndWaitsForABusyService(t *testing.T) {
	// The HSS store is not ready yet (503), then the subscription exists.
	f := newFakes(t, []int{http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusConflict}, http.StatusOK)
	var out bytes.Buffer
	if err := seed(context.Background(), f.config(t), &out); err != nil {
		t.Fatal(err)
	}
	if f.hssCalls != 4 || !strings.Contains(out.String(), "hss: client test subscription exists") || !strings.Contains(out.String(), "hss: peer test subscription exists") {
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
	code, _, errOut := runCmd(t, env(append([]string{"STACK_HSS_API", f.hss.URL, "STACK_ACS_URL", f.acs.URL,
		"HSS_ADMIN_TOKEN", hssToken, "ACS_ADMIN_TOKEN", acsToken, "RCS_IMS_DOMAIN", domain,
		"FT_UPLOAD_URI", "u", "FT_DOWNLOAD_URI", "d"}, keyEnv...)...), "seed")
	if code != exitFailed || !strings.Contains(errOut, "HTTP 403") {
		t.Fatalf("exit %d, stderr %q", code, errOut)
	}
}
