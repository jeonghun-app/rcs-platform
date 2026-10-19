package main

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
)

// TS 35.208 test set 1, not a SIM's; the IMPI's IMSI is on
// .github/allowed-test-identifiers.txt.
const (
	testK    = "465b5ce8b199b49faa5f0a2ee238a6bc"
	testOPc  = "cd63cb71954a9f4e48a5994e37a02baf"
	testIMPI = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
)

func TestSIPFlagsAndEnvironmentMakeTheClientConfig(t *testing.T) {
	lookup := env("RCS_SIM_SIP_IMPI", testIMPI, "RCS_SIM_AKA_K", testK, "RCS_SIM_AKA_OPC", testOPc)
	cfg, err := sipConfig(context.Background(), sipFlags{proxy: "127.0.0.1:5060", transport: "tcp", auth: "aka"}, defaultSelf, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network != transport.TCP || cfg.Proxy.String() != "127.0.0.1:5060" || cfg.ServerName != "" ||
		cfg.Domain != "ims.mnc001.mcc001.3gppnetwork.org" || cfg.IMPU.String() != defaultSelf {
		t.Fatalf("config = %+v", cfg)
	}
	if !regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(cfg.InstanceID) {
		t.Fatalf("instance %q is not a version 4 UUID URN", cfg.InstanceID)
	}
	// A host name is resolved, and is the name TLS verifies.
	cfg, err = sipConfig(context.Background(), sipFlags{proxy: "localhost:5061", transport: "tls", auth: "digest", impi: testIMPI, domain: "ims.example.com"}, defaultSelf,
		env("RCS_SIM_SIP_PASSWORD", "sim-test-sip-password"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network != transport.TLS || cfg.ServerName != "localhost" || !cfg.Proxy.Addr().IsLoopback() || cfg.Domain != "ims.example.com" || cfg.Realm != "" {
		t.Fatalf("config = %+v", cfg)
	}
}

func TestSIPUsageErrorsNameNoValue(t *testing.T) {
	aka := []string{"RCS_SIM_SIP_IMPI", testIMPI, "RCS_SIM_AKA_K", testK, "RCS_SIM_AKA_OPC", testOPc}
	for _, tt := range []struct {
		name string
		env  []string
		args []string
		want string
	}{
		{"no IMPI", []string{"RCS_SIM_AKA_K", testK, "RCS_SIM_AKA_OPC", testOPc}, nil, "RCS_SIM_SIP_IMPI"},
		{"no K", []string{"RCS_SIM_SIP_IMPI", testIMPI, "RCS_SIM_AKA_OPC", testOPc}, nil, "RCS_SIM_AKA_K"},
		{"K not hex", []string{"RCS_SIM_SIP_IMPI", testIMPI, "RCS_SIM_AKA_K", strings.Repeat("z", 32), "RCS_SIM_AKA_OPC", testOPc}, nil, "RCS_SIM_AKA_K"},
		{"no password", []string{"RCS_SIM_SIP_IMPI", testIMPI}, []string{"-sip-auth", "digest"}, "RCS_SIM_SIP_PASSWORD"},
		{"bad auth", aka, []string{"-sip-auth", "none"}, "-sip-auth"},
		{"bad transport", aka, []string{"-sip-transport", "udp"}, "-sip-transport"},
		{"tel self", aka, []string{"-self", "tel:+15550100001"}, "-self"},
		{"TLS to an address without a name", aka, []string{"-sip-transport", "tls"}, "server name"},
		{"no port", aka, []string{"-sip-proxy", "pcscf.operator-host.invalid"}, "-sip-proxy"},
		{"host that does not resolve", aka, []string{"-sip-proxy", "pcscf.operator-host.invalid:5060"}, "-sip-proxy"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"-sip-proxy", "127.0.0.1:5060"}, tt.args...)
			code, _, errOut := call(env(tt.env...), append(args, "all")...)
			if code != exitUsage || !strings.Contains(errOut, tt.want) {
				t.Fatalf("exit %d, stderr %q; want 2 and %q", code, errOut, tt.want)
			}
			for _, v := range []string{testK, testOPc, "001010000000001", "operator-host", strings.Repeat("z", 32)} {
				if strings.Contains(errOut, v) {
					t.Fatalf("stderr %q repeats %q", errOut, v)
				}
			}
		})
	}
}

func TestTheSIPRealmFlagReachesTheClient(t *testing.T) {
	lookup := env("RCS_SIM_SIP_IMPI", testIMPI, "RCS_SIM_AKA_K", testK, "RCS_SIM_AKA_OPC", testOPc)
	cfg, err := sipConfig(context.Background(), sipFlags{proxy: "127.0.0.1:5060", transport: "tcp", auth: "aka", realm: "realm.example.net"}, defaultSelf, lookup)
	if err != nil || cfg.Realm != "realm.example.net" {
		t.Fatalf("config %+v, %v", cfg, err)
	}
}
