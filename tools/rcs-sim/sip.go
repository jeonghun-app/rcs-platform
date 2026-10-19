package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/transport"
	"github.com/jeonghun-app/rcs-platform/tools/rcs-sim/internal/sipua"
)

// sipFlags are the settings of the SIP client (#135). Identities and
// addresses come from flags, credentials from the environment only.
type sipFlags struct {
	proxy, transport, serverName, domain, realm, impi, auth, instance string
}

// envIMPI is where the IMPI comes from when -sip-impi is not given. It is
// an identity, not a secret, but it is the IMSI-based one, so a deployment
// keeps it with the credentials.
const envIMPI = "RCS_SIM_SIP_IMPI"

// sipConfig builds the SIP client's configuration, with self as the IMPU.
// The errors name flags and variables, never their values: an IMPI is an
// IMSI, a host an operator's.
func sipConfig(ctx context.Context, f sipFlags, self string, lookup func(string) (string, bool)) (*sipua.Config, error) {
	cfg := &sipua.Config{}
	switch strings.ToLower(f.transport) {
	case "tcp":
		cfg.Network = transport.TCP
	case "tls":
		cfg.Network = transport.TLS
	default:
		return nil, errors.New("-sip-transport must be tcp or tls")
	}
	host, port, err := net.SplitHostPort(f.proxy)
	if err != nil {
		return nil, errors.New("-sip-proxy is not host:port")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, errors.New("-sip-proxy has no valid port")
	}
	addr, err := resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	cfg.Proxy = netip.AddrPortFrom(addr, uint16(p))
	cfg.ServerName = f.serverName
	if cfg.ServerName == "" {
		if _, err := netip.ParseAddr(host); err != nil {
			cfg.ServerName = host
		}
	}
	if cfg.IMPU, err = sip.ParseURI(self); err != nil || !cfg.IMPU.IsSIP() {
		return nil, errors.New("-self must be a SIP URI to register")
	}
	cfg.Domain = f.domain
	if cfg.Domain == "" {
		cfg.Domain = cfg.IMPU.Host
	}
	cfg.Realm = f.realm
	cfg.InstanceID = f.instance
	if cfg.InstanceID == "" {
		if cfg.InstanceID, err = newInstanceID(); err != nil {
			return nil, err
		}
	}
	impi := f.impi
	if impi == "" {
		impi = envOr(lookup, envIMPI, "")
	}
	if impi == "" {
		return nil, errors.New("SIP needs -sip-impi or " + envIMPI)
	}
	getenv := func(k string) string { v, _ := lookup(k); return v }
	switch f.auth {
	case "aka":
		cfg.Credentials, err = sipua.AKACredentialsFromEnv(impi, getenv)
	case "digest":
		cfg.Credentials, err = sipua.DigestCredentialsFromEnv(impi, getenv)
	default:
		return nil, errors.New("-sip-auth must be aka or digest")
	}
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// resolve returns host's first address. The error does not repeat host.
func resolve(ctx context.Context, host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a, nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, errors.New("-sip-proxy's host does not resolve")
	}
	return addrs[0].Unmap(), nil
}

// newInstanceID returns a random version 4 UUID URN (RFC 9562 §5.4), the
// +sip.instance of a client without an IMEI (RFC 5626 §4.1).
func newInstanceID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
