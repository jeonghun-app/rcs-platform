package runtime

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestInstanceAddrReadsTheVariableOrTheOnePrivateIPv4Address(t *testing.T) {
	ipNet := func(s string) net.Addr {
		ip := net.ParseIP(s)
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	for _, tt := range []struct {
		name  string
		env   map[string]string
		addrs []net.Addr
		err   error
		want  string
	}{
		{"set", map[string]string{"X_HOST": "10.0.2.9"}, nil, nil, "10.0.2.9"},
		{"set, IPv4-mapped", map[string]string{"X_HOST": "::ffff:10.0.2.9"}, nil, nil, "10.0.2.9"},
		{"set, not an address", map[string]string{"X_HOST": "task"}, nil, nil, "X_HOST: not an IP address"},
		{"set, with a zone", map[string]string{"X_HOST": "fe80::1%eth0"}, nil, nil, "X_HOST: not an IP address"},
		{"one private address", nil, []net.Addr{ipNet("127.0.0.1"), ipNet("172.31.4.5"), ipNet("fd00::5"), &net.IPAddr{}}, nil, "172.31.4.5"},
		{"two", nil, []net.Addr{ipNet("10.0.0.1"), ipNet("192.168.0.1")}, nil, "X_HOST: unset, and this host has 2 private IPv4 addresses rather than one"},
		{"none", nil, []net.Addr{ipNet("8.8.8.8")}, nil, "X_HOST: unset, and this host has 0 private IPv4 addresses rather than one"},
		{"unreadable", nil, nil, errors.New("no"), "X_HOST: unset, and the interface addresses could not be read"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := NewEnv("X_", func(k string) (string, bool) { v, ok := tt.env[k]; return v, ok })
			a := InstanceAddr(e, "HOST", func() ([]net.Addr, error) { return tt.addrs, tt.err })
			switch err := e.Err(); {
			case err == nil && a.String() == tt.want:
			case err != nil && strings.Contains(err.Error(), tt.want) && !a.IsValid():
			default:
				t.Fatalf("addr %v, error %v, want %q", a, err, tt.want)
			}
		})
	}
}
