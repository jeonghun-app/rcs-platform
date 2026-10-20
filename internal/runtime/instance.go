package runtime

import (
	"net"
	"net/netip"
	"strconv"
)

// InstanceAddr reads the variable name as this task's own address, or, when
// it is unset, finds the task's one private IPv4 address among addrs (pass
// net.InterfaceAddrs): on Fargate a task definition cannot know the address,
// and a service that names its instance to its peers, such as pcscf in Path
// or msrp-relay in MSRP paths, must use it (ADR 0005). A problem is recorded
// on e and the zero Addr returned.
func InstanceAddr(e *Env, name string, addrs func() ([]net.Addr, error)) netip.Addr {
	if v := e.String(name, ""); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" {
			e.Invalid(name, "not an IP address")
			return netip.Addr{}
		}
		return a.Unmap()
	}
	list, err := addrs()
	if err != nil {
		e.Invalid(name, "unset, and the interface addresses could not be read")
		return netip.Addr{}
	}
	var found []netip.Addr
	for _, a := range list {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		if ip = ip.Unmap(); ip.Is4() && ip.IsPrivate() {
			found = append(found, ip)
		}
	}
	if len(found) != 1 {
		e.Invalid(name, "unset, and this host has "+strconv.Itoa(len(found))+" private IPv4 addresses rather than one")
		return netip.Addr{}
	}
	return found[0]
}
