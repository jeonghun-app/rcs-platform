//go:build linux

package msrp

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// kernelReportMarkers are lines a bind report has on this system.
var kernelReportMarkers = []string{"kernel:", " outq ", " backoff ", "counters since the rig began:"}

// kernelCounters reads the TCP counters of /proc/net/netstat and
// /proc/net/snmp, by "Table.Name". They count the whole network namespace,
// not one test, so a report reads them as what happened around the rig.
func kernelCounters() map[string]int64 {
	m := map[string]int64{}
	for _, file := range []string{"/proc/net/netstat", "/proc/net/snmp"} {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		// Each table is a line of names followed by a line of values.
		sc := bufio.NewScanner(f)
		var names []string
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) == 0 {
				continue
			}
			if names == nil || fields[0] != names[0] {
				names = fields
				continue
			}
			table := strings.TrimSuffix(names[0], ":")
			if table == "TcpExt" || table == "Tcp" {
				for i := 1; i < len(fields) && i < len(names); i++ {
					if v, err := strconv.ParseInt(fields[i], 10, 64); err == nil {
						m[table+"."+names[i]] = v
					}
				}
			}
			names = nil
		}
		_ = f.Close()
	}
	return m
}

// socketState is the kernel's view of a TCP connection: the octets still
// in its receive and send queues and the TCP_INFO a stalled connection is
// read by (#140: both ends idle with nothing queued in this package, yet
// the bytes one side wrote never reached the other).
func socketState(nc net.Conn) string {
	tc, ok := nc.(*net.TCPConn)
	if !ok {
		return "not a TCP connection"
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%v->%v", tc.LocalAddr(), tc.RemoteAddr())
	cerr := raw.Control(func(fd uintptr) {
		var inq, outq int32
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCINQ, uintptr(unsafe.Pointer(&inq))); e != 0 {
			fmt.Fprintf(&b, " inq: %v", e)
		} else {
			fmt.Fprintf(&b, " inq %d", inq)
		}
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCOUTQ, uintptr(unsafe.Pointer(&outq))); e != 0 {
			fmt.Fprintf(&b, " outq: %v", e)
		} else {
			fmt.Fprintf(&b, " outq %d", outq)
		}
		rcvbuf, _ := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
		sndbuf, _ := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		fmt.Fprintf(&b, " rcvbuf %d sndbuf %d", rcvbuf, sndbuf)
		var ti syscall.TCPInfo
		size := uint32(unsafe.Sizeof(ti))
		if _, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.IPPROTO_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&ti)), uintptr(unsafe.Pointer(&size)), 0); e != 0 {
			fmt.Fprintf(&b, " TCP_INFO: %v", e)
			return
		}
		fmt.Fprintf(&b, " | state %d ca_state %d retransmits %d probes %d backoff %d rto %dus"+
			" unacked %d lost %d retrans %d total_retrans %d"+
			" last_data_sent %dms last_data_recv %dms last_ack_recv %dms"+
			" rtt %dus cwnd %d rcv_ssthresh %d rcv_space %d snd_mss %d rcv_mss %d",
			ti.State, ti.Ca_state, ti.Retransmits, ti.Probes, ti.Backoff, ti.Rto,
			ti.Unacked, ti.Lost, ti.Retrans, ti.Total_retrans,
			ti.Last_data_sent, ti.Last_data_recv, ti.Last_ack_recv,
			ti.Rtt, ti.Snd_cwnd, ti.Rcv_ssthresh, ti.Rcv_space, ti.Snd_mss, ti.Rcv_mss)
	})
	if cerr != nil {
		fmt.Fprintf(&b, " %v", cerr)
	}
	return b.String()
}

// kernelReport is the kernel part of a bind report: each connection's
// socket state and the TCP counters that changed since base was read.
func kernelReport(base map[string]int64, conns []roleConn) string {
	var b strings.Builder
	b.WriteString("kernel:\n")
	for _, rc := range conns {
		fmt.Fprintf(&b, "  %s %p: %s\n", rc.role, rc.c, socketState(rc.c.nc))
	}
	now := kernelCounters()
	var changed []string
	for k, v := range now {
		if d := v - base[k]; d != 0 {
			changed = append(changed, fmt.Sprintf("%s%+d", k, d))
		}
	}
	slices.Sort(changed)
	b.WriteString("  counters since the rig began: " + strings.Join(changed, " ") + "\n")
	if s, err := os.ReadFile("/proc/net/sockstat"); err == nil {
		b.WriteString("  sockstat: " + strings.Join(strings.Split(strings.TrimSpace(string(s)), "\n"), " | ") + "\n")
	}
	if s, err := os.ReadFile("/proc/sys/net/ipv4/tcp_mem"); err == nil {
		b.WriteString("  tcp_mem (pages): " + strings.Join(strings.Fields(string(s)), " ") + "\n")
	}
	return b.String()
}
