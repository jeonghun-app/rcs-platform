//go:build !linux

package msrp

// kernelReportMarkers are lines a bind report has on this system: none,
// as the kernel's socket state is read only on Linux.
var kernelReportMarkers []string

func kernelCounters() map[string]int64 { return nil }

func kernelReport(map[string]int64, []roleConn) string { return "" }
