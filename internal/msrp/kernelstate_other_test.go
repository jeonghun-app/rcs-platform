//go:build !linux || 386

package msrp

import "testing"

// checkKernelReport checks nothing here: the kernel's socket state is read
// only on Linux, and not on linux/386.
func checkKernelReport(*testing.T, string) {}

func kernelCounters() map[string]int64 { return nil }

func kernelReport(map[string]int64, []roleConn) string { return "" }
