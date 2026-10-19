// Command pcscf is the Proxy-CSCF, the only SIP entry point for clients (TS
// 24.229 §5.2): it holds their connections behind the NLB, asserts their
// identity and keeps their flows (RFC 5626). All of the logic is in
// internal/pcscf; the settings are documented in docs/pcscf.md.
package main

import (
	"github.com/jeonghun-app/rcs-platform/internal/pcscf"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

func main() {
	runtime.Main(pcscf.Service())
}
