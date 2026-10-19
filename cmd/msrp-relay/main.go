// Command msrp-relay anchors MSRP between clients on the internet and rcs-as
// inside the VPC (ADR 0004): clients connect to it through the NLB, it
// connects onward to rcs-as, and pcscf allocates the bindings that tie the
// two together through its control API. All of the logic is in
// internal/msrprelay; the settings are documented in docs/msrp-relay.md.
package main

import (
	"github.com/jeonghun-app/rcs-platform/internal/msrprelay"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

func main() {
	runtime.Main(msrprelay.Service())
}
