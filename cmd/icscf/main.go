// Command icscf is the Interrogating-CSCF: it asks the HSS which S-CSCF
// serves a user and forwards REGISTER and terminating requests there.
// docs/icscf.md describes its configuration.
package main

import (
	"github.com/jeonghun-app/rcs-platform/internal/icscf"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

func main() {
	runtime.Main(icscf.Service())
}
