// Command scscf is the Serving-CSCF: the registrar, the reg event notifier
// and the service router of the IMS core. docs/scscf.md describes its
// configuration.
package main

import (
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
	"github.com/jeonghun-app/rcs-platform/internal/scscf"
)

func main() {
	runtime.Main(scscf.Service())
}
