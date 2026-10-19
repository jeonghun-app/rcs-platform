// Command hss is the platform's Home Subscriber Server: Diameter Cx for
// icscf and scscf and the provisioning API for operators, acs and ft-server.
// docs/hss.md describes its configuration.
package main

import (
	"github.com/jeonghun-app/rcs-platform/internal/hss"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

func main() {
	runtime.Main(hss.Service())
}
