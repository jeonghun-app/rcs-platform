// Command rcs-as is the RCS messaging application server: the
// participating function of 1-to-1 chat and standalone messaging, which
// stores messages for later delivery and sends their notifications. All of
// the logic is in internal/rcsas; the settings are documented in
// docs/rcs-as.md.
package main

import (
	"github.com/jeonghun-app/rcs-platform/internal/rcsas"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

func main() {
	runtime.Main(rcsas.Service())
}
