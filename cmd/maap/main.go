// Command maap is the half of the Chatbot Platform outside the SIP trust
// domain (ADR 0009): the chatbot registry and its operator API, and later
// the chatbot API and webhooks. All of the logic is in internal/maap; the
// settings are documented in docs/maap.md.
package main

import (
	"github.com/jeonghun-app/rcs-platform/internal/maap"
	"github.com/jeonghun-app/rcs-platform/internal/runtime"
)

func main() {
	runtime.Main(maap.Service())
}
