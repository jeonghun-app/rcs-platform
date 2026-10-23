// Package nosip does not depend on sip, and can still be handed a message
// in an interface: printguard must refuse the same shapes here.
package nosip

import "fmt"

type stringerField struct{ s fmt.Stringer }
type anyField struct{ v any }
type errorField struct{ err error }

func refused() {
	_ = fmt.Sprint(stringerField{}) // want "interface that may hold a sip.Request in an unexported field (s)"
	_ = fmt.Sprint(anyField{})      // want "interface that may hold a sip.Request in an unexported field (v)"
}

func allowed() {
	// No message type is an error.
	_ = fmt.Sprint(errorField{})
}
