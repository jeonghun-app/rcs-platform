package simtest

import "github.com/jeonghun-app/rcs-platform/internal/sip"

// SetAnswered sets c's hook for a REGISTER that changed a registration:
// it runs on the request's reading goroutine once the REGISTER has been
// answered, where #272's reading of the subscribers used to be.
func SetAnswered(c *IMSCore, f func(*sip.Request)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answered = f
}
