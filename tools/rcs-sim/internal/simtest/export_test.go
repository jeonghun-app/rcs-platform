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

// SetOrderHooks sets c's hooks around a 200 and the NOTIFYs it lets go:
// answering runs just before the 200 of a REGISTER or a SUBSCRIBE is
// written; waiting runs on the notifier's goroutine as each NOTIFY begins
// to wait for the gate its request's 200 opens.
func SetOrderHooks(c *IMSCore, answering func(*sip.Request), waiting func(gate <-chan struct{})) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.answering, c.waiting = answering, waiting
}
