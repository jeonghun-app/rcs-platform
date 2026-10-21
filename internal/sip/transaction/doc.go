// Package transaction implements the SIP transaction layer of RFC 3261 §17, with
// the corrections of RFC 6026, for every SIP service in the repository.
//
// A transaction is a request and the responses to it. Its state machine absorbs
// retransmissions, retransmits over unreliable transports, and times out, so the
// layer above (the transaction user, or TU: a UA core or a proxy core) sees each
// response once and in order. The four machines are the client INVITE (§17.1.1),
// client non-INVITE (§17.1.2), server INVITE (§17.2.1) and server non-INVITE
// (§17.2.2) transactions. RFC 6026 adds the Accepted state to both INVITE
// machines: a 2xx ends neither transaction at once, so 2xx retransmissions reach
// the TU and INVITE retransmissions are still absorbed, for Timer M (client) or
// Timer L (server).
//
// A Layer owns the transactions of one transport. It matches inbound messages to
// transactions as §17.1.3 and §17.2.3 say, creates server transactions for new
// requests, and passes to the TU what belongs to no transaction: ACKs for 2xx
// responses, which are end to end (§17.1.1.3, §13.2.2.4), and responses that
// match no client transaction, which a proxy forwards statelessly (§16.7, §16.11).
//
// The layer bounds its server transactions by count and by the memory their
// requests and kept responses hold (Config.MaxServerTransactions and
// MaxServerTransactionBytes), keeping a share of both for core traffic; a
// request beyond them is answered with 503 and Retry-After without a
// transaction (RFC 3261 §21.5.4, §8.2.7), and the ACK for that 503 goes no
// further, so a flood of requests cannot grow memory without bound.
//
// A server transaction whose TU sends no final response in time is answered 500
// by the layer, and its Context is cancelled so the TU can stop: after 128*T1
// for non-INVITE, later than a proxy TU's own Timer F, and for INVITE after
// Timer C, 64*T1 for the answer to a CANCEL and a margin since the TU's last
// provisional response, since a ringing call may last minutes
// (Config.InviteFinalTimeout). A TU that starts new work on the request, such
// as a proxy's next fork group, starts the timer again (Progress).
//
// Every timer runs on an injected Clock, so tests drive T1 to T4 without
// sleeping. Retransmission timers (A, E, G) run only over unreliable transports.
//
// Dialogs, CANCEL processing beyond finding the INVITE a CANCEL refers to (§9.2),
// and the proxy's Timer C belong to the TU.
//
// Wiring: the transport's handler is the layer's Receive method, and the layer
// sends through the transport.
//
//	var layer *transaction.Layer
//	tr, err := transport.New(tcfg, func(in transport.Inbound) { layer.Receive(in) })
//	layer, err = transaction.New(tr, tu, transaction.Config{})
//	tr.Listen(...)
package transaction
