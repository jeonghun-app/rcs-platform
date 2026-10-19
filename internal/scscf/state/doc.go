// Package state is the state the S-CSCF instances share, so that any instance
// can serve any user (ADR 0005): the registrations (bindings), the user
// profiles, the authentication challenges between the two REGISTERs of an
// authentication, and the reg event subscriptions with their NOTIFY counters.
// It has no SIP or Diameter in it; scscf (#14) fills it from the messages.
//
// Every store method is safe on several instances at once:
//
//   - Saves are conditional on the version read (optimistic concurrency), so
//     two instances that change one registration cannot overwrite each other:
//     the loser gets ErrConflict, reads again and decides afresh. A new item
//     starts at a random version, so one deleted and created again does not
//     take a save meant for the old one.
//   - TakeChallenge hands a challenge to exactly one caller, so a response to
//     it is checked once and cannot be replayed (TS 33.203 §6.1).
//   - NextNotify advances the NOTIFY CSeq and the reginfo version (RFC 3680
//     §5.2) in one atomic step, so two instances never send the same pair.
//   - SweepRegistrations and SweepSubscriptions may run on every instance:
//     each expired item is claimed by one conditional write before it is
//     handled, so it is handled once; a deregistration that fails, or whose
//     instance stops, is retried once its lease has passed.
//
// Memory implements the stores in process memory for tests and development;
// package dynamostore implements them in DynamoDB; package statetest checks
// both against one contract. Times are passed in by the caller, so the stores
// have no clock of their own.
package state
