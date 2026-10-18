// Package store holds msrp-relay's bindings: what pcscf allocated through the
// control API, so that whichever relay task a client connects to can bridge
// it (ADR 0004, ADR 0005). The Store interface has a memory backend here,
// for tests and single-task local runs, and a DynamoDB backend in
// internal/msrprelay/dynamostore; storetest checks that both behave the
// same.
//
// Every rule that must hold across relay tasks is part of the contract, so a
// backend enforces it atomically rather than leaving it to a read followed by
// a write:
//
//   - A binding carries its own expiry, and every operation treats one whose
//     expiry has passed as absent. DynamoDB's TTL deletion can lag by days
//     and only keeps the table small.
//   - A path, once set, can only be set again to the same value: the paths
//     name the session's endpoints, and RFC 4975 §8.4 makes a different
//     path a different session.
//   - Claim succeeds once per binding, whichever task asks, so one binding
//     carries one client connection (ADR 0004).
package store

import (
	"context"
	"errors"
	"time"
)

// Errors of the contract. Backends wrap them; compare with errors.Is.
var (
	// ErrNotFound: no binding with that id, or its expiry has passed.
	ErrNotFound = errors.New("store: no such binding")
	// ErrExists: Create found the id taken.
	ErrExists = errors.New("store: binding id taken")
	// ErrConflict: Update would change a path that is already set.
	ErrConflict = errors.New("store: path already set to another value")
	// ErrClaimed: a relay task has already claimed the binding.
	ErrClaimed = errors.New("store: binding already claimed")
	// ErrIncomplete: Claim found a path still missing.
	ErrIncomplete = errors.New("store: binding paths not yet known")
)

// Binding is one relay binding. Paths are kept in the a=path form, URIs
// separated by single spaces, so the store compares them as plain strings.
//
// The client-side session id is not part of a Binding: the id is derived
// from it one way (see msrprelay.BindingID), so a copy of the table does not
// let anyone connect as a client.
type Binding struct {
	ID string
	// CorePath is rcs-as's a=path, where the relay connects; empty until
	// pcscf knows it.
	CorePath string
	// ClientEndpointPath is the client's own a=path, the To-Path of
	// everything the relay sends to the client; empty until pcscf knows it.
	// The relay never connects to it (ADR 0004).
	ClientEndpointPath string
	// CoreLocal is the relay's own URI on the core side.
	CoreLocal string
	// ExpiresAt is when the binding stops being usable. Backends keep it to
	// the millisecond.
	ExpiresAt time.Time
	// ClaimedBy names the relay task and connection that claimed the
	// binding; empty until then.
	ClaimedBy string
}

// Expired reports whether b is unusable at now.
func (b Binding) Expired(now time.Time) bool { return !now.Before(b.ExpiresAt) }

// Complete reports whether both paths are known, which Claim requires.
func (b Binding) Complete() bool { return b.CorePath != "" && b.ClientEndpointPath != "" }

// Update changes a binding; zero fields are left as they are.
type Update struct {
	ExpiresAt          time.Time
	CorePath           string
	ClientEndpointPath string
}

// Store keeps bindings. Every method checks expiry against now, which the
// caller passes so that tests control time.
type Store interface {
	// Create stores b, which must not be claimed. ErrExists if the id is
	// taken, even by an expired binding the TTL has not removed yet.
	Create(ctx context.Context, b Binding) error
	// Get reads the binding with a strongly consistent read: a client may
	// connect milliseconds after another task wrote it (ADR 0004).
	Get(ctx context.Context, id string, now time.Time) (Binding, error)
	// Update applies u and returns the result. ErrNotFound for a missing or
	// expired binding; ErrConflict, with nothing changed, if u sets a path
	// that is already set to something else.
	Update(ctx context.Context, id string, u Update, now time.Time) (Binding, error)
	// Claim records by as the claimant and returns the binding. It fails
	// with ErrNotFound, ErrClaimed or ErrIncomplete, checked in that order,
	// and only one Claim of a binding ever succeeds.
	Claim(ctx context.Context, id, by string, now time.Time) (Binding, error)
	// Delete removes the binding. ErrNotFound if there was none, or only an
	// expired one (which is removed all the same).
	Delete(ctx context.Context, id string, now time.Time) error
	// Ready reports whether the store can be reached, for /readyz.
	Ready(ctx context.Context) error
}

// Precision is the resolution backends keep ExpiresAt at.
const Precision = time.Millisecond
