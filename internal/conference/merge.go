package conference

import (
	"errors"
	"fmt"
	"slices"
)

var (
	// ErrStaleVersion reports a document whose version is not above the
	// local one; RFC 4575 §4.6 discards it without processing.
	ErrStaleVersion = errors.New("conference: document is not newer than the local state")
	// ErrVersionGap reports a partial document that skips versions; the
	// subscriber must refresh its subscription to get a full one (§4.6).
	ErrVersionGap = errors.New("conference: partial document skips a version")
	// ErrNoFullState reports a partial document with no full state to apply
	// it to.
	ErrNoFullState = errors.New("conference: partial document without a full state")
	// ErrEntityMismatch reports a document about another conference.
	ErrEntityMismatch = errors.New("conference: document describes another conference")
)

// Merge applies doc to local, the state built from earlier documents of the
// same subscription, and returns the new state; local is not modified. Pass a
// nil local for the first document. The procedure is RFC 4575 §4.6:
//
//   - a document whose version is not above local's is discarded
//     (ErrStaleVersion);
//   - a full or deleted document replaces the state; deleted means the
//     conference has ended and the subscription should be terminated;
//   - a partial document must be exactly one version above local
//     (ErrVersionGap otherwise). Each element it carries is replaced when
//     full, removed when deleted and merged by key when partial; users and
//     endpoints are keyed by entity.
//
// The returned state is full throughout, or deleted, and marshals as a full
// document.
func Merge(local, doc *Info) (*Info, error) {
	if doc == nil {
		return nil, fmt.Errorf("%w: no document", ErrMalformed)
	}
	if err := doc.validate(); err != nil {
		return nil, err
	}
	if local == nil {
		if doc.State.orFull() == Partial {
			return nil, ErrNoFullState
		}
		return doc.clone(), nil
	}
	if err := local.validate(); err != nil {
		return nil, fmt.Errorf("local state: %w", err)
	}
	if doc.Entity != local.Entity {
		return nil, ErrEntityMismatch
	}
	if doc.Version <= local.Version {
		return nil, ErrStaleVersion
	}
	if doc.State.orFull() != Partial {
		return doc.clone(), nil
	}
	if local.State.orFull() != Full {
		return nil, ErrNoFullState
	}
	if doc.Version != local.Version+1 {
		return nil, ErrVersionGap
	}

	out := local.clone()
	out.Version = doc.Version
	// conference-description has no state attribute, so it is atomic and a
	// present one replaces the old (§4.6 step 3.2).
	if doc.Description != nil {
		d := *doc.Description
		out.Description = &d
	}
	if doc.Users != nil {
		out.Users = mergeUsers(out.Users, doc.Users)
	}
	return out, nil
}

// clone returns a deep copy of c with every state made explicit.
func (c *Info) clone() *Info {
	out := &Info{Entity: c.Entity, State: c.State.orFull(), Version: c.Version}
	if c.Description != nil {
		d := *c.Description
		out.Description = &d
	}
	if c.Users != nil {
		out.Users = &Users{State: c.Users.State.orFull()}
		for _, u := range c.Users.List {
			out.Users.List = append(out.Users.List, u.asFull())
		}
	}
	return out
}

func mergeUsers(local, upd *Users) *Users {
	switch upd.State.orFull() {
	case Full:
		out := &Users{State: Full}
		for _, u := range upd.List {
			out.List = append(out.List, u.asFull())
		}
		return out
	case Deleted:
		// The element is removed (§4.6 step 2). An empty roster says the
		// same and keeps the state marshallable as a full document.
		return &Users{State: Full}
	}

	out := &Users{State: Full}
	var list []User
	if local != nil {
		list = local.List
	}
	index := make(map[string]int, len(list))
	for _, u := range list {
		index[u.Entity] = len(out.List)
		out.List = append(out.List, u.asFull())
	}
	removed := map[string]bool{}
	for _, u := range upd.List {
		i, known := index[u.Entity]
		switch {
		case u.State.orFull() == Deleted:
			// Deleting an unknown user changes nothing.
			removed[u.Entity] = true
		case !known:
			// §4.6 step 3.1.1: an unknown key adds a row, whatever the state.
			index[u.Entity] = len(out.List)
			out.List = append(out.List, u.asFull())
		case u.State.orFull() == Full:
			out.List[i] = u.asFull()
		default:
			out.List[i] = mergeUser(out.List[i], u)
		}
	}
	out.List = slices.DeleteFunc(out.List, func(u User) bool { return removed[u.Entity] })
	return out
}

// mergeUser applies a partial user to a local one: the elements it carries
// replace the local ones and its endpoints merge by key (§4.6 step 3).
func mergeUser(local, upd User) User {
	if upd.DisplayText != "" {
		local.DisplayText = upd.DisplayText
	}
	if len(upd.Roles) > 0 {
		local.Roles = slices.Clone(upd.Roles)
	}
	index := make(map[string]int, len(local.Endpoints))
	for i, e := range local.Endpoints {
		index[e.Entity] = i
	}
	removed := map[string]bool{}
	for _, e := range upd.Endpoints {
		i, known := index[e.Entity]
		switch {
		case e.State.orFull() == Deleted:
			removed[e.Entity] = true
		case !known:
			index[e.Entity] = len(local.Endpoints)
			e.State = Full
			local.Endpoints = append(local.Endpoints, e)
		case e.State.orFull() == Full:
			e.State = Full
			local.Endpoints[i] = e
		default:
			local.Endpoints[i] = mergeEndpoint(local.Endpoints[i], e)
		}
	}
	local.Endpoints = slices.DeleteFunc(local.Endpoints, func(e Endpoint) bool { return removed[e.Entity] })
	return local
}

func mergeEndpoint(local, upd Endpoint) Endpoint {
	if upd.DisplayText != "" {
		local.DisplayText = upd.DisplayText
	}
	if upd.Status != "" {
		local.Status = upd.Status
	}
	if upd.JoiningMethod != "" {
		local.JoiningMethod = upd.JoiningMethod
	}
	if upd.DisconnectionMethod != "" {
		local.DisconnectionMethod = upd.DisconnectionMethod
	}
	return local
}

// asFull returns a deep copy of u as a row of the merged state: full, and
// without endpoints a partial update deleted.
func (u User) asFull() User {
	out := User{Entity: u.Entity, State: Full, DisplayText: u.DisplayText, Roles: slices.Clone(u.Roles)}
	for _, e := range u.Endpoints {
		if e.State.orFull() == Deleted {
			continue
		}
		e.State = Full
		out.Endpoints = append(out.Endpoints, e)
	}
	return out
}
