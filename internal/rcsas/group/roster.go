package group

import (
	"slices"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/rcsas/groupstore"
)

// The roster is a conference-info document (RFC 4575) with one user per
// participant, current or former, and one endpoint per user, the
// participant's identity: a group chat focus has a single session with
// each participant. What the endpoint says:
//
//	invited  dialing-out              the focus is inviting it (§5.7.3)
//	joined   connected
//	left     disconnected, departed   (§5.7.6)
//	removed  disconnected, booted
//
// Former participants stay in the roster as disconnected, as clients show
// who left; a partial document carries each changed user whole (state
// full) under a <users> marked partial, which RFC 4575 §4.6 merges by
// entity.

func endpoint(p groupstore.Participant) conference.Endpoint {
	e := conference.Endpoint{Entity: p.Identity, State: conference.Full}
	switch p.State {
	case groupstore.Invited:
		e.Status = conference.DialingOut
	case groupstore.Joined:
		e.Status = conference.Connected
	case groupstore.Left:
		e.Status, e.DisconnectionMethod = conference.Disconnected, conference.Departed
	case groupstore.Removed:
		e.Status, e.DisconnectionMethod = conference.Disconnected, conference.Booted
	}
	return e
}

func user(p groupstore.Participant) conference.User {
	return conference.User{
		Entity: p.Identity, State: conference.Full, DisplayText: p.DisplayName,
		Roles: []string{string(p.Role)}, Endpoints: []conference.Endpoint{endpoint(p)},
	}
}

func info(g groupstore.Group, state conference.State) *conference.Info {
	return &conference.Info{Entity: g.URI, State: state, Version: g.Version}
}

// fullDocument is the whole roster at g's version.
func fullDocument(g groupstore.Group) ([]byte, error) {
	c := info(g, conference.Full)
	// RFC 4575 §5.2: a full document always has a description, if empty.
	c.Description = &conference.Description{Subject: g.Subject}
	c.Users = &conference.Users{State: conference.Full}
	for _, p := range g.Participants {
		c.Users.List = append(c.Users.List, user(p))
	}
	return c.Marshal()
}

// partialDocument is the change to the participants named in changed, at
// g's version, one above the document before.
func partialDocument(g groupstore.Group, changed []string) ([]byte, error) {
	c := info(g, conference.Partial)
	c.Users = &conference.Users{State: conference.Partial}
	for _, p := range g.Participants {
		if slices.Contains(changed, p.Identity) {
			c.Users.List = append(c.Users.List, user(p))
		}
	}
	return c.Marshal()
}
