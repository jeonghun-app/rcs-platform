package group

import (
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/jeonghun-app/rcs-platform/internal/conference"
	"github.com/jeonghun-app/rcs-platform/internal/ims/identity"
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
// who left, up to as many as the group's size limit; older ones leave it
// as deleted users (RFC 4575 §4.4). A partial document carries each
// changed user whole (state full) under a <users> marked partial, which
// RFC 4575 §4.6 merges by entity.

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

// partialDocument is the change to the participants named in changed, and
// the removal of those in deleted, at g's version, one above the document
// before.
func partialDocument(g groupstore.Group, changed, deleted []string) ([]byte, error) {
	c := info(g, conference.Partial)
	c.Users = &conference.Users{State: conference.Partial}
	for _, p := range g.Participants {
		if slices.Contains(changed, p.Identity) {
			c.Users.List = append(c.Users.List, user(p))
		}
	}
	for _, id := range deleted {
		c.Users.List = append(c.Users.List, conference.User{Entity: id, State: conference.Deleted})
	}
	return c.Marshal()
}

// The roster's size is bounded by the limits rather than checked as it
// grows: a document that internal/conference could not read back
// (conference.MaxDocumentSize) would make Roster fail for everyone, and a
// check on each change would block the Leave or Remove that adds one more
// former participant to a full roster. rosterBound is the size of the
// largest full document a group can have, for n entries in all, under the
// limits on what a client names: the longest conference URI, subject and
// version, and n users each with the longest identity (stored unescaped,
// canonical refuses what XML escapes), the longest name in the character
// that escapes longest (& to &amp;), the longer role and the longest
// endpoint, a former participant's. A partial document never holds more
// than the full one it changes.
func rosterBound(host string, n int) (int, error) {
	g := groupstore.Group{
		URI:     "sip:chat-" + strings.Repeat("0", 32) + "@" + host,
		Subject: strings.Repeat("&", MaxSubjectLength),
		Version: math.MaxUint32,
	}
	for i := range n {
		suffix := "@" + strconv.Itoa(i) + ".example.net"
		g.Participants = append(g.Participants, groupstore.Participant{
			Identity:    "sip:" + strings.Repeat("u", identity.MaxLength-len("sip:")-len(suffix)) + suffix,
			DisplayName: strings.Repeat("&", MaxDisplayNameLength),
			Role:        groupstore.Member,
			State:       groupstore.Left,
		})
	}
	doc, err := fullDocument(g)
	return len(doc), err
}

// formerLimit is how many former participants a group of at most
// maxParticipants keeps: as many as maxParticipants, or fewer if that
// many would take the largest roster beyond conference.MaxDocumentSize.
// It fails when not even maxParticipants current ones fit.
func formerLimit(host string, maxParticipants int) (int, error) {
	one, err := rosterBound(host, 1)
	if err != nil {
		return 0, err
	}
	two, err := rosterBound(host, 2)
	if err != nil {
		return 0, err
	}
	perUser := two - one
	fit := (conference.MaxDocumentSize - (one - perUser)) / perUser
	if fit < maxParticipants {
		return 0, fmt.Errorf("group: a roster of %d participants could exceed %d bytes; at most %d fit", maxParticipants, conference.MaxDocumentSize, fit)
	}
	return min(maxParticipants, fit-maxParticipants), nil
}
