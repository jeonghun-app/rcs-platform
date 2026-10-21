package regevent

import (
	"fmt"
	"slices"

	"github.com/jeonghun-app/rcs-platform/internal/scscf/state"
	"github.com/jeonghun-app/rcs-platform/internal/sip"
	"github.com/jeonghun-app/rcs-platform/internal/sip/dialog"
)

// storedDialog is d as the store keeps it, every part in its wire form
// (dialog.Dialog is not a storage format: its sip types write themselves
// redacted).
func storedDialog(d *dialog.Dialog) state.Dialog {
	routes := make([]string, len(d.RouteSet))
	for i, r := range d.RouteSet {
		routes[i] = r.String()
	}
	if len(routes) == 0 {
		routes = nil
	}
	return state.Dialog{
		CallID: d.CallID, LocalTag: d.LocalTag(), RemoteTag: d.RemoteTag(),
		LocalURI: untagged(d.Local).String(), RemoteURI: untagged(d.Remote).String(),
		RemoteTarget: d.RemoteTarget.String(), RouteSet: routes, RemoteSeq: d.RemoteSeq,
	}
}

func untagged(a sip.Address) sip.Address {
	a.Params = slices.Clone(a.Params)
	a.Params.Del("tag")
	return a
}

// dialogOf is s's dialog, its CSeq the last s used, to build the next
// request in it from.
func (n *Notifier) dialogOf(s *state.Subscription) (*dialog.Dialog, error) {
	sd := s.Dialog
	local, err := sip.ParseAddress(sd.LocalURI)
	if err != nil {
		return nil, fmt.Errorf("regevent: stored dialog: %w", err)
	}
	remote, err := sip.ParseAddress(sd.RemoteURI)
	if err != nil {
		return nil, fmt.Errorf("regevent: stored dialog: %w", err)
	}
	local.Params.Set("tag", sd.LocalTag)
	remote.Params.Set("tag", sd.RemoteTag)
	target, err := sip.ParseURI(sd.RemoteTarget)
	if err != nil {
		return nil, fmt.Errorf("regevent: stored dialog: %w", err)
	}
	d := &dialog.Dialog{
		CallID: sd.CallID, Local: local, Remote: remote,
		LocalTarget: n.cfg.Contact, RemoteTarget: target,
		LocalSeq: s.CSeq, RemoteSeq: sd.RemoteSeq, HasRemoteSeq: true,
	}
	for _, r := range sd.RouteSet {
		a, err := sip.ParseAddress(r)
		if err != nil {
			return nil, fmt.Errorf("regevent: stored dialog: %w", err)
		}
		d.RouteSet = append(d.RouteSet, a)
	}
	return d, nil
}
