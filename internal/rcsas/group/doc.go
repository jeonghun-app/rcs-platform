// Package group runs rcs-as's group chats: the controlling function (the
// conference focus) of RCC.07 Group Chat. It keeps each group's roster
// (internal/rcsas/groupstore), decides who may create, join, leave, add
// and remove, tells subscribers of the conference event package (RFC
// 4575) what changed, and tells the messaging engine who a participant's
// message goes to. The engine (internal/rcsas/messaging) does the rest: it
// queues one copy of each message per participant, delivers it on that
// participant's own session with the group, keeps it while the participant
// is away and carries notifications back to the author.
//
// The package has no SIP code. The SIP layer (a later issue) calls Create
// when a client's INVITE reaches the conference factory, Join when a
// participant's session with the group is set up, Leave on its BYE or on a
// 603 Decline of the focus's INVITE, Add on a REFER, Remove on a REFER with
// method=BYE, and Roster for a SUBSCRIBE; it implements Notifier, through
// which roster changes become NOTIFYs, and ends the session and the
// subscriptions of whoever leaves or is removed.
//
// # Rules
//
// The rules are this package's reading of RCC.07 Group Chat and OMA CPM
// group sessions (docs/rcs-as.md has the table):
//
//   - Anyone may create a group with one to RCSAS_GROUP_MAX_PARTICIPANTS-1
//     others; the creator is its chairman.
//   - Only a participant in the group (joined) may add others, and only
//     within the size limit. Only the chairman may remove others; anyone may
//     leave.
//   - A participant who left or was removed comes back only by being added
//     again; being in the roster once is not a standing invitation.
//   - A group remembers at most as many former participants as its size
//     limit; the one who left longest ago is forgotten first, so that
//     churn cannot grow the stored group without bound.
//   - When the chairman leaves, the role passes to the participant who has
//     been in the group longest.
//   - Only a joined participant may write in the group, and what it writes
//     goes to every other current participant, invited ones included, so
//     that they find it when they join.
//
// Every change is computed from the stored group and written back
// conditionally (groupstore.Store.Update), so two tasks changing one group
// at once never lose a change, and each change gets the next roster
// version.
package group
