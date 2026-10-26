# Conformance

This file says which RCS Universal Profile features the platform serves, and
what is known of the move from UP 2.4 to UP 4.0
([ADR 0008](adr/0008-target-profile-up-4-0-in-stages.md)). Stage 1 of that ADR
files its issues from [UP 2.4 status](#up-24-status), stage 2 from
[UP 2.4 → UP 4.0 gaps](#up-24--up-40-gaps).

Every state word is one of ADR 0008 §2. The tables were checked against the
code of `main` at eca7e2c.

- **Status rows** name the code that serves a feature: a path and a type or
  function. Where there is none, the row says "no code found" and gives the
  search that found nothing.
- **Specification references.** No maintainer holds the GSMA documents, so a
  GSMA clause is *to confirm* ([spec references](spec-references.md#gsma)).
  IETF and 3GPP clauses are given where the code cites them.
- **Unverified behaviour.** A row that rests on a reading of a public client,
  not of the text, has an "unverified" note. The note is not a state.

Device configuration (RCC.14) is served by `acs`, a separate repository with
its own conformance record ([ADR 0006](adr/0006-acs-integration.md)), and is
not listed here.

## Unverified behaviour

Behaviour built from the public reference client (rcsjta) and public
descriptions, not checked against a licensed RCC.07, is listed where it is
built. This file links to the lists and does not copy them:

- `rcs-as` messaging: [Assumptions and limitations](rcs-as.md#assumptions-and-limitations),
  the item "Not checked against a licensed copy of RCC.07".
- Group chat: [Rules](rcs-as.md#rules) in `docs/rcs-as.md`, which says the
  rules have not been checked against the licensed texts.
- File Transfer via HTTP: [Unverified against RCC.07](ft-server.md#unverified-against-rcc07)
  in `docs/ft-server.md`.

## UP 2.4 status

One row per service area. "What is missing" is filled in for `partial` and
`absent` rows only. In the evidence, "off by default" says the feature needs a
setting turned on; it is a note, not a state.

| Feature | Status | Evidence | Specification | What is missing | Open issue |
|---|---|---|---|---|---|
| Capability discovery (OPTIONS) | `implemented` | [`internal/hss/defaultprofile.go`](../internal/hss/defaultprofile.go) `DefaultRCSProfile`, trigger 30: an OPTIONS with RCS service tags goes to `rcs-as` with SESSION_CONTINUED. [`internal/rcsas/sipas/server.go`](../internal/rcsas/sipas/server.go) `Server.Route` sends it on along its Route. [`internal/scscf/routing/terminating.go`](../internal/scscf/routing/terminating.go) `Router.toContacts` answers 480 for a user with no live binding. End to end: `options` scenario, [`tools/rcs-sim/internal/scenario/options.go`](../tools/rcs-sim/internal/scenario/options.go) | RCC.07 capability discovery, clause *to confirm*; RFC 3840, RFC 3841 | | none |
| Presence-based discovery | `out of scope`: [architecture](architecture.md#53-capability-discovery) §5.3 leaves it out of the first release | No code found: `grep -rni -e presence -e pidf internal/ cmd/` finds only the Diameter `cx.Presence` type, comments and test fixtures | *to confirm* | | none |
| 1-to-1 Chat | `implemented` | [`internal/rcsas/sipas/answer.go`](../internal/rcsas/sipas/answer.go) `Server.invite` (client's INVITE, `oma.cpm.session` or `+g.oma.sip-im`); [`internal/rcsas/sipas/invite.go`](../internal/rcsas/sipas/invite.go) `Server.Invite` (terminating session); [`internal/rcsas/messaging/leg.go`](../internal/rcsas/messaging/leg.go) `Engine.OpenLeg`, `Engine.Offer`; is-composing in `leg.go`. End to end: `chat-invite` scenario, [`sipchat.go`](../tools/rcs-sim/internal/scenario/sipchat.go). Unverified (rcs-as list) | RCC.07 Chat, clause *to confirm*; OMA CPM; RFC 4975, RFC 3862, RFC 4028 | | #663 |
| IMDN delivery and display | `implemented` | [`internal/rcsas/messaging/notify.go`](../internal/rcsas/messaging/notify.go) `Engine.submitNotification` (checks a notification and queues it once per notifier and kind); negative delivery notifications on expiry or a full queue; [`internal/imdn`](../internal/imdn). End to end: `chat-invite` and `pager-message` scenarios. `rcs-as` does not add itself to `IMDN-Record-Route`, by design ([rcs-as](rcs-as.md#assumptions-and-limitations)). Unverified (rcs-as list) | RFC 5438 §7.2.1, §8; RCC.07 clause *to confirm* | | none |
| IMDN processing notifications | `absent` | `rcs-as` accepts processing notifications from `RCSAS_IMDN_INTERMEDIARIES` (`Engine.submitNotification`) but sends none of its own ([rcs-as](rcs-as.md#assumptions-and-limitations), "No processing notifications") | RFC 5438; RCC.07 clause *to confirm* | `rcs-as` never sends a "stored" processing notification for a message it holds; whether UP 2.4 asks the network for one is *to confirm*. | none |
| Store-and-forward | `implemented` | [`internal/rcsas/messaging/engine.go`](../internal/rcsas/messaging/engine.go) `Engine.submitMessage`, `Engine.enqueue`, `Engine.UserRegistered`; [`dispatch.go`](../internal/rcsas/messaging/dispatch.go) `Engine.drain`; [`internal/rcsas/store`](../internal/rcsas/store) `Store`, DynamoDB backend in [`internal/rcsas/awsstore`](../internal/rcsas/awsstore); default profile triggers for unregistered users ([hss](hss.md#default-service-profile)). End to end: the `peer-offline` steps of `chat-invite` and `pager-message` | RCC.07 and OMA CPM, clause *to confirm* | | #663 |
| Chat-to-SMS interworking | `absent` | No code found: `grep -rniw -e sms -e smsc -e ip-sm-gw internal/ cmd/ tools/` finds nothing. [`notify.go`](../internal/rcsas/messaging/notify.go) `Engine.Report`, the hook for a disposition an interworking network reports, has no caller outside tests | *to confirm* | Nothing sends a chat or standalone message on as SMS, or takes an SMS into RCS. | none |
| Standalone Messaging, pager mode | `implemented` | [`internal/rcsas/sipas/server.go`](../internal/rcsas/sipas/server.go) `Server.message` (202 once stored); [`internal/rcsas/sipas/pager.go`](../internal/rcsas/sipas/pager.go) `Server.Pager` (delivery, `oma.cpm.msg`). End to end: `pager-message` scenario, [`pager.go`](../tools/rcs-sim/internal/scenario/pager.go) | RFC 3428 §7; RCC.07 standalone messaging, clause *to confirm* | | none |
| Standalone Messaging, large-message mode | `implemented` | [`answer.go`](../internal/rcsas/sipas/answer.go) `Server.invite` (`oma.cpm.largemsg`, `store.Standalone`); `Server.Invite` offers the large-mode ICSI (`largeICSI`, [`session.go`](../internal/rcsas/sipas/session.go)). One message per session, unverified (rcs-as list). No end-to-end scenario | RCC.07 standalone messaging, clause *to confirm*; RFC 4975 | | none |
| Group Chat: create, join, rejoin, leave, roster | `implemented` | Off by default: on only with `RCSAS_GROUP_CHAT_ENABLED=true` ([`internal/rcsas/config.go`](../internal/rcsas/config.go)), which the compose stack sets and `infra/platform.yaml` does not. [`internal/rcsas/sipas/group.go`](../internal/rcsas/sipas/group.go) `Server.groupInvite`; [`internal/rcsas/group/group.go`](../internal/rcsas/group/group.go) `Service.Create`, `Join`, `Leave`; roster: [`subscription.go`](../internal/rcsas/sipas/subscription.go) `Server.groupSubscribe`. End to end: `group-chat` scenario, [`sipgroup.go`](../tools/rcs-sim/internal/scenario/sipgroup.go). Unverified (group rules) | RCC.07 Group Chat, clause *to confirm*; RFC 4575, RFC 4579, RFC 5366 | | #590 |
| Group Chat: add participants | `implemented` | Off by default. [`internal/rcsas/sipas/refer.go`](../internal/rcsas/sipas/refer.go) `Server.refer`; `group.Service.Add` | RCC.07 Group Chat, clause *to confirm*; RFC 3515 | | none |
| Group Chat: remove participants | `implemented` | Off by default. `Server.refer` with `method=BYE`; `group.Service.Remove` (chairman only, `ErrNotChairman`) | RCC.07 Group Chat, clause *to confirm*; RFC 3515 | | none |
| Group Chat: roles | `partial` | [`internal/rcsas/groupstore/groupstore.go`](../internal/rcsas/groupstore/groupstore.go) `Role` (`Chairman`, `Member`); `group.Service.Leave` passes the role on (`successor`) | RCC.07 Group Chat, clause *to confirm* | The chairman cannot hand the role to another participant: it passes only when the chairman leaves. | none |
| Group Chat: subject change | `absent` | The subject is read once, from the factory INVITE's `Subject` (`Server.groupInvite`, into `group.CreateRequest`); `group.Service` has no operation that changes it | RCC.07 Group Chat, clause *to confirm* | No request changes a group's subject after it is created. | none |
| Group Chat: icon | `absent` | No code found: `grep -rniE '\bicon' internal/rcsas internal/conference` finds nothing | RCC.07 Group Chat, clause *to confirm* | A group has no icon: nothing sets, stores or sends one. | none |
| FT via HTTP: upload, resume, download | `implemented` | [`internal/ftserver/upload.go`](../internal/ftserver/upload.go) `Server.handleUpload`, `handleResume`, `handleInfo`; [`download.go`](../internal/ftserver/download.go) `Server.handleDownload` (single byte ranges). End to end: `ft` and `ft-resume` scenarios, [`ft.go`](../tools/rcs-sim/internal/scenario/ft.go). Unverified ([ft-server list](ft-server.md#unverified-against-rcc07)) | RCC.07 FT via HTTP, clause *to confirm*; RFC 9110, RFC 7578, RFC 6266 | | none |
| FT via HTTP: thumbnails | `implemented` | `ftserver` stores the thumbnail the client uploads (`Thumbnail` form part, [`form.go`](../internal/ftserver/form.go); `Server.storeThumbnail`) and lists it in the file-info document; it makes none itself. End to end: `download-thumbnail` step of `ft` | RCC.07 FT via HTTP, clause *to confirm* | | none |
| FT via HTTP: file-info in 1-to-1 chat and standalone messages | `partial` | `rcs-as` carries a CPIM body's content unchanged and does not read it ([`internal/rcsas/messaging/doc.go`](../internal/rcsas/messaging/doc.go); `Engine.submitMessage`), so a file-info document should go as any message does | RCC.07 FT via HTTP, clause *to confirm* | No test shows the file-info document passing through. | none |
| FT via HTTP in group chat | `partial` | Off by default. Group messages keep their content headers and body (`groupView`, [`internal/rcsas/messaging/group.go`](../internal/rcsas/messaging/group.go)) | RCC.07 Group Chat and FT via HTTP, clause *to confirm* | No test shows the file-info document passing through. | none |
| File transfer over MSRP | `absent` | `Server.invite` ([`answer.go`](../internal/rcsas/sipas/answer.go)) and `Server.groupInvite` answer 403 to an offer with `a=file-selector` | RFC 5547 §6; RCC.07 clause *to confirm* | An INVITE for a file transfer over MSRP is refused, in 1-to-1 and in group chat. | none |
| Geolocation push | `absent` | No code found: `grep -rni geoloc internal/ cmd/ tools/` finds nothing; the geopush IARI is only in a reference request of [`internal/hss/reference.go`](../internal/hss/reference.go) | *to confirm* | No code or test handles a geolocation push; whether one needs more than chat carrying its content unchanged is *to confirm*. | none |
| Audio messaging | `absent` | No code found: `grep -rni audio internal/rcsas internal/ftserver` finds only an SDP fixture in a test | *to confirm* | Nothing treats an audio message apart from any other file; whether it needs more than FT via HTTP is *to confirm*. | none |
| Chatbot (MaaP) | `out of scope`: epic #668 | No chatbot service: the chatbot IARI and bot tags are only in reference requests ([`internal/hss/reference.go`](../internal/hss/reference.go)) and iFC tests; `hss` supports no wildcarded identity or PSI ([hss](hss.md#cx-behaviour)) | *to confirm* | | #668, #671 |
| Multi-device | `partial` | [`terminating.go`](../internal/scscf/routing/terminating.go) `onePerInstance` forks a terminating request to one flow of each device; `Server.Pager` reaches each device that registered `oma.cpm.msg`; [`invite.go`](../internal/rcsas/sipas/invite.go) `Server.dropFork` ends the session of every device but the first to answer | RFC 5626 §7, RFC 3841; RCC.07 clause *to confirm* | A chat or large-mode session reaches only the first device to answer, and no code gives a user's other devices the messages of that session or the messages the user sent. | none |
| Message revocation | `absent` | No code found: `grep -rni -e revoc -e revok internal/ cmd/ tools/` finds nothing | *to confirm* | A sender cannot revoke a message `rcs-as` still holds or has delivered. | none |
| Enriched Calling | `absent` | No code found: `grep -rni -e enriched -e callcomposer -e callunanswered -e sharedmap -e sharedsketch -e postcall internal/ cmd/ tools/` finds only an iFC test fixture; `Server.invite` answers 403 to an INVITE that names no CPM chat or large-message service | *to confirm* | Nothing serves any Enriched Calling service. | none |
| IP voice and video calls | `absent` | No MMTEL code: the default profile sends an MMTEL INVITE past `rcs-as` (`otherService`, [`defaultprofile.go`](../internal/hss/defaultprofile.go)); [`internal/pcscf/msrphooks.go`](../internal/pcscf/msrphooks.go) `anchorInitial` leaves an offer without MSRP lines alone, so the core passes a call's signalling on and serves nothing; no test places a call | *to confirm* | The platform does not serve voice or video calls: it has no MMTEL application server and does not anchor RTP media. | none |

## UP 2.4 → UP 4.0 gaps

No maintainer holds the UP 4.0 text. Each row cites a row of
[Public sources](spec-references.md#public-sources) by its bold short name.
None of those sources states an edition, clause or value, so every row is
*to confirm* (ADR 0008 §2) and `open`. A #667 row needs an open issue to pass
the exit rule (ADR 0008 §4); a #668 row does not count for it.

### Named by GSMA for UP 4.0

These are every new feature the **GSMA UP 4.0 article** names (ADR 0008 §4,
third condition).

| Item | Change from 2.4 | Source | Evidence | Progress | Epic | Issue |
|---|---|---|---|---|---|---|
| Messaging-initiated video calls | A user can turn a 1-to-1 or group conversation into a video call from inside it; the platform serves no video calls today (IP voice and video calls above). | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Late joining of a group video call | A group member who missed the start of a messaging-initiated video call can join it while it lasts. | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Video call log in the chat timeline | The records of messaging-initiated video calls are kept in step with the conversation they started from. | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Rich text | A message can carry styling such as bold, italics and strikethrough, with defined fallbacks that keep it backward compatible. | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Plain-text review on SMS fallback | When a rich-text message has to go as SMS, the user is asked to review its plain-text form; the platform has no SMS fallback (Chat-to-SMS interworking above). | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Media format discovery | A device learns which audio, video and image formats its conversation partner supports, so that it picks the encoding of what it sends. | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Streaming video in rich cards | A business's rich card can embed video that streams instead of being downloaded whole. | **GSMA UP 4.0 article** | *to confirm* | `open` | #668 | none |
| Business control of how links open | A business can choose whether a link opens in the messaging app or in another app. | **GSMA UP 4.0 article** | *to confirm* | `open` | #668 | none |
| Deep links to businesses and their verification | Deep links to businesses, and the verification of those businesses, are handled more efficiently. | **GSMA UP 4.0 article** | *to confirm* | `open` | #668 | none |

### Named by GSMA for UP 3.0 and 3.1

Releases between 2.4 and 4.0. GSMA states these for UP 3.0 or 3.1; that UP 4.0
keeps each of them is *to confirm*.

| Item | Change from 2.4 | Source | Evidence | Progress | Epic | Issue |
|---|---|---|---|---|---|---|
| End-to-end encryption | Messages and files between clients can be encrypted end to end with MLS, which UP 3.0 and 3.1 set out. | **GSMA RCS encryption article**, **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Audio messaging codecs | UP 3.0 improves the codecs of audio messages, and UP 3.1 adds xHE-AAC. | **GSMA RCS encryption article**, **GSMA UP 3.1 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Client connection to operator services | UP 3.1 changes how a client is onboarded and connects to operator services, using the push notification services of the device's operating system. | **GSMA UP 3.1 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Richer deep links to businesses | UP 3.0 brings a richer format of deep link for reaching a business. | **GSMA RCS encryption article** | *to confirm* | `open` | #668 | none |
| Subscriptions to business senders | UP 3.0 makes it easier for a user to manage subscriptions to business messaging senders. | **GSMA RCS encryption article** | *to confirm* | `open` | #668 | none |

### Seen only in a lead

The **Wikipedia RCS article** names these for releases after 2.4. A
third-party lead confirms nothing and creates no obligation (ADR 0008 §3, §4);
each row records where to look.

| Item | Change from 2.4 | Source | Evidence | Progress | Epic | Issue |
|---|---|---|---|---|---|---|
| Message replies | A message can be sent as a reply to an earlier one (the lead names UP 2.7). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Reactions | A user can react to a message, with custom emoji (UP 2.7, improved in 3.0 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Editing and deleting messages | A sender can edit or delete a message it sent (UP 2.7 per the lead); compare Message revocation above. | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Spam handling and reporting | Spam handling improves and a user can report spam (UP 2.7 and 3.1 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| File transfer authentication and security | Optional authentication procedures for file transfer, and better file transfer security (UP 2.6 and 3.1 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Messaging verification | More verification of messaging (UP 2.5 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Deep links that start a conversation | A deep link can open a conversation (UP 3.1 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Encrypted video calls | Video calls from a conversation are encrypted end to end (UP 4.0 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Chatbot features and verification | More chatbot features and chatbot verification (UP 2.5 to 3.0 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #668 | none |
