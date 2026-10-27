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
- **Unverified behaviour.** An "unverified" note says that a row relies on an
  edition marked *to confirm* (ADR 0008 §2); it is a note, not a state. Every
  GSMA edition is *to confirm* today, so the note is put where it tells the
  reader something: on each row whose behaviour one of the lists below records
  as not checked against the text, with the list named.

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
`absent` rows only. "Code" names the code a row rests on; in it, "off by
default" says that the feature needs a setting turned on, a note and not a
state.

| Feature | Status | What is missing | Open issue | Specification | Code |
|---|---|---|---|---|---|
| Capability discovery (OPTIONS) | `implemented` |  | none | RCC.07 capability discovery, clause *to confirm*; RFC 3840, RFC 3841 | [`internal/hss/defaultprofile.go`](../internal/hss/defaultprofile.go) `DefaultRCSProfile`, trigger 30: an OPTIONS with RCS service tags goes to `rcs-as` with SESSION_CONTINUED. [`internal/rcsas/sipas/server.go`](../internal/rcsas/sipas/server.go) `Server.Route` sends it on along its Route. [`internal/scscf/routing/terminating.go`](../internal/scscf/routing/terminating.go) `Router.toContacts` answers 480 for a user with no live binding. End to end: `options` scenario, [`tools/rcs-sim/internal/scenario/options.go`](../tools/rcs-sim/internal/scenario/options.go) |
| Presence-based discovery | `out of scope`: [architecture](architecture.md#53-capability-discovery) §5.3 leaves it out of the first release |  | none | *to confirm* | No code found: `grep -rni -e presence -e pidf internal/ cmd/` finds only the Diameter `cx.Presence` type, comments and test fixtures |
| 1-to-1 Chat | `implemented` |  | #663 | RCC.07 Chat, clause *to confirm*; OMA CPM, clause *to confirm*; RFC 4975, RFC 3862, RFC 4028. Unverified (rcs-as list) | [`internal/rcsas/sipas/answer.go`](../internal/rcsas/sipas/answer.go) `Server.invite` (client's INVITE, `oma.cpm.session` or `+g.oma.sip-im`); [`internal/rcsas/sipas/invite.go`](../internal/rcsas/sipas/invite.go) `Server.Invite` (terminating session); [`internal/rcsas/messaging/leg.go`](../internal/rcsas/messaging/leg.go) `Engine.OpenLeg`, `Engine.Offer`; is-composing in `leg.go`. End to end: `chat-invite` scenario, [`sipchat.go`](../tools/rcs-sim/internal/scenario/sipchat.go) |
| IMDN delivery and display | `implemented` |  | none | RFC 5438 §7.2.1, §8; RCC.07 clause *to confirm*. Unverified (rcs-as list) | [`internal/rcsas/messaging/notify.go`](../internal/rcsas/messaging/notify.go) `Engine.submitNotification` (checks a notification and queues it once per notifier and kind); negative delivery notifications on expiry or a full queue; [`internal/imdn`](../internal/imdn). End to end: `chat-invite` and `pager-message` scenarios. `rcs-as` does not add itself to `IMDN-Record-Route`, by design ([rcs-as](rcs-as.md#assumptions-and-limitations)) |
| IMDN processing notifications | `absent` | `rcs-as` never sends a "stored" processing notification for a message it holds; whether UP 2.4 asks the network for one is *to confirm*. | none | RFC 5438; RCC.07 clause *to confirm* | `rcs-as` accepts processing notifications from `RCSAS_IMDN_INTERMEDIARIES` (`Engine.submitNotification`) but sends none of its own ([rcs-as](rcs-as.md#assumptions-and-limitations), "No processing notifications") |
| Store-and-forward | `implemented` |  | #663 | RCC.07 and OMA CPM, clause *to confirm* | [`internal/rcsas/messaging/engine.go`](../internal/rcsas/messaging/engine.go) `Engine.submitMessage`, `Engine.enqueue`, `Engine.UserRegistered`; [`dispatch.go`](../internal/rcsas/messaging/dispatch.go) `Engine.drain`; [`internal/rcsas/store`](../internal/rcsas/store) `Store`, DynamoDB backend in [`internal/rcsas/awsstore`](../internal/rcsas/awsstore); default profile triggers for unregistered users ([hss](hss.md#default-service-profile)). End to end: the `peer-offline` steps of `chat-invite` and `pager-message` |
| Chat-to-SMS interworking | `absent` | Nothing sends a chat or standalone message on as SMS, or takes an SMS into RCS. | none | *to confirm* | No code found: `grep -rniw -e sms -e smsc -e ip-sm-gw internal/ cmd/ tools/` finds nothing. [`notify.go`](../internal/rcsas/messaging/notify.go) `Engine.Report`, the hook for a disposition an interworking network reports, has no caller outside tests |
| Standalone Messaging, pager mode | `implemented` |  | none | RFC 3428 §7; RCC.07 standalone messaging, clause *to confirm*. Unverified (rcs-as list: one From and at most one To) | [`internal/rcsas/sipas/server.go`](../internal/rcsas/sipas/server.go) `Server.message` (202 once stored); [`internal/rcsas/sipas/pager.go`](../internal/rcsas/sipas/pager.go) `Server.Pager` (delivery, `oma.cpm.msg`). End to end: `pager-message` scenario, [`pager.go`](../tools/rcs-sim/internal/scenario/pager.go) |
| Standalone Messaging, large-message mode | `implemented` |  | none | RCC.07 standalone messaging, clause *to confirm*; RFC 4975. Unverified (rcs-as list: one message per session) | [`answer.go`](../internal/rcsas/sipas/answer.go) `Server.invite` (`oma.cpm.largemsg`, `store.Standalone`); `Server.Invite` offers the large-mode ICSI (`largeICSI`, [`session.go`](../internal/rcsas/sipas/session.go)). No end-to-end scenario |
| Group Chat: create, join, rejoin, leave, roster | `implemented` |  | #590 | RCC.07 Group Chat, clause *to confirm*; RFC 4575, RFC 4579, RFC 5366. Unverified (group rules) | Off by default: on only with `RCSAS_GROUP_CHAT_ENABLED=true` ([`internal/rcsas/config.go`](../internal/rcsas/config.go)), which the compose stack sets and `infra/platform.yaml` does not. [`internal/rcsas/sipas/group.go`](../internal/rcsas/sipas/group.go) `Server.groupInvite`; [`internal/rcsas/group/group.go`](../internal/rcsas/group/group.go) `Service.Create`, `Join`, `Leave`; roster: [`subscription.go`](../internal/rcsas/sipas/subscription.go) `Server.groupSubscribe`. End to end: `group-chat` scenario, [`sipgroup.go`](../tools/rcs-sim/internal/scenario/sipgroup.go) |
| Group Chat: add participants | `implemented` |  | none | RCC.07 Group Chat, clause *to confirm*; RFC 3515. Unverified (group rules) | Off by default. [`internal/rcsas/sipas/refer.go`](../internal/rcsas/sipas/refer.go) `Server.refer`; `group.Service.Add` |
| Group Chat: remove participants | `implemented` |  | none | RCC.07 Group Chat, clause *to confirm*; RFC 3515. Unverified (group rules) | Off by default. `Server.refer` with `method=BYE`; `group.Service.Remove` (chairman only, `ErrNotChairman`) |
| Group Chat: roles | `partial` | The chairman cannot hand the role to another participant: it passes only when the chairman leaves. | none | RCC.07 Group Chat, clause *to confirm*. Unverified (group rules) | [`internal/rcsas/groupstore/groupstore.go`](../internal/rcsas/groupstore/groupstore.go) `Role` (`Chairman`, `Member`); `group.Service.Leave` passes the role on (`successor`) |
| Group Chat: subject change | `absent` | No request changes a group's subject after it is created. | none | RCC.07 Group Chat, clause *to confirm* | The subject is read once, from the factory INVITE's `Subject` (`Server.groupInvite`, into `group.CreateRequest`); `group.Service` has no operation that changes it |
| Group Chat: icon | `absent` | A group has no icon: nothing sets, stores or sends one. | none | RCC.07 Group Chat, clause *to confirm* | No code found: `grep -rniE '\bicon' internal/rcsas internal/conference` finds nothing |
| FT via HTTP: upload, resume, download | `implemented` |  | none | RCC.07 FT via HTTP, clause *to confirm*; RFC 9110, RFC 7578, RFC 6266. Unverified ([ft-server list](ft-server.md#unverified-against-rcc07)) | [`internal/ftserver/upload.go`](../internal/ftserver/upload.go) `Server.handleUpload`, `handleResume`, `handleInfo`; [`download.go`](../internal/ftserver/download.go) `Server.handleDownload` (single byte ranges). End to end: `ft` and `ft-resume` scenarios, [`ft.go`](../tools/rcs-sim/internal/scenario/ft.go) |
| FT via HTTP: thumbnails | `implemented` |  | none | RCC.07 FT via HTTP, clause *to confirm*. Unverified (ft-server list: the namespace of the file-info document that lists the thumbnail) | `ftserver` stores the thumbnail the client uploads (`Thumbnail` form part, [`form.go`](../internal/ftserver/form.go); `Server.storeThumbnail`) and lists it in the file-info document; it makes none itself. End to end: `download-thumbnail` step of `ft` |
| FT via HTTP: file-info in 1-to-1 chat and standalone messages | `partial` | No test shows the file-info document passing through. | none | RCC.07 FT via HTTP, clause *to confirm* | `rcs-as` carries a CPIM body's content unchanged and does not read it ([`internal/rcsas/messaging/doc.go`](../internal/rcsas/messaging/doc.go); `Engine.submitMessage`), so a file-info document should go as any message does |
| FT via HTTP in group chat | `partial` | No test shows the file-info document passing through. | none | RCC.07 Group Chat and FT via HTTP, clause *to confirm* | Off by default. Group messages keep their content headers and body (`groupView`, [`internal/rcsas/messaging/group.go`](../internal/rcsas/messaging/group.go)) |
| File transfer over MSRP | `absent` | An INVITE for a file transfer over MSRP is refused, in 1-to-1 and in group chat. | none | RFC 5547 §6; RCC.07 clause *to confirm* | `Server.invite` ([`answer.go`](../internal/rcsas/sipas/answer.go)) and `Server.groupInvite` answer 403 to an offer with `a=file-selector` |
| Geolocation push | `partial` | No test shows the content passing through. | none | *to confirm* | Chat carries a CPIM body's content unchanged ([`internal/rcsas/messaging/doc.go`](../internal/rcsas/messaging/doc.go); `Engine.submitMessage`), so a push sent as chat content should go as any message does; no code reads one. `grep -rni geopush internal/ cmd/ tools/` finds the geopush IARI only in reference requests ([`internal/hss/reference.go`](../internal/hss/reference.go)), a comment in [`internal/scscf/routing/prefs.go`](../internal/scscf/routing/prefs.go), and iFC and caller-preferences tests. Whether a push needs more than this is *to confirm* |
| Audio messaging | `partial` | No test shows the content passing through. | none | *to confirm* | `ftserver` stores and serves a file of any declared media type (`declaredType`, [`internal/ftserver/form.go`](../internal/ftserver/form.go)), so an audio file uploads as any other does; nothing treats an audio message apart (`grep -rni audio internal/rcsas internal/ftserver` finds one SDP test fixture). Whether an audio message needs more than FT via HTTP is *to confirm* |
| Chatbot (MaaP) | `out of scope`: epic #668 |  | #668, #671 | *to confirm* | No chatbot service: `grep -rni -e chatbot -e isbot -e botversion internal/ cmd/ tools/` finds the chatbot IARI and bot tags only in reference requests ([`internal/hss/reference.go`](../internal/hss/reference.go)), a comment in [`internal/hss/defaultprofile.go`](../internal/hss/defaultprofile.go), and iFC, Cx and Sh tests; `hss` supports no wildcarded identity or PSI ([hss](hss.md#cx-behaviour)) |
| Multi-device | `partial` | A chat or large-mode session reaches only the first device to answer, and no code gives a user's other devices the messages of that session or the messages the user sent. | none | RFC 5626 §7, RFC 3841; RCC.07 clause *to confirm* | [`terminating.go`](../internal/scscf/routing/terminating.go) `onePerInstance` forks a terminating request to one flow of each device; `Server.Pager` reaches each device that registered `oma.cpm.msg`; [`invite.go`](../internal/rcsas/sipas/invite.go) `Server.dropFork` ends the session of every device but the first to answer |
| Message revocation | `absent` | A sender cannot revoke a message `rcs-as` still holds or has delivered. | none | *to confirm* | No code found: `grep -rni -e revoc -e revok internal/ cmd/ tools/` finds nothing |
| Image share and video share | `absent` | Nothing serves image share or video share: the core passes their requests on, or `rcs-as` refuses them. | none | RCC.07, clause *to confirm* | `otherService` in [`internal/hss/defaultprofile.go`](../internal/hss/defaultprofile.go) names their IARIs (`gsma-is`, `gsma-vs`), so trigger 10 does not take an MSRP INVITE that names either and no RCS service tag, and it goes past `rcs-as` to the callee. One whose Contact also carries an RCS tag, a chat tag or an RCS IARI, does take trigger 10 and reaches `rcs-as`, where `Server.invite` ([`answer.go`](../internal/rcsas/sipas/answer.go)) answers 403 (read from the code, not run end to end). No other code handles them, and no end-to-end test sets one up |
| Enriched Calling | `absent` | Nothing serves any Enriched Calling service. | none | *to confirm* | No Enriched Calling code: `grep -rni -e enriched -e callcomposer -e callunanswered -e sharedmap -e sharedsketch -e postcall -e gsma-is -e gsma-vs -e "image share" -e "video share" internal/ cmd/ tools/` finds test fixtures, a comment in [`internal/ifc/evaluate.go`](../internal/ifc/evaluate.go), and `otherService` in [`internal/hss/defaultprofile.go`](../internal/hss/defaultprofile.go), which sends image share and video share past `rcs-as` (their own row); `Server.invite` answers 403 to an INVITE that names no CPM chat or large-message service |
| IP voice and video calls | `absent` | The platform does not serve voice or video calls: it has no MMTEL application server and does not anchor RTP media. | none | *to confirm* | No MMTEL code: the default profile sends an MMTEL INVITE past `rcs-as` (`otherService`, [`defaultprofile.go`](../internal/hss/defaultprofile.go)); [`internal/pcscf/msrphooks.go`](../internal/pcscf/msrphooks.go) `anchorInitial` leaves an offer without MSRP lines alone, so the core passes a call's signalling on and serves nothing (`TestADialogWithoutMSRPGetsNone` passes an audio-only dialog through `pcscf`); no end-to-end test places a call |

## UP 2.4 → UP 4.0 gaps

No maintainer holds the UP 4.0 text. Each row cites a row of
[Public sources](spec-references.md#public-sources) by its bold short name.
No source that meets the evidence rule states every edition, clause and value
a row needs, so every row is *to confirm* (ADR 0008 §2) and `open`. A #667 row
needs an open issue to pass the exit rule (ADR 0008 §4); a #668 row does not
count for it.

### Named by GSMA for UP 4.0

This table lists every new feature that the **GSMA UP 4.0 article** and the
**GSMA RCS February 2026 publications page** name (ADR 0008 §4, third
condition).

| Item | Change from 2.4 | Source | Evidence | Progress | Epic | Issue |
|---|---|---|---|---|---|---|
| Messaging-initiated video calls | A user can turn a 1-to-1 or group conversation into a video call from inside it, with up to 32 participants per the February 2026 page (see IP voice and video calls). | **GSMA UP 4.0 article**, **GSMA RCS February 2026 publications page** | *to confirm* | `open` | #667 | to be filed (lead) |
| Late joining of a group video call | A group member who missed the start of a messaging-initiated video call can join it while it lasts. | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Video call log in the chat timeline | The records of messaging-initiated video calls are kept in step with the conversation they started from. | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Rich text | A sender can format the text of a message, as bold, italic or struck-through text for example, with defined fallbacks that keep it backward compatible. | **GSMA UP 4.0 article**, **GSMA RCS February 2026 publications page** | *to confirm* | `open` | #667 | to be filed (lead) |
| Plain-text review on SMS fallback | When a rich-text message has to go as SMS, the user is asked to review its plain-text form (see Chat-to-SMS interworking). | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Media format discovery | A device learns which audio, video and image formats its conversation partner supports, so that it picks the encoding of what it sends. | **GSMA UP 4.0 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Streaming video in rich cards | A business's rich card can embed video that streams instead of being downloaded whole. | **GSMA UP 4.0 article**, **GSMA RCS February 2026 publications page** | *to confirm* | `open` | #668 | none |
| Icons for suggested actions that open a URL | Suggested actions that open a URL get icons that are easier for users to recognise. | **GSMA RCS February 2026 publications page** | *to confirm* | `open` | #668 | none |
| Business control of how links open | A business can choose whether a link opens in a webview inside the messaging app, in a web browser, or in an app for it that the device has installed. | **GSMA UP 4.0 article**, **GSMA RCS February 2026 publications page** | *to confirm* | `open` | #668 | none |
| Deep links to businesses and their verification | Deep links to businesses and chatbots, business verification and information about chatbots more broadly are handled with less overhead and more robustly. | **GSMA UP 4.0 article**, **GSMA RCS February 2026 publications page** | *to confirm* | `open` | #668 | none |

### Named by GSMA for UP 3.0 and 3.1

GSMA states these for UP 3.0 or 3.1, not for 4.0; that UP 4.0 has each of
them is *to confirm*. Features GSMA names only for UP 4.1 are not listed: 4.1
is not a target (ADR 0008).

| Item | Change from 2.4 | Source | Evidence | Progress | Epic | Issue |
|---|---|---|---|---|---|---|
| End-to-end encryption | Messages and files between clients can be encrypted end to end with MLS, which GSMA names as the main change of UP 3.0. | **GSMA RCS encryption article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Audio messaging codecs | UP 3.0 improves the codecs of audio messages, and UP 3.1 adds xHE-AAC. | **GSMA RCS encryption article**, **GSMA UP 3.1 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Client connection to operator services | UP 3.1 changes how a client is onboarded and connects to operator services, using the push notification services of the device's operating system. | **GSMA UP 3.1 article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Richer deep links to businesses | UP 3.0 brings a richer format of deep link for reaching a business. | **GSMA RCS encryption article** | *to confirm* | `open` | #668 | none |
| Subscriptions to business senders | UP 3.0 makes it easier for a user to manage subscriptions to business messaging senders. | **GSMA RCS encryption article** | *to confirm* | `open` | #668 | none |

### Seen only in a lead

The **Wikipedia RCS article** names these for releases after 2.4. A
third-party lead confirms nothing and creates no obligation (ADR 0008 §3, §4);
each row records where to look. A GSMA source marked "supporting" names the
feature without stating a change, and confirms no more than the lead does.

| Item | Change from 2.4 | Source | Evidence | Progress | Epic | Issue |
|---|---|---|---|---|---|---|
| Message replies | A message can be sent as a reply to an earlier one (the lead names UP 2.7). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Reactions | A user can react to a message, with custom emoji (UP 2.7, improved in 3.0 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Editing and deleting messages | A sender can edit or delete a message it sent (UP 2.7 per the lead); compare Message revocation above. | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Spam handling and reporting | Spam handling improves and a user can report spam (UP 2.7 and 3.1 per the lead); the UP 4.1 article names spam and scam reporting as an existing capability, not a change. | **Wikipedia RCS article**, **GSMA UP 4.1 article** (supporting) | *to confirm* | `open` | #667 | to be filed (lead) |
| File transfer authentication and security | File transfer gains optional authentication procedures (UP 2.6 per the lead) and better security (UP 3.1 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Messaging verification | Something in messaging is verified more than in 2.4, but the lead does not say what (UP 2.5 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Deep links that start a conversation | A deep link can open a conversation (UP 3.1 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Encrypted video calls | Video calls from a conversation are encrypted end to end (UP 4.0 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #667 | to be filed (lead) |
| Chatbot features and verification | Chatbots gain features and a verification procedure, which the lead does not describe (UP 2.5 to 3.0 per the lead). | **Wikipedia RCS article** | *to confirm* | `open` | #668 | none |
