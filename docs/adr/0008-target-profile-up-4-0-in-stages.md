# ADR 0008 — The target profile moves to UP 4.0 in stages, on public sources

**Status:** accepted

## Context

The platform targets RCS Universal Profile 2.4 (`docs/spec-references.md`), the
profile `acs` provisions by default, and parts of 2.4 are not built yet. In an
article dated 2026-03-26, GSMA announced the finalisation of UP 4.0; it
announced UP 4.1 in an article dated 2026-07-28 (**GSMA UP 4.0 article**,
**GSMA UP 4.1 article** in
[Public sources](../spec-references.md#public-sources)). On 2026-10-25 the
product owner chose UP 4.0 as the next target (epic #667).

No maintainer holds the UP 4.0 text. Public pages name its features but not its
clauses, values or document editions. Moving the target in one step would mix
finishing 2.4 with adding 4.0 and would claim a profile the code does not meet;
once code and docs cite 4.0, that claim is costly to take back.

## Decision

1. The move happens in four stages, one after another:

   0. **ADR and gap table:** this ADR, and the **UP 2.4 status** and
      **UP 2.4 → UP 4.0 gaps** sections of `docs/conformance.md` (#670).
   1. **Finish UP 2.4:** one issue per **UP 2.4 status** row that is not
      `implemented` or `out of scope`.
   2. **Close the 2.4 → 4.0 gaps:** one issue per gap row tagged #667 that is
      not `out of scope`.
   3. **Switch the target:** `docs/spec-references.md` names UP 4.0 as the
      target profile.

   A stage starts when the one before it is done; stage 2 starts when the first
   condition of the exit rule holds. UP 2.4 stays the target in force until the
   stage 3 change merges. Before then nothing is described as UP 4.0
   conformant; stage 2 work names the gap row it closes.
2. **Row states.** Rows of `docs/conformance.md` carry two separate states
   and, on gap rows, an epic tag, written only with these words:
   - **Evidence** (rule 3), for an item or a reference: *confirmed* or
     *to confirm*. A gap row is *confirmed* only when a source that meets
     rule 3 states the feature and every edition, clause or value the change
     needs; otherwise it is *to confirm*.
   - **Progress.** A **UP 2.4 status** row is `implemented`, `partial`,
     `absent` or `out of scope`. A **UP 2.4 → UP 4.0 gaps** row is `open`,
     `closed` or `out of scope`. `closed` means the change is merged and the row
     names its pull request. An issue closed without a merged change leaves the
     row `open`. A gap row may be `closed` only when its evidence is
     *confirmed*: a *to confirm* row does not count as done, even when code
     exists, and stays `open` with an issue to confirm the item. An
     `out of scope` row gives its reason in the row.
   - **Epic** (gap rows): #667, or #668 when the feature exists only in a
     conversation with a chatbot (business messaging, rich cards, chatbot
     verification and branding); the lead decides edge cases in review. A
     **UP 2.4 status** row for MaaP or chatbots is `out of scope` with the
     reason "epic #668", so it blocks neither stage 1 nor the exit rule.

   "Unverified" is a note, not a state. It says that a row relies on an edition
   marked *to confirm*, and it does not block stage 3. Nobody holds the text, so
   a rule that waited for it could never clear.
3. **Evidence rule.** An item (a feature, behaviour, document edition, clause
   number or value) is *to confirm* unless a copy held by a maintainer, or a
   public source that meets this rule, establishes it. For UP 4.0 no copy is
   held, so an item may be called UP 4.0 behaviour, and marked *confirmed*,
   only when a cited public source states it. The citation names a row of the
   Public sources table, which gives the source's title, publisher, URL and
   date read. The source must state the item itself: GSMA for the content or
   edition of a GSMA document, an implementation's own code or documentation
   for what that implementation does. A third-party summary (an encyclopedia,
   the press) says where to look and confirms nothing. No clause number,
   edition or value is written from memory or inferred, for example from how
   earlier editions were numbered. GSMA text is never quoted
   (`docs/architecture.md` §9); a source is summarised in our own words.
4. **Exit rule.** The stage 3 change may merge only when, in
   `docs/conformance.md`:
   - every **UP 2.4 status** row is `implemented`, or `out of scope` with its
     reason;
   - every gap row tagged #667 is `closed` (which needs *confirmed*, §2),
     `out of scope` with its reason, or `open` and *to confirm* with a link to
     an open issue; and
   - every UP 4.0 feature stated by a Public sources row that meets the
     evidence rule has a gap row, tagged #667 or #668. Third-party leads
     create no obligation; a feature seen only in a lead may be added as a
     *to confirm* row.

   Gap rows tagged #668 (MaaP and chatbots) may be listed but do not count for
   the second condition: epic #667 puts MaaP out of scope, and
   [ADR 0009](0009-maap-chatbot-platform.md) and epic #668 decide them. A row
   in any other state blocks stage 3.

## Rationale

Finishing 2.4 first keeps the repository's claim true at every merge: the
profile named as the target is the one the code is held to, and 4.0 work shows
up as gap rows, not as a partial claim. A public feature list is enough to plan
a gap but not to choose a header, a value or a clause, so those stay
*to confirm* instead of being guessed and later cited as fact. A third-party
summary is not the publisher of what it reports, so it cannot confirm it: on
2026-10-25 the **Wikipedia RCS article** gave UP 4.0 a release month and an
RCC.07 version that the **GSMA UP 4.0 article** does not state. Letting an
`open`, *to confirm* row pass the exit rule with an open issue keeps stage 3
from waiting on text nobody holds, while each unknown stays visible and owned.
The completeness condition stops a feature that a source meeting the evidence
rule names from passing stage 3 by having no row.

## Consequences

- `acs` keeps provisioning UP 2.4 until stage 3; nothing changes in
  [auto-configuration-server](https://github.com/jeonghun-app/auto-configuration-server)
  before then. The stage 3 change there is an issue in that repository, linked
  from the stage 3 issue here, and reaches the platform as a pinned `acs`
  release (ADR 0006). (Amended in #671: provisioning changes MaaP needs are
  tracked in #668; the profile `acs` provisions stays 2.4 until stage 3.)
- With public sources only, most #667 gap rows are expected to reach stage 3
  as `open` and *to confirm*, each with an open issue to confirm it: public
  pages name features, not the editions, clauses and values a change needs.
  That is the product owner's decision (no UP 4.0 text) applied as written.
- A pull request that calls something UP 4.0 is reviewed against the evidence
  rule; a 4.0 edition, clause or value that does not meet it is a finding.
- Later issues cite Public sources rows by their bold short name.
- UP 4.1 is not a target; the product owner chose 4.0 (epic #667).
- Revisit this ADR when a maintainer obtains the UP 4.0 text, or when the
  product owner moves the target past 4.0.
