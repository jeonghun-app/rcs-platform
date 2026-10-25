# ADR 0008 — The target profile moves to UP 4.0 in stages, on public sources

**Status:** accepted

## Context

The platform targets RCS Universal Profile 2.4 (`docs/spec-references.md`), the
profile `acs` provisions by default, and parts of 2.4 are not built yet. GSMA
announced UP 4.0 as finalised in March 2026 and has since published UP 4.1
(*GSMA UP 4.0 article*, *GSMA UP 4.1 article* in the Public sources table of
[spec-references.md](../spec-references.md#public-sources)). The product owner
decided on 2026-10-25 to move the target to UP 4.0 (epic #667).

No maintainer holds the UP 4.0 text. Public pages name its features but not its
clauses, values or document editions. Moving the target in one step would mix
finishing 2.4 with adding 4.0 and would claim a profile the code does not meet;
once code and docs cite 4.0, that claim is costly to take back.

## Decision

1. The move happens in four stages, in this order:
   0. **ADR and gap table:** this ADR, and the UP 2.4 status and the 2.4 → 4.0
      gap table in `docs/conformance.md` (#670).
   1. **Finish UP 2.4:** one issue per UP 2.4 row that is not implemented.
   2. **Close the 2.4 → 4.0 gaps:** one issue per gap row.
   3. **Switch the target:** `docs/spec-references.md` names UP 4.0 as the
      target profile.

   UP 2.4 stays the target in force until the stage 3 change merges. Before
   then nothing is described as UP 4.0 conformant; stage 2 work names the gap
   row it closes.
2. **Evidence rule.** An item (a feature, behaviour, document edition, clause
   number or value) may be called UP 4.0 behaviour, and marked *confirmed*, only
   when a cited public source states it. The citation names a row of the Public
   sources table, which gives the source's title, publisher, URL and date read.
   The source must state the item itself: GSMA for the content or edition of a
   GSMA document, an implementation's own code or documentation for what that
   implementation does. A third-party summary (an encyclopedia, the press) says
   where to look and confirms nothing. Every other item is *to confirm*. No
   clause number, edition or value is written from memory or inferred, for
   example from how earlier editions were numbered. GSMA text is never quoted
   (`docs/architecture.md` §9); a source is summarised in our own words.
3. **Exit rule.** The stage 3 change may merge only when, in
   `docs/conformance.md`:
   - every UP 2.4 row is *implemented*, or *out of scope* with the reason in the
     row; and
   - every 2.4 → 4.0 gap row is *closed*, *out of scope* with the reason in the
     row, or *to confirm* with a link to an open issue.

   A row in any other state blocks stage 3.

## Rationale

Finishing 2.4 first keeps the repository's claim true at every merge: the
profile named as the target is the one the code is held to, and 4.0 work shows
up as gap rows, not as a partial claim. A public feature list is enough to plan
a gap but not to choose a header, a value or a clause, so those stay
*to confirm* instead of being guessed and later cited as fact. Third-party
summaries are not evidence because they state more than GSMA does: the
*Wikipedia RCS article* gives UP 4.0 a release month and an RCC.07 version, and
the *GSMA UP 4.0 article*, which announced the finalisation later, states
neither. Letting a *to confirm* row pass the exit rule with an open issue keeps
stage 3 from waiting on text nobody holds, while each unknown stays visible and
owned.

## Consequences

- `acs` keeps provisioning UP 2.4 until stage 3; nothing changes in
  [auto-configuration-server](https://github.com/jeonghun-app/auto-configuration-server)
  before then. The stage 3 change there is an issue in that repository, linked
  from the stage 3 issue here, and reaches the platform as a pinned `acs`
  release (ADR 0006).
- A pull request that calls something UP 4.0 is reviewed against the evidence
  rule; a 4.0 edition, clause or value without a Public sources row is a
  finding.
- `docs/spec-references.md` gains a Public sources table. Later issues cite its
  rows by name; a source that could not be opened is not listed.
- UP 4.0 MaaP and chatbot items are decided in ADR 0009 (#671), not in this gap
  table.
- UP 4.1 is not a target. Moving past 4.0 needs a new ADR.
