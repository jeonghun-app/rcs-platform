#!/usr/bin/env bash
#
# Refuse any subscriber-identifier-shaped number that is not on the allow-list.
#
# A 15- or 16-digit literal is most likely an IMSI or IMEI, and a "+" followed by
# 10-15 digits is most likely an E.164 phone number. Both identify a subscriber and
# must never be committed. So does a maap alias, sip:<alias-id>@<host>;user=rcstk
# with a 26-character base32 alias ID (ADR 0009 §10), which maap maps back to one
# subscriber; it is allowed by its ID. The allow-list is
# .github/allowed-test-identifiers.txt, which documents why each entry is safe.
# Every tracked file is scanned.
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: not a git work tree; the check scans tracked files and cannot run" >&2
  exit 2
fi

ALLOWLIST=".github/allowed-test-identifiers.txt"
if [[ ! -f "$ALLOWLIST" ]]; then
  echo "error: $ALLOWLIST is missing" >&2
  exit 2
fi

# Whole lines only, so that an alias ID made of digits allows no number.
allowed="$(grep -oE '^\+?[0-9]{10,16}$' "$ALLOWLIST" | sort -u || true)"
allowed_aliases="$(grep -E '^[a-z2-7]{26}$' "$ALLOWLIST" | sort -u || true)"

# git grep exits 1 when nothing matches; anything above 1 is a real failure. The
# scans run at top level (not in a command substitution) so `exit` really exits.
hits="$(mktemp)"
alias_hits="$(mktemp)"
trap 'rm -f "$hits" "$alias_hits"' EXIT
for pattern in '\b[0-9]{15,16}\b' '\+[0-9]{10,15}\b'; do
  rc=0
  git grep -hIoE "$pattern" -- ':!.github/allowed-test-identifiers.txt' ':!go.sum' >>"$hits" || rc=$?
  if (( rc > 1 )); then
    echo "error: git grep failed ($rc)" >&2
    exit 2
  fi
done
# An alias in either case: base32 reads both alike (RFC 4648 §6). A host and its
# parameters hold no "@" or "," (RFC 3261 §25.1), so two aliases in a list are
# two hits.
rc=0
git grep -hIoiE 'sips?:[a-z2-7]{26}@[^[:space:]<>"@,]*;user=rcstk' -- ':!.github/allowed-test-identifiers.txt' ':!go.sum' >"$alias_hits" || rc=$?
if (( rc > 1 )); then
  echo "error: git grep failed ($rc)" >&2
  exit 2
fi

found="$(grep -E '^\+?[0-9]+$' "$hits" | sort -u || true)"
found_aliases="$(sed -E 's/^[^:]*:([^@]*)@.*$/\1/' "$alias_hits" | tr '[:upper:]' '[:lower:]' | sort -u)"

if [[ -z "$found$found_aliases" ]]; then
  echo "no subscriber-shaped identifiers found"
  exit 0
fi

unexpected="$( {
  comm -23 <(echo "$found") <(echo "$allowed")
  comm -23 <(echo "$found_aliases") <(echo "$allowed_aliases")
} | grep . || true)"

if [[ -n "$unexpected" ]]; then
  echo "error: identifiers not on the allow-list:" >&2
  echo "$unexpected" >&2
  cat >&2 <<'HINT'

If these are test data, add them to .github/allowed-test-identifiers.txt with a
comment explaining why they are safe: IMSIs from MCC 001, phone numbers from the
fictional ranges listed there, alias IDs made up for the test (the ID alone, in
lower case). If any of them is a real subscriber identifier or alias,
remove it and rewrite history before pushing.
HINT
  exit 1
fi

count="$(printf '%s\n%s\n' "$found" "$found_aliases" | grep -c . || true)"
echo "all $count identifiers are on the allow-list"
