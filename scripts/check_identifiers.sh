#!/usr/bin/env bash
#
# Refuse any subscriber-identifier-shaped number that is not on the allow-list.
#
# A 15- or 16-digit literal is most likely an IMSI or IMEI, and a "+" followed by
# 10-15 digits is most likely an E.164 phone number. Both identify a subscriber and
# must never be committed. The allow-list is .github/allowed-test-identifiers.txt,
# which documents why each entry is safe. Every tracked file is scanned.
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

allowed="$(grep -oE '^\+?[0-9]{10,16}' "$ALLOWLIST" | sort -u)"

# git grep exits 1 when nothing matches; anything above 1 is a real failure. The
# scans run at top level (not in a command substitution) so `exit` really exits.
hits="$(mktemp)"
trap 'rm -f "$hits"' EXIT
for pattern in '\b[0-9]{15,16}\b' '\+[0-9]{10,15}\b'; do
  rc=0
  git grep -hIoE "$pattern" -- ':!.github/allowed-test-identifiers.txt' ':!go.sum' >>"$hits" || rc=$?
  if (( rc > 1 )); then
    echo "error: git grep failed ($rc)" >&2
    exit 2
  fi
done

found="$(grep -E '^\+?[0-9]+$' "$hits" | sort -u || true)"

if [[ -z "$found" ]]; then
  echo "no subscriber-shaped identifiers found"
  exit 0
fi

unexpected="$(comm -23 <(echo "$found") <(echo "$allowed"))"

if [[ -n "$unexpected" ]]; then
  echo "error: identifiers not on the allow-list:" >&2
  echo "$unexpected" >&2
  cat >&2 <<'HINT'

If these are test data, add them to .github/allowed-test-identifiers.txt with a
comment explaining why they are safe: IMSIs from MCC 001, phone numbers from the
fictional ranges listed there. If any of them is a real subscriber identifier,
remove it and rewrite history before pushing.
HINT
  exit 1
fi

count="$(echo "$found" | grep -c . || true)"
echo "all $count identifiers are on the allow-list"
