#!/usr/bin/env bash
#
# Refuse any 15- or 16-digit identifier that is not on the allow-list.
#
# A 15-digit literal in this repository is most likely an IMSI, and an IMSI is
# subscriber-identifying data that must never be committed. The allow-list is
# .github/allowed-test-identifiers.txt, which documents why each entry is safe.
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

ALLOWLIST=".github/allowed-test-identifiers.txt"
if [[ ! -f "$ALLOWLIST" ]]; then
  echo "error: $ALLOWLIST is missing" >&2
  exit 1
fi

allowed="$(grep -oE '^[0-9]{14,16}' "$ALLOWLIST" | sort -u)"

found="$(git grep -hIoE '\b[0-9]{15,16}\b' -- \
  'cmd' 'internal' 'tools' 'scripts' 'docs' 'infra' 'deploy' '*.go' '*.md' '*.yml' '*.yaml' '*.json' \
  ':!.github/allowed-test-identifiers.txt' 2>/dev/null | sort -u || true)"

if [[ -z "$found" ]]; then
  echo "no long numeric identifiers found"
  exit 0
fi

unexpected="$(comm -23 <(echo "$found") <(echo "$allowed"))"

if [[ -n "$unexpected" ]]; then
  echo "error: identifiers not on the allow-list:" >&2
  echo "$unexpected" >&2
  cat >&2 <<'HINT'

If these are test data, add them to .github/allowed-test-identifiers.txt with a
comment explaining why they are safe. Prefer MCC 001 (the reserved test network).
If any of them is a real subscriber identifier, remove it — and rewrite history
before pushing.
HINT
  exit 1
fi

count="$(echo "$found" | grep -c . || true)"
echo "all $count long identifiers are on the allow-list"
