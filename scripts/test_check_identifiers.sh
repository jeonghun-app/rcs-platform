#!/usr/bin/env bash
#
# Self-test of check_identifiers.sh's alias rule (#714), run by `make privacy`:
# in a scratch repository, an alias written out in a tracked file fails the
# check in either case, and passes once its ID is on the allow-list. The test
# alias is assembled at run time, so this file holds none for the real scan.
#
set -euo pipefail

check="$(dirname "${BASH_SOURCE[0]}")/check_identifiers.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The scratch repository is this test's own, whichever repository runs it.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
git -c init.defaultBranch=main init -q "$work"
mkdir "$work/scripts" "$work/.github"
cp "$check" "$work/scripts/check_identifiers.sh"
allowlist="$work/.github/allowed-test-identifiers.txt"
printf '# test\n+15550100001\n' >"$allowlist"

id="planted""aliasselftest23456a"
alias="sip:${id}@alias.example.net;user=rcstk"
# An alias ID can be all digits; its first 16 read as an IMEI-shaped number.
digit_id=23456723456723456723456723

# expect <exit status> <description> [<line the output must hold>]: runs the
# check on what is tracked now; a failure must name the identifier, $id unless
# another is given.
expect() {
  local rc=0 out
  git -C "$work" add -A
  out="$(bash "$work/scripts/check_identifiers.sh" 2>&1)" || rc=$?
  if (( rc != $1 )); then
    echo "FAIL: $2: exit $rc, want $1" >&2
    echo "$out" >&2
    exit 1
  fi
  if (( $1 == 1 )) && ! grep -qx -- "${3:-$id}" <<<"$out"; then
    echo "FAIL: $2: the output does not name ${3:-$id}" >&2
    echo "$out" >&2
    exit 1
  fi
  echo "ok: $2"
}

# Each case replaces what the one before planted.
planted="$work/planted.txt"
expect 0 "no alias passes"
printf 'To: <%s>;tag=1\n' "$alias" >"$planted"
expect 1 "a planted alias fails"
printf '{"to":"%s"}\n' "${alias^^}" >"$planted"
expect 1 "a planted upper-case alias fails"
printf 'sip:%s@alias.example.net;user=rcstk,%s\n' "$digit_id" "$alias" >"$planted"
expect 1 "the second alias in a list fails"
printf '%s\n%s\n' "${alias^^}" "sip:${digit_id}@alias.example.net;user=rcstk,$alias" >"$planted"
printf '# made up for this test\n%s\n%s\n' "$id" "$digit_id" >>"$allowlist"
expect 0 "allow-listed aliases pass in either case"
printf '%s\n' "${digit_id:0:16}" >"$planted"
expect 1 "an alias ID made of digits allows no number" "${digit_id:0:16}"
