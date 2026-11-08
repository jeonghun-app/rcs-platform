#!/usr/bin/env bash
#
# Self-test of check_identifiers.sh's alias rules (#714, #719), run by `make
# privacy`: in a scratch repository, an alias or a standalone alias ID written
# out in a tracked file fails the check, and passes once its ID is on the
# allow-list. The test values are assembled at run time, so this file holds
# none for the real scan.
# It runs on bash 3.2, the macOS default, so it uses no bash 4 expansion.
#
set -euo pipefail

check="$(dirname "${BASH_SOURCE[0]}")/check_identifiers.sh"
work="$(mktemp -d)"
# Pass only when the last case was reached. bash 3.2 runs the EXIT trap with
# $? = 0 after an expansion error (a bad substitution), so the status alone
# would turn a run that stopped early into a pass.
finished=no
cleanup() {
  local status=$?
  rm -rf "$work"
  if (( status == 0 )) && [[ $finished != yes ]]; then
    echo "FAIL: the self-test stopped before its last case" >&2
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

# The scratch repository is this test's own, whichever repository runs it.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
git -c init.defaultBranch=main init -q "$work"
mkdir "$work/scripts" "$work/.github"
cp "$check" "$work/scripts/check_identifiers.sh"
allowlist="$work/.github/allowed-test-identifiers.txt"
printf '# test\n+15550100001\n' >"$allowlist"

id="planted""aliasselftest23456a"
alias="sip:${id}@alias.example.net;user=rcstk"
upper_alias="$(printf '%s' "$alias" | tr '[:lower:]' '[:upper:]')"
upper_id="$(printf '%s' "$id" | tr '[:lower:]' '[:upper:]')"
# Mixed case is only caught in the alias form.
mixed_id="P${id:1}"
# An alias ID can be all digits; its first 16 read as an IMEI-shaped number.
digit_id="234567234567234567234567""23"

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
printf '{"to":"%s"}\n' "$upper_alias" >"$planted"
expect 1 "a planted upper-case alias fails"
printf 'sip:%s@alias.example.net;user=rcstk\n' "$mixed_id" >"$planted"
expect 1 "a planted mixed-case alias fails"
printf 'sip:%s@alias.example.net;user=rcstk,sip:%s@alias.example.net;user=rcstk\n' "$digit_id" "$mixed_id" >"$planted"
expect 1 "the second alias in a list fails"
printf 'no alias %s here\n' "$id" >"$planted"
expect 1 "a standalone alias ID fails"
printf '{"to":"%s"}\n' "$id" >"$planted"
expect 1 "an alias ID in JSON fails"
printf 'POST /v1/conversations/%s/messages\n' "$upper_id" >"$planted"
expect 1 "an upper-case alias ID in a path fails"
printf 'sip%%3A%s%%40alias.example.net%%3Buser%%3Drcstk\n' "$id" >"$planted"
expect 1 "a percent-encoded alias fails"
printf 'sip:%s@alias.example.net\n' "$id" >"$planted"
expect 1 "an alias without user=rcstk fails"
# Just outside the form.
printf '%s %sa %s x%s\n' "${id:0:25}" "$id" "$mixed_id" "$id" >"$planted"
expect 0 "25 and 27 characters, mixed case and a joined word pass"
printf '%s\n' "$upper_alias" "sip:${digit_id}@alias.example.net;user=rcstk,$alias" \
  "sip:$mixed_id@alias.example.net;user=rcstk" "{\"to\":\"$id\"} $upper_id" \
  "sip%3A$id%40alias.example.net" >"$planted"
printf '# made up for this test\n%s\n%s\n' "$id" "$digit_id" >>"$allowlist"
expect 0 "allow-listed aliases and alias IDs pass in every form"
printf '%s\n' "${digit_id:0:16}" >"$planted"
expect 1 "an alias ID made of digits allows no number" "${digit_id:0:16}"
finished=yes
