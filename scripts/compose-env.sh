#!/bin/sh
# Writes the local compose stack's env file (default deploy/compose.env) from
# deploy/compose.env.example, with every secret filled in with fresh random
# bytes: 256 bits each, which ADR 0007 §4 asks of the service tokens.
#
# An existing file is kept as it is, so make up can run this every time;
# pass -f to write a new one. The file is created readable by its owner
# only, and git and docker builds ignore it.
#
# usage: scripts/compose-env.sh [-f] [file]
set -eu

force=0
if [ "${1:-}" = "-f" ]; then
	force=1
	shift
fi
out=${1:-deploy/compose.env}
example=$(dirname "$0")/../deploy/compose.env.example

if [ -e "$out" ] && [ "$force" -eq 0 ]; then
	echo "$out exists; keeping it (scripts/compose-env.sh -f writes a new one)"
	exit 0
fi

# hex64 prints 32 random bytes as 64 hex digits; b64 as base64 (the HSS data
# key). od and base64 are in busybox and coreutils alike.
hex64() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
b64() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }

tmp="$out.tmp.$$"
trap 'rm -f "$tmp"' EXIT
umask 077
while IFS= read -r line || [ -n "$line" ]; do
	case "$line" in
	HSS_DATA_KEY=) printf 'HSS_DATA_KEY=%s\n' "$(b64)" ;;
	HSS_ADMIN_TOKEN= | HSS_ACS_TOKEN= | HSS_FT_TOKEN= | RELAY_PCSCF_TOKEN= | ACS_ADMIN_TOKEN= | FT_NONCE_KEY= | RCS_PII_HMAC_KEY=)
		printf '%s%s\n' "$line" "$(hex64)" ;;
	*) printf '%s\n' "$line" ;;
	esac
done <"$example" >"$tmp"

# Every secret line of the example must have been filled: a line left empty
# would start a service without its token.
if grep -Eq '^[A-Z_]+(TOKEN|KEY)=$' "$tmp"; then
	echo "compose-env: a secret in $example has no generator here" >&2
	exit 1
fi
mv "$tmp" "$out"
trap - EXIT
echo "wrote $out with new secrets"
