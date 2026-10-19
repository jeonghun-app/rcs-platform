#!/bin/sh
# Writes the local compose stack's env file (default deploy/compose.env) from
# deploy/compose.env.example, with every secret filled in with fresh random
# bytes: 256 bits each, which ADR 0007 §4 asks of the service tokens.
#
# An existing file keeps its values, so make up can run this every time.
# Settings the example has and the file lacks, added by a later change, are
# appended, secrets freshly generated. Pass -f to write a new file. The file
# is readable by its owner only, and git and docker builds ignore it.
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

# hex64 prints 32 random bytes as 64 hex digits; b64 as base64 (the HSS data
# key). od and base64 are in busybox and coreutils alike.
hex64() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
b64() { head -c 32 /dev/urandom | base64 | tr -d '\n'; }

# fill prints an example line with its secret, if it is one, filled in.
fill() {
	case "$1" in
	HSS_DATA_KEY=) printf 'HSS_DATA_KEY=%s\n' "$(b64)" ;;
	HSS_ADMIN_TOKEN= | HSS_ACS_TOKEN= | HSS_FT_TOKEN= | RELAY_PCSCF_TOKEN= | ACS_ADMIN_TOKEN= | FT_NONCE_KEY= | RCS_PII_HMAC_KEY=)
		printf '%s%s\n' "$1" "$(hex64)" ;;
	*) printf '%s\n' "$1" ;;
	esac
}

# require_secrets fails when a secret in file is still empty: a service would
# start without its token.
require_secrets() {
	if grep -Eq '^[A-Z_]+(TOKEN|KEY)=$' "$1"; then
		echo "compose-env: $1 has an empty secret ($(grep -Eo '^[A-Z_]+(TOKEN|KEY)=$' "$1" | tr -d = | tr '\n' ' '))" >&2
		echo "compose-env: fill it in, or write a new file with scripts/compose-env.sh -f" >&2
		exit 1
	fi
}

umask 077
if [ -e "$out" ] && [ "$force" -eq 0 ]; then
	added=
	# An edited file may end without a newline; the next line would join it.
	if [ -s "$out" ] && [ -n "$(tail -c 1 "$out")" ]; then
		echo >>"$out"
	fi
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		[A-Z]*=*)
			key=${line%%=*}
			if ! grep -q "^$key=" "$out"; then
				fill "$line" >>"$out"
				added="$added $key"
			fi
			;;
		esac
	done <"$example"
	require_secrets "$out"
	if [ -n "$added" ]; then
		echo "$out: added$added; run make up to restart the services with them"
	else
		echo "$out exists; keeping it (scripts/compose-env.sh -f writes a new one)"
	fi
	exit 0
fi

tmp="$out.tmp.$$"
trap 'rm -f "$tmp"' EXIT
while IFS= read -r line || [ -n "$line" ]; do
	fill "$line"
done <"$example" >"$tmp"
# Every secret line of the example must have been filled.
if grep -Eq '^[A-Z_]+(TOKEN|KEY)=$' "$tmp"; then
	echo "compose-env: a secret in $example has no generator here" >&2
	exit 1
fi
mv "$tmp" "$out"
trap - EXIT
echo "wrote $out with new secrets"
