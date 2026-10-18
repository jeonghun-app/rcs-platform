#!/bin/sh
# Run every Fuzz* target in the module for $FUZZTIME each (Go allows one fuzz
# target per invocation, hence the loop). Runs inside the toolchain container.
#
# Go 1.26's fuzz coordinator occasionally reports its own -fuzztime expiry as
# "context deadline exceeded" and fails the run although no input failed (#29).
# A real failure always prints "Failing input written to" and leaves a file in
# testdata/fuzz, so a run that fails with only the deadline message and no new
# corpus entry is reported and treated as a pass. Anything else fails.
set -eu

: "${FUZZTIME:=10s}"
status=0
log=$(mktemp)
trap 'rm -f "$log"' EXIT

for pkg in $(go list ./...); do
  for f in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
    echo "== $pkg $f"
    dir=$(go list -f '{{.Dir}}' "$pkg")/testdata/fuzz/$f
    before=$(ls "$dir" 2>/dev/null | wc -l)
    if go test "$pkg" -run '^$' -fuzz "^$f\$" -fuzztime "$FUZZTIME" >"$log" 2>&1; then
      cat "$log"
      continue
    fi
    cat "$log"
    after=$(ls "$dir" 2>/dev/null | wc -l)
    if grep -q 'context deadline exceeded' "$log" &&
       ! grep -q 'Failing input written to' "$log" &&
       [ "$before" -eq "$after" ]; then
      echo "warning: $f: coordinator deadline race (#29), no failing input; treated as pass"
      continue
    fi
    status=1
  done
done
exit "$status"
