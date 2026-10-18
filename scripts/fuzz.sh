#!/bin/sh
# Run every Fuzz* target in the module for $FUZZTIME each (Go allows one fuzz
# target per invocation, hence the loop). Runs inside the toolchain container.
#
# Go 1.26's fuzz coordinator occasionally reports its own -fuzztime expiry as
# "context deadline exceeded" and fails the run although no input failed (#29).
# That case is recognised only by the coordinator's own line (four spaces, then
# exactly that text) together with: no "Failing input written to", no failing
# seed corpus entry (those write nothing new), and no new file in testdata/fuzz
# (a crasher found during minimisation is written without the message). It is
# reported as a GitHub Actions warning and treated as a pass; anything else
# fails. A hung target is not detected by Go either way (#30).
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
    if grep -qx '    context deadline exceeded' "$log" &&
       ! grep -q 'Failing input written to' "$log" &&
       ! grep -q 'failure while testing seed corpus entry' "$log" &&
       [ "$before" -eq "$after" ]; then
      echo "::warning title=fuzz deadline race::$pkg $f failed only with the coordinator deadline (#29); treated as pass"
      continue
    fi
    status=1
  done
done
exit "$status"
