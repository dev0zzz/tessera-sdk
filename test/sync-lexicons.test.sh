#!/usr/bin/env bash
# Verifies sync-lexicons.sh refuses to silently overwrite or delete lexicons
# that exist in the fork. Uses temp dirs, never touches a real checkout.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/scripts/sync-lexicons.sh"
FAILED=0

check() { # check <name> <expected-exit> <actual-exit>
  if [ "$2" = "$3" ]; then echo "ok - $1"; else echo "FAIL - $1 (expected exit $2, got $3)"; FAILED=1; fi
}

# A fake fork whose lexicon is AHEAD of the SDK: the dangerous case.
fake_fork=$(mktemp -d)
mkdir -p "$fake_fork/lexicons/at/tessera/passkey"
echo '{"id":"x","param":"newer"}' > "$fake_fork/lexicons/at/tessera/passkey/removeDevice.json"

set +e
"$SCRIPT" "$fake_fork" >/dev/null 2>&1
check "aborts when the sync would modify or delete a fork lexicon" 1 $?

"$SCRIPT" "$fake_fork" --force >/dev/null 2>&1
check "proceeds with --force" 0 $?
set -e

# A fake fork that is simply empty: adding files is the normal, safe case.
empty_fork=$(mktemp -d)
set +e
"$SCRIPT" "$empty_fork" >/dev/null 2>&1
check "proceeds without --force when it only adds files" 0 $?
set -e

rm -rf "$fake_fork" "$empty_fork"
exit $FAILED
