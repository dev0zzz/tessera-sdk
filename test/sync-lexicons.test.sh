#!/usr/bin/env bash
# Verifies sync-lexicons.sh refuses to silently overwrite or delete lexicons
# that exist in the fork. Uses temp dirs, never touches a real checkout.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/scripts/sync-lexicons.sh"
FAILED=0

check() { # check <name> <expected-exit> <actual-exit>
  if [ "$2" = "$3" ]; then echo "ok - $1"; else echo "FAIL - $1 (expected exit $2, got $3)"; FAILED=1; fi
}

# MODIFY case: the fork holds a lexicon that ALSO exists in the SDK but differs
# (the real abandonWallet/removeDevice regression). The sync would overwrite it.
modify_fork=$(mktemp -d)
mkdir -p "$modify_fork/lexicons/at/tessera/passkey"
echo '{"id":"x","param":"newer"}' > "$modify_fork/lexicons/at/tessera/passkey/removeDevice.json"

set +e
"$SCRIPT" "$modify_fork" >/dev/null 2>&1
check "aborts when the sync would MODIFY a fork lexicon in place" 1 $?

"$SCRIPT" "$modify_fork" --force >/dev/null 2>&1
check "proceeds with --force" 0 $?
set -e

# DELETE case: the fork holds a lexicon that does NOT exist in the SDK. With
# rsync --delete the sync would remove it — must also abort without --force.
delete_fork=$(mktemp -d)
mkdir -p "$delete_fork/lexicons/at/tessera/ghost"
echo '{"id":"at.tessera.ghost.only"}' > "$delete_fork/lexicons/at/tessera/ghost/only.json"

set +e
"$SCRIPT" "$delete_fork" >/dev/null 2>&1
check "aborts when the sync would DELETE a fork-only lexicon" 1 $?
set -e

# A fake fork that is simply empty: adding files is the normal, safe case.
empty_fork=$(mktemp -d)
set +e
"$SCRIPT" "$empty_fork" >/dev/null 2>&1
check "proceeds without --force when it only adds files" 0 $?
set -e

rm -rf "$modify_fork" "$delete_fork" "$empty_fork"
exit $FAILED
