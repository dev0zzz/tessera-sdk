#!/usr/bin/env bash
# Sync the CANONICAL at.tessera.* lexicons into the atproto fork, which
# needs them at build time for codegen + server-side record validation.
# Usage: scripts/sync-lexicons.sh [path-to-atproto-repo] [--force]
#
# The sync is one-way and uses --delete, so a lexicon that was extended in the
# fork but never backported here would be silently reverted. That happened once
# (abandonWallet on removeDevice), so anything beyond adding new files now needs
# an explicit --force.
set -euo pipefail

ATPROTO="${1:-$HOME/src/repos/atproto}"
FORCE="${2:-}"
if [ "$ATPROTO" = "--force" ]; then
  ATPROTO="$HOME/src/repos/atproto"
  FORCE="--force"
fi

SRC="$(cd "$(dirname "$0")/../lexicons/at/tessera" && pwd)"
DST="$ATPROTO/lexicons/at/tessera"
mkdir -p "$DST"

# Itemized dry run: '>f' with a 'c' or 's' flag means an existing file changes,
# '*deleting' means one disappears. Newly added files show as '>f+++++++++'.
changes=$(rsync -ai --delete --dry-run "$SRC/" "$DST/" \
  | grep -Ev '^>f\+\+\+\+\+\+\+\+\+|^\.d|^cd\+\+\+\+\+\+\+\+\+' || true)

if [ -n "$changes" ] && [ "$FORCE" != "--force" ]; then
  echo "REFUSING TO SYNC: this would change or delete lexicons in the fork." >&2
  echo >&2
  echo "$changes" >&2
  echo >&2
  echo "The fork may hold changes that were never backported here. Check with:" >&2
  echo "  diff -ru $SRC $DST" >&2
  echo >&2
  echo "Backport them into this repo first, or re-run with --force if the" >&2
  echo "overwrite is genuinely intended." >&2
  exit 1
fi

rsync -a --delete "$SRC/" "$DST/"
echo "synced $(find "$SRC" -name '*.json' | wc -l) lexicons -> $DST"
echo "now run: cd $ATPROTO/packages/pds && pnpm run codegen:lex"
