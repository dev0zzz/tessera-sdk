#!/usr/bin/env bash
# Sync the CANONICAL at.tessera.* lexicons into the atproto fork, which
# needs them at build time for codegen + server-side record validation.
# Usage: scripts/sync-lexicons.sh [path-to-atproto-repo]
set -euo pipefail
ATPROTO="${1:-$HOME/src/repos/atproto}"
SRC="$(cd "$(dirname "$0")/../lexicons/at/tessera" && pwd)"
DST="$ATPROTO/lexicons/at/tessera"
mkdir -p "$DST"
rsync -a --delete "$SRC/" "$DST/"
echo "synced $(find "$SRC" -name '*.json' | wc -l) lexicons -> $DST"
echo "now run: cd $ATPROTO/packages/pds && pnpm run codegen:lex"
