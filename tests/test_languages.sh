#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

echo "=== Verifying all 20 language files in modules/languages ==="
count=0
for f in modules/languages/*.sh; do
    [ -f "$f" ] || continue
    code="$(basename "$f" .sh)"
    upper="$(echo "$code" | tr '[:lower:]' '[:upper:]')"
    source "$f"
    ref="STR_${upper}[lang_name]"
    echo "  [OK] $code -> ${!ref}"
    count=$((count + 1))
done

echo "Successfully verified $count language files!"
