#!/bin/bash
# ============================================================================
#  RAQIB — UI / i18n regression tests
#  Verifies:
#    1. 20 language files expose the same 712-key set (14,240 strings)
#    2. localized UI keys are populated and non-English menus are translated
#    3. clean-output gate: non-TTY / NO_COLOR / TERM=dumb suppress ANSI + FX
#    4. RAQIB_COLOR=always forces visuals, RAQIB_FX=off still wins
#    5. run_tool preserves success/failure exit codes with FX enabled/disabled
# ============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR" || exit 1

FAIL=0
PASS=0
TMP="$(mktemp -d)" || exit 1
trap 'rm -rf "$TMP"' EXIT

pass() { PASS=$((PASS + 1)); printf '  [OK] %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  [FAIL] %s\n' "$1"; }

UI_KEYS=(
    cat1 cat2 cat3 cat4 cat5 cat6 cat7 cat8 cat9 cat10 cat11 cat12 cat13
    menu_exit menu_prompt menu_choice_range
    lbl_platform lbl_date lbl_hijri lbl_siem lbl_operator lbl_author
    lbl_updated lbl_status lbl_tagline
    fx_op_scan fx_op_radar fx_op_complete
)

echo "=== 1) Language parity (20 x 712 keys) ==="
lang_count=0
for f in modules/languages/*.sh; do
    [ -f "$f" ] || continue
    code="$(basename "$f" .sh)"
    lang_count=$((lang_count + 1))

    header="$(sed -n 's/^#  Total Keys: \([0-9][0-9]*\)$/\1/p' "$f" | head -1)"
    if [ "$header" = "712" ]; then
        pass "$code: header says 712 keys"
    else
        fail "$code: header says '${header:-missing}' (expected 712)"
    fi

    if (
        # shellcheck disable=SC1090
        source "$f" || exit 1
        arr="$(declare -A | sed -n 's/^declare -A \([A-Za-z0-9_]*\)=.*/\1/p' | grep '^STR_' | head -1)"
        [ -n "$arr" ] || exit 2
        eval "count=\${#$arr[@]}"
        printf '%s\n' "$count" > "$TMP/$code.count"
        eval "keys=(\"\${!$arr[@]}\")"
        printf '%s\n' "${keys[@]}" | LC_ALL=C sort > "$TMP/$code.keys"
    ); then
        count="$(cat "$TMP/$code.count")"
        if [ "$count" -eq 712 ]; then
            pass "$code: $count keys"
        else
            fail "$code: $count keys (expected 712)"
        fi
    else
        fail "$code: could not load language file"
    fi
done

if [ "$lang_count" -eq 20 ]; then
    pass "20 language files found"
else
    fail "found $lang_count language files (expected 20)"
fi

if [ -f "$TMP/ar.keys" ]; then
    key_mismatch=0
    for f in "$TMP"/*.keys; do
        code="$(basename "$f" .keys)"
        if ! diff -q "$TMP/ar.keys" "$f" >/dev/null 2>&1; then
            fail "$code: key set differs from ar"
            key_mismatch=1
        fi
    done
    [ "$key_mismatch" -eq 0 ] && pass "all 20 key sets are identical"
fi

echo ""
echo "=== 2) Localized UI keys ==="
for f in modules/languages/*.sh; do
    [ -f "$f" ] || continue
    code="$(basename "$f" .sh)"
    if (
        # shellcheck disable=SC1090
        source "$f" || exit 1
        arr="$(declare -A | sed -n 's/^declare -A \([A-Za-z0-9_]*\)=.*/\1/p' | grep '^STR_' | head -1)"
        [ -n "$arr" ] || exit 2
        for key in "${UI_KEYS[@]}"; do
            eval "value=\${$arr[$key]-}"
            printf '%s\t%s\n' "$key" "$value"
        done
    ) > "$TMP/$code.ui"; then
        missing=0
        while IFS=$'\t' read -r key value; do
            if [ -z "$value" ]; then
                fail "$code: empty UI key '$key'"
                missing=1
            fi
        done < "$TMP/$code.ui"
        [ "$missing" -eq 0 ] && pass "$code: ${#UI_KEYS[@]} UI keys populated"
    else
        fail "$code: could not read UI keys"
    fi
done

en_prompt="$(awk -F'\t' '$1 == "menu_prompt" {print $2}' "$TMP/en.ui")"
if [ "$en_prompt" = "Choose a defensive category:" ]; then
    pass "en: menu_prompt is the canonical English text"
else
    fail "en: unexpected menu_prompt '${en_prompt:-missing}'"
fi
for f in "$TMP"/*.ui; do
    code="$(basename "$f" .ui)"
    [ "$code" = "en" ] && continue
    prompt="$(awk -F'\t' '$1 == "menu_prompt" {print $2}' "$f")"
    if [ -n "$prompt" ] && [ "$prompt" != "$en_prompt" ]; then
        pass "$code: menu_prompt is localized"
    else
        fail "$code: menu_prompt is not localized"
    fi
done

echo ""
echo "=== 3) Clean-output gate ==="
gate_case() {
    local name="$1" want_level="$2" want_color="$3" want_cyan="$4"
    shift 4
    (
        unset _RAQIB_FX_OK _RAQIB_FX_LEVEL _RAQIB_FX_LEVEL_MODE NO_COLOR TERM
        for pair in "$@"; do export "$pair"; done
        # shellcheck disable=SC1091
        source modules/common.sh >/dev/null 2>&1
        raqib_fx_level_cache
        if raqib_color_enabled; then color=on; else color=off; fi
        printf '%s|%s|%s\n' "${_RAQIB_FX_LEVEL:-}" "$color" "${CYAN:+set}"
    ) > "$TMP/gate.out" 2>&1

    IFS='|' read -r level color cyan < "$TMP/gate.out"
    if [ "$level" = "$want_level" ] && [ "$color" = "$want_color" ] && [ "$cyan" = "$want_cyan" ]; then
        pass "$name: level=$level color=$color"
    else
        fail "$name: got level=$level color=$color cyan=$cyan; expected level=$want_level color=$want_color cyan=$want_cyan"
    fi
}

gate_case "default (non-TTY)" none off "" RAQIB_FX=auto RAQIB_COLOR=auto
gate_case "explicit strong (non-TTY)" none off "" RAQIB_FX=strong RAQIB_COLOR=auto
gate_case "explicit light (non-TTY)" none off "" RAQIB_FX=light RAQIB_COLOR=auto
gate_case "RAQIB_COLOR=never" none off "" RAQIB_FX=strong RAQIB_COLOR=never
gate_case "NO_COLOR=1" none off "" RAQIB_FX=strong RAQIB_COLOR=auto NO_COLOR=1
gate_case "TERM=dumb" none off "" RAQIB_FX=strong RAQIB_COLOR=auto TERM=dumb
gate_case "forced strong" strong on set RAQIB_FX=strong RAQIB_COLOR=always
gate_case "forced light" light on set RAQIB_FX=light RAQIB_COLOR=always
gate_case "forced cinematic" cinematic on set RAQIB_FX=cinematic RAQIB_COLOR=always
gate_case "forced + FX off" none on set RAQIB_FX=off RAQIB_COLOR=always

(
    # shellcheck disable=SC1091
    source modules/common.sh >/dev/null 2>&1
    raqib_clear
    fx_ops_header demo_tool
    fx_ops_footer demo_tool 0 0
) > "$TMP/clean.out" 2>&1
if [ -s "$TMP/clean.out" ]; then
    fail "clean path emitted $(wc -c < "$TMP/clean.out") bytes (expected 0)"
else
    pass "clean path emits no bytes"
fi

echo ""
echo "=== 4) run_tool exit codes ==="
cat > "$TMP/ok.sh" <<'EOF'
#!/bin/bash
exit 0
EOF
cat > "$TMP/bad.sh" <<'EOF'
#!/bin/bash
exit 3
EOF
chmod +x "$TMP/ok.sh" "$TMP/bad.sh" 2>/dev/null || true

for fx in off light strong cinematic; do
    (
        # shellcheck disable=SC1091
        source modules/common.sh >/dev/null 2>&1
        export RAQIB_FX="$fx"
        run_tool "$TMP/ok.sh" >/dev/null 2>&1
    )
    rc=$?
    if [ "$rc" -eq 0 ]; then
        pass "RAQIB_FX=$fx: success exit code preserved"
    else
        fail "RAQIB_FX=$fx: success exit code was $rc (expected 0)"
    fi

    (
        # shellcheck disable=SC1091
        source modules/common.sh >/dev/null 2>&1
        export RAQIB_FX="$fx"
        run_tool "$TMP/bad.sh" >/dev/null 2>&1
    )
    rc=$?
    if [ "$rc" -eq 3 ]; then
        pass "RAQIB_FX=$fx: failure exit code preserved"
    else
        fail "RAQIB_FX=$fx: failure exit code was $rc (expected 3)"
    fi
done

echo ""
echo "=================================================="
printf 'passed=%d failed=%d\n' "$PASS" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "ALL UI/I18N REGRESSION TESTS PASSED"
    exit 0
fi
echo "UI/I18N REGRESSION TESTS FAILED"
exit 1
