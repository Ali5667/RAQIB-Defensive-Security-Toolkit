#!/bin/bash
finding_reset

TOOL_TITLE="$(t cred_leak_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# مترجم بايثون: نستخدم الكاشف المركزي (_raqib_py) بدل python3 مباشرة،
# لأن Git Bash يعرّض python3 كـ Windows Store stub فاشل.
# Resolve Python through the central probe — Git Bash's python3 may be a broken stub.
PY=""
if declare -F _raqib_py >/dev/null 2>&1; then
    PY="$(_raqib_py 2>/dev/null)" || PY=""
fi
if [ -z "$PY" ] && command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
    PY="python3"
fi
if [ -z "$PY" ]; then
    echo -e "${RED}$(t cred_leak_no_python)${NC}"
    exit 1
fi

SCRIPT_PATH="$(dirname "${BASH_SOURCE[0]}")/raqib_credential_leak_checker.py"
if [ ! -f "$SCRIPT_PATH" ]; then
    echo -e "${RED}[!] Script not found: $SCRIPT_PATH${NC}"
    exit 1
fi

python3 "$SCRIPT_PATH"

echo ""
echo -e "${GREEN}$(t cred_leak_tip)${NC}"

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$(t cred_leak_title) — $(date)\n\n$(t cred_leak_tip)" "credential_leak_report.txt" "$TOOL_TITLE"
