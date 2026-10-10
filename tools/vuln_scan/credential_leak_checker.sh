#!/bin/bash
finding_reset

TOOL_TITLE="$(t cred_leak_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
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
