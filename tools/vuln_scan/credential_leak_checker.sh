#!/bin/bash
echo -e "${CYAN}$(t cred_leak_title)${NC}"

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
read -rp "$(t c_save_report_prompt)" ans
if [ "$ans" = "y" ]; then
    echo -e "${GREEN}$(t cred_leak_tip)${NC}"
fi
