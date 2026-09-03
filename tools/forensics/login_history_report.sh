#!/bin/bash
echo -e "${CYAN}$(t for1_title)${NC}"

echo -e "${YELLOW}$(t for1_successful)${NC}"
successful=$(last -20 2>/dev/null)
echo "$successful"

echo ""
echo -e "${YELLOW}$(t for1_failed)${NC}"
failed=$(lastb -20 2>/dev/null)
if [ -n "$failed" ]; then echo "$failed"; else echo "$(t for1_needs_root)"; fi

echo ""
echo -e "${YELLOW}$(t for1_last_per_user)${NC}"
lastlogins=$(lastlog 2>/dev/null | grep -v "Never logged in")
echo "$lastlogins"

save_report "$(tf for1_report_title "$(date)")

$(t for1_successful)
$successful

$(t for1_failed)
$failed

$(t for1_last_per_user)
$lastlogins" "login_history_report.txt"
