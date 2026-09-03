#!/bin/bash
finding_reset
echo -e "${CYAN}$(t har3_title)${NC}"

if command -v systemctl >/dev/null 2>&1; then
    echo -e "${YELLOW}$(t har3_at_boot)${NC}"
    systemctl list-unit-files --state=enabled --type=service 2>/dev/null

    echo ""
    echo -e "${YELLOW}$(t har3_currently_running)${NC}"
    systemctl list-units --type=service --state=running 2>/dev/null | head -30
else
    service --status-all 2>/dev/null
fi

RISKY="telnet|ftp|rsh|rlogin|tftp"
echo ""
echo -e "${RED}$(t har3_risky_warning)${NC}"
risky_found=$(systemctl list-unit-files --state=enabled 2>/dev/null | grep -iE "$RISKY")
echo "$risky_found"
if [ -n "$risky_found" ]; then
    while read -r _; do finding_add critical; done <<< "$risky_found"
else
    echo -e "${GREEN}$(t har3_all_good)${NC}"
fi

print_executive_summary "$(t har3_title)"

if [ -n "$risky_found" ]; then
    save_report "$(t har3_report_title)
$risky_found" "risky_services.txt" "$(t har3_title)"
fi
