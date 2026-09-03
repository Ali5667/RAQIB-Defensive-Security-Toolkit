#!/bin/bash
echo -e "${CYAN}$(t for5_title)${NC}"
LOGFILE=$(find_auth_log) || exit 1

echo -e "${YELLOW}$(t for5_last30)${NC}"
grep "sudo:" "$LOGFILE" 2>/dev/null | grep "COMMAND=" | tail -30

echo ""
echo -e "${YELLOW}$(t for5_usage_per_user)${NC}"
grep "sudo:" "$LOGFILE" 2>/dev/null | grep -oE 'sudo:\s+[a-zA-Z0-9_]+' | \
    awk '{print $2}' | sort | uniq -c | sort -rn

echo ""
echo -e "${RED}$(t for5_failed_attempts)${NC}"
grep -i "sudo:.*authentication failure\|not in the sudoers" "$LOGFILE" 2>/dev/null
