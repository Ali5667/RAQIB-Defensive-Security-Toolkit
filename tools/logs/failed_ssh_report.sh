#!/bin/bash
echo -e "${CYAN}$(t log1_title)${NC}"
LOGFILE=$(find_auth_log) || exit 1

echo -e "${YELLOW}$(t log1_top_ips)${NC}"
attempt_word="$(t log1_attempt_word)"
top_ips=$(grep -i "Failed password" "$LOGFILE" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sort | uniq -c | sort -rn | head -20)
echo "$top_ips" | awk -v w="$attempt_word" '{printf "  %-6s "w"  ->  %s\n", $1, $2}'

total=$(grep -ci "Failed password" "$LOGFILE" 2>/dev/null)
echo -e "${GREEN}$(tf log1_total "${total:-0}")${NC}"

save_report "$(tf log1_report_title "$(date)")
$(tf log1_report_file "$LOGFILE")
$(tf log1_report_total "${total:-0}")

$(t log1_report_top)
$top_ips" "failed_ssh_report.txt"
