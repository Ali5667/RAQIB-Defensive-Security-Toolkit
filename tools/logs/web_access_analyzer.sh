#!/bin/bash
echo -e "${CYAN}$(t log5_title)${NC}"
read -rp "$(t log5_prompt_path)" logfile
if [ ! -f "$logfile" ]; then
    echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1
fi

echo -e "${YELLOW}$(t log5_top_ips)${NC}"
top_ips=$(awk '{print $1}' "$logfile" | sort | uniq -c | sort -rn | head -10)
echo "$top_ips"

echo ""
echo -e "${YELLOW}$(t log5_status_dist)${NC}"
status_codes=$(awk '{print $9}' "$logfile" | grep -E '^[0-9]{3}$' | sort | uniq -c | sort -rn)
echo "$status_codes"

echo ""
echo -e "${YELLOW}$(t log5_top_paths)${NC}"
top_paths=$(awk '{print $7}' "$logfile" | sort | uniq -c | sort -rn | head -10)
echo "$top_paths"

echo ""
echo -e "${RED}$(t log5_suspicious_4xx5xx)${NC}"
suspicious=$(awk '$9 ~ /^[45][0-9][0-9]$/ {print $1}' "$logfile" | sort | uniq -c | sort -rn | head -10)
echo "$suspicious"

save_report "$(tf log5_report_title "$logfile" "$(date)")

$(t log5_top_ips)
$top_ips

$(t log5_status_dist)
$status_codes

$(t log5_top_paths)
$top_paths

$(t log5_suspicious_4xx5xx)
$suspicious" "web_access_analysis.txt"
