#!/bin/bash
echo -e "${CYAN}$(t log4_title)${NC}"
read -rp "$(t log2_prompt_path)" logfile
if [ ! -f "$logfile" ]; then
    echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1
fi
read -rp "$(t log4_prompt_from)" from_time
read -rp "$(t log4_prompt_to)" to_time
if [ -z "$from_time" ] || [ -z "$to_time" ]; then
    echo -e "${RED}$(t log4_need_both)${NC}"; exit 1
fi

echo -e "${YELLOW}$(tf log4_events_between "$from_time" "$to_time")${NC}"
result=$(awk -v from="$from_time" -v to="$to_time" '
    $0 ~ from {flag=1}
    flag {print}
    $0 ~ to {flag=0}
' "$logfile")
echo "$result"
[ -n "$result" ] && save_report "$result" "log_timeline_${from_time//[: ]/_}.txt"
