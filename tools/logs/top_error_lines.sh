#!/bin/bash
echo -e "${CYAN}$(t log3_title)${NC}"
read -rp "$(t log2_prompt_path)" logfile
if [ ! -f "$logfile" ]; then
    echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1
fi
read -rp "$(t log3_prompt_filter)" filter

echo -e "${YELLOW}$(t log3_top20)${NC}"
if [ -n "$filter" ]; then
    result=$(grep -i -- "$filter" "$logfile" | sort | uniq -c | sort -rn | head -20)
else
    result=$(sort "$logfile" | uniq -c | sort -rn | head -20)
fi
echo "$result"
save_report "$result" "top_error_lines.txt"
