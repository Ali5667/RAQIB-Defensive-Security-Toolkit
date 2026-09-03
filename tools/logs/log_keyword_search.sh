#!/bin/bash
echo -e "${CYAN}$(t log2_title)${NC}"
read -rp "$(t log2_prompt_path)" logfile
read -rp "$(t log2_prompt_keyword)" keyword

if [ ! -f "$logfile" ]; then
    echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1
fi
if [ -z "$keyword" ]; then
    echo -e "${RED}$(t log2_need_keyword)${NC}"; exit 1
fi

echo -e "${YELLOW}$(tf log2_results_for "$keyword")${NC}"
grep -in -B2 -A2 --color=always -- "$keyword" "$logfile"

count=$(grep -ic -- "$keyword" "$logfile")
echo -e "${GREEN}$(tf log2_match_count "$count")${NC}"

if [ "$count" -gt 0 ]; then
    save_report "$(grep -in -B2 -A2 -- "$keyword" "$logfile")" "keyword_search_${keyword// /_}.txt"
fi
