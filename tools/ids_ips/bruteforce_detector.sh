#!/bin/bash
echo -e "${CYAN}$(t ids1_title)${NC}"
LOGFILE=$(find_auth_log) || exit 1

read -rp "$(t ids1_prompt_threshold)" threshold
threshold=${threshold:-5}
if ! [[ "$threshold" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}$(t c_value_must_be_number)${NC}"; exit 1
fi

echo -e "${YELLOW}$(t ids1_analyzing)${NC}"
results=$(grep -i "Failed password" "$LOGFILE" | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | \
    awk -v t="$threshold" '$1 >= t {print}' | sort -rn)

if [ -z "$results" ]; then
    echo -e "${GREEN}$(tf ids1_no_ip_exceeded "$threshold")${NC}"
else
    echo "$results" | while read -r count ip; do
        echo -e "${RED}$(tf ids1_warning "$ip" "$count")${NC}"
    done
    save_report "$(tf ids1_report_title "$(date)")
$(tf ids1_threshold_label "$threshold")
$results" "bruteforce_report.txt"
fi
echo -e "${GREEN}$(t ids1_analysis_done)${NC}"
