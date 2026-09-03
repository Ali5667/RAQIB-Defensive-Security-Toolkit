#!/bin/bash
echo -e "${CYAN}$(t mon4_title)${NC}"
BASELINE="/tmp/raqib_arp_baseline.txt"

capture_arp() {
    ip neigh show 2>/dev/null | awk '{print $1, $5}' | sort
}

if [ ! -f "$BASELINE" ]; then
    capture_arp > "$BASELINE"
    echo -e "${YELLOW}$(t mon4_baseline_created)${NC}"
    cat "$BASELINE"
    echo -e "${GREEN}$(t mon4_run_again)${NC}"
    exit 0
fi

current=$(capture_arp)
echo -e "${YELLOW}$(t mon4_comparing)${NC}"
diff_result=$(diff <(printf '%s' "$(cat "$BASELINE")") <(printf '%s' "$current"))

if [ -z "$diff_result" ]; then
    echo -e "${GREEN}$(t mon4_no_change)${NC}"
else
    echo -e "${RED}$(t mon4_changes_detected)${NC}"
    echo "$diff_result"
fi

read -rp "$(t c_confirm_update_baseline)" ans
[ "$ans" = "y" ] && echo "$current" > "$BASELINE" && echo -e "${GREEN}$(t c_updated)${NC}"
