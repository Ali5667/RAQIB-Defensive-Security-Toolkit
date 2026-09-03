#!/bin/bash
echo -e "${CYAN}$(t for2_title)${NC}"

SUSPICIOUS_PATTERNS='wget |curl |base64 -d|nc -e|/dev/tcp/|chmod 777|rm -rf /|python -c|history -c'
report=""
found_any=0

for histfile in /root/.bash_history /home/*/.bash_history; do
    [ -f "$histfile" ] || continue
    echo -e "${YELLOW}--- $histfile ---${NC}"
    matches=$(grep -inE "$SUSPICIOUS_PATTERNS" "$histfile" 2>/dev/null)
    if [ -n "$matches" ]; then
        found_any=1
        echo "$matches" | while read -r line; do
            echo -e "${RED}[!] $line${NC}"
        done
        report="${report}
--- $histfile ---
$matches"
    fi
    echo ""
done

echo -e "${GREEN}$(t for2_scanned_all)${NC}"
[ "$found_any" -eq 1 ] && save_report "$report" "bash_history_review.txt"
