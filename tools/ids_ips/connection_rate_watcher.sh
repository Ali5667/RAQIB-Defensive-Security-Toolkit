#!/bin/bash
echo -e "${CYAN}$(t ids5_title)${NC}"
echo -e "${YELLOW}$(t ids5_desc)${NC}"

snapshot() {
    if command -v ss >/dev/null 2>&1; then
        ss -tn state established 2>/dev/null | awk 'NR>1{print $4}' | \
            sed -E 's/:[0-9]+$//' | sort | uniq -c | sort -rn
    else
        netstat -tn 2>/dev/null | awk '$6=="ESTABLISHED"{print $5}' | \
            sed -E 's/:[0-9]+$//' | sort | uniq -c | sort -rn
    fi
}

echo -e "${CYAN}$(t ids5_first_snapshot)${NC}"
snap1=$(snapshot)
echo "$snap1" | head -15

sleep 5

echo ""
echo -e "${CYAN}$(t ids5_second_snapshot)${NC}"
snap2=$(snapshot)
echo "$snap2" | head -15

echo ""
echo -e "${YELLOW}$(t ids5_high_conn)${NC}"
echo "$snap2" | awk '$1 > 20 {print}'
