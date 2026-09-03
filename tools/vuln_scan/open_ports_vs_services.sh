#!/bin/bash
finding_reset
echo -e "${CYAN}$(t vul1_title)${NC}"
echo -e "${YELLOW}$(t vul1_header)${NC}"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null | awk 'NR>1{print $5, $1, $7}' | \
        sed -E 's/.*:([0-9]+)$/\1/'
else
    netstat -tulnp 2>/dev/null
fi

echo ""
echo -e "${YELLOW}$(t vul1_risky_ports)${NC}"
RISKY_PORTS="21|23|445|3389|135|139|1433|3306|5432"
if command -v ss >/dev/null 2>&1; then
    risky_lines=$(ss -tuln 2>/dev/null | grep -E ":(${RISKY_PORTS})\b")
else
    risky_lines=$(netstat -tuln 2>/dev/null | grep -E ":(${RISKY_PORTS})\b")
fi
if [ -n "$risky_lines" ]; then
    while read -r line; do
        [ -z "$line" ] && continue
        echo -e "${RED}[!] $line${NC}"
        finding_add high
    done <<< "$risky_lines"
fi
echo -e "${GREEN}$(t vul1_ensure_protected)${NC}"

print_executive_summary "$(t vul1_title)"
