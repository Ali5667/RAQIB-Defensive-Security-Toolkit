#!/bin/bash
echo -e "${CYAN}$(t mon2_title)${NC}"
if command -v ss >/dev/null 2>&1; then
    echo -e "${YELLOW}$(t mon2_header)${NC}"
    ss -tunap 2>/dev/null | awk 'NR>1{print $1, $5, "->", $6, $7}'
else
    netstat -tunap 2>/dev/null
fi
echo ""
echo -e "${GREEN}$(t mon2_done)${NC}"
