#!/bin/bash
echo -e "${CYAN}$(t ids2_title)${NC}"
echo -e "${YELLOW}$(t ids2_header)${NC}"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null | awk 'NR>1 {print $1, $5, $7}'
else
    netstat -tulnp 2>/dev/null
fi

echo ""
echo -e "${YELLOW}$(t ids2_ask_process)${NC}"
read -rp "$(t ids2_prompt_pname)" pname
if [ -n "$pname" ]; then
    ps aux | grep -i "$pname" | grep -v grep
fi

save_report "$(if command -v ss >/dev/null 2>&1; then ss -tulnp 2>/dev/null; else netstat -tulnp 2>/dev/null; fi)" "listening_ports.txt"
