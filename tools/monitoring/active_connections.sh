#!/bin/bash
echo -e "${CYAN}$(t mon2_title)${NC}"
if command -v ss >/dev/null 2>&1; then
    echo -e "${YELLOW}$(t mon2_header)${NC}"
    ss -tunap 2>/dev/null | awk 'NR>1{print $1, $5, "->", $6, $7}'
else
    netstat -tunap 2>/dev/null
fi
echo ""

if raqib_intel_available && command -v ss >/dev/null 2>&1; then
    echo -e "${CYAN}$(t intel_scan_connections)${NC}"
    remote_ips=$(ss -tunap 2>/dev/null | awk 'NR>1{print $6}' | sed -E 's/^\[?([0-9a-fA-F:.]+)\]?:[0-9]+$/\1/' | sort -u)
    intel_hits=0
    while IFS= read -r rip; do
        [ -z "$rip" ] && continue
        case "$rip" in "*"|"0.0.0.0"|"::"|"") continue ;; esac
        if raqib_intel_check_and_report "$rip"; then intel_hits=1; fi
    done <<< "$remote_ips"
    [ "$intel_hits" -eq 0 ] && echo -e "  ${GREEN}$(t intel_no_match)${NC}"
    echo ""
fi

echo -e "${GREEN}$(t mon2_done)${NC}"
