#!/bin/bash
finding_reset
echo -e "${CYAN}$(t har5_title)${NC}"

fw_active=""
if command -v ufw >/dev/null 2>&1; then
    echo -e "${YELLOW}$(t har5_ufw_status)${NC}"
    ufw_out=$(ufw status verbose 2>/dev/null)
    echo "$ufw_out"
    fw_active="$ufw_out"
    echo "$ufw_out" | grep -qi "Status: inactive" && finding_add high
elif command -v firewall-cmd >/dev/null 2>&1; then
    echo -e "${YELLOW}$(t har5_firewalld_status)${NC}"
    fwd_state=$(firewall-cmd --state 2>/dev/null)
    echo "$fwd_state"
    firewall-cmd --list-all 2>/dev/null
    fw_active="$fwd_state"
    [ "$fwd_state" != "running" ] && finding_add high
else
    finding_add medium
fi

echo ""
echo -e "${YELLOW}$(t har5_iptables_rules)${NC}"
if command -v iptables >/dev/null 2>&1; then
    iptables -L -n -v 2>/dev/null || echo "$(t c_needs_root)"
else
    echo "$(t har5_iptables_not_installed)"
fi

echo ""
policy_default=$(iptables -L INPUT 2>/dev/null | head -1)
if echo "$policy_default" | grep -qi "ACCEPT"; then
    echo -e "${RED}$(t har5_default_accept)${NC}"
    finding_add critical
fi

print_executive_summary "$(t har5_title)"
