#!/bin/bash
finding_reset
echo -e "${CYAN}$(t vul4_title)${NC}"
read -rp "$(t vul4_prompt_domain)" domain
[ -z "$domain" ] && { echo -e "${RED}$(t mon5_need_domain)${NC}"; exit 1; }
read -rp "$(t vul4_prompt_port)" port
port=${port:-443}
if ! is_valid_port "$port"; then
    echo -e "${RED}$(t mon1_invalid_port_range)${NC}"; exit 1
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo -e "${RED}$(t vul4_openssl_missing)${NC}"; exit 1
fi

cert_info=$(run_with_spinner "$(tf vul4_connecting "$domain" "$port") " -- \
    bash -c 'echo | openssl s_client -connect "$1:$2" -servername "$1" 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null' _ "$domain" "$port")

if [ -z "$cert_info" ]; then
    echo -e "${RED}$(t vul4_fetch_failed)${NC}"
    exit 1
fi

echo "$cert_info"

expiry=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
expiry_epoch=$(raqib_date_epoch "$expiry")
if [ -z "$expiry_epoch" ]; then
    echo -e "${YELLOW}$(t vul4_cant_calc_days)${NC}"
    exit 0
fi
now_epoch=$(date +%s)
days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

echo ""
if [ "$days_left" -lt 0 ]; then
    echo -e "${RED}$(t vul4_expired)${NC}"
    finding_add critical
elif [ "$days_left" -lt 15 ]; then
    echo -e "${RED}$(tf vul4_expiring_soon "$days_left")${NC}"
    finding_add high
else
    echo -e "${GREEN}$(tf vul4_valid "$days_left")${NC}"
fi

print_executive_summary "$(t vul4_title)"
