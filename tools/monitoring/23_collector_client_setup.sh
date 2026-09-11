#!/bin/bash
# collector_client_setup.sh
# يضبط هذا الجهاز ليرسل نسخة من كل حدث لسيرفر تجميع مركزي بجهاز ثاني
# (شغّال عليه raqib_collector_server.sh). يختبر الاتصال فعلياً قبل التأكيد.

echo -e "${CYAN}$(t colcli_title)${NC}"
echo -e "${GREY}$(t colcli_disclaimer)${NC}"
echo ""

if raqib_collector_configured; then
    url=$(sed -n 's/^COLLECTOR_URL=//p' "$RAQIB_COLLECTOR_CONF" | head -1)
    echo -e "${GREEN}$(tf colcli_already_configured "$url")${NC}"
    read -rp "$(t colcli_reconfigure_prompt)" reconf
    [ "$reconf" != "y" ] && exit 0
    echo ""
fi

read -rp "$(t colcli_url_prompt)" url
[ -z "$url" ] && { echo -e "${RED}$(t colcli_cancelled)${NC}"; exit 1; }
read -rp "$(t colcli_apikey_prompt)" api_key
[ -z "$api_key" ] && { echo -e "${RED}$(t colcli_cancelled)${NC}"; exit 1; }

echo -e "${CYAN}$(t colcli_testing)${NC}"
test_payload='{"timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","host":"'"$(hostname 2>/dev/null || echo unknown)"'","severity":"low","tool":"collector_client_setup","message":"test connection","operator":"'"${RAQIB_OPERATOR:-unknown}"'"}'

status_code=$(curl -s -m 8 -o /dev/null -w "%{http_code}" -X POST "${url%/}/event" \
    -H "Content-Type: application/json" -H "X-API-Key: ${api_key}" -d "$test_payload")

if [ "$status_code" = "200" ]; then
    printf 'COLLECTOR_URL=%s\nAPI_KEY=%s\n' "$url" "$api_key" > "$RAQIB_COLLECTOR_CONF"
    chmod 600 "$RAQIB_COLLECTOR_CONF" 2>/dev/null
    echo -e "${GREEN}$(t colcli_test_success)${NC}"
elif [ "$status_code" = "401" ]; then
    echo -e "${RED}$(t colcli_bad_apikey)${NC}"
else
    echo -e "${RED}$(t colcli_test_failed)${NC}"
fi
