#!/bin/bash
# ip_blocker.sh — يحظر/يفك حظر عنوان IP عبر جدار الحماية المتوفر
# (ufw > firewalld > iptables)، ويحتفظ بسجل بالعناوين التي حظرها عبر التاق
# RAQIB-BLOCK حتى يقدر يعرضها/يفكها لاحقاً.
echo -e "${CYAN}$(t ipb_title)${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}$(t ipb_needs_root)${NC}"
    exit 1
fi

STATE_FILE="$HOME/.raqib_blocked_ips"
touch "$STATE_FILE" 2>/dev/null

detect_fw() {
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
        echo "ufw"
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi running; then
        echo "firewalld"
    elif command -v iptables >/dev/null 2>&1; then
        echo "iptables"
    else
        echo "none"
    fi
}
fw=$(detect_fw)
if [ "$fw" = "none" ]; then
    echo -e "${RED}$(t ipb_no_firewall)${NC}"
    exit 1
fi
echo -e "${YELLOW}$(tf ipb_using_fw "$fw")${NC}"

echo ""
echo "1) $(t ipb_opt_block)"
echo "2) $(t ipb_opt_unblock)"
echo "3) $(t ipb_opt_list)"
echo "0) $(t back)"
read -rp "  $(t choice_label)" opt

block_ip() {
    local ip="$1"
    case "$fw" in
        ufw) ufw insert 1 deny from "$ip" to any comment "RAQIB-BLOCK-$ip" >/dev/null 2>&1 ;;
        firewalld) firewall-cmd --add-rich-rule="rule family='ipv4' source address='$ip' reject" --permanent >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 ;;
        iptables) iptables -I INPUT 1 -s "$ip" -m comment --comment "RAQIB-BLOCK-$ip" -j DROP >/dev/null 2>&1 ;;
    esac
    return $?
}

unblock_ip() {
    local ip="$1"
    case "$fw" in
        ufw) ufw delete deny from "$ip" to any >/dev/null 2>&1 ;;
        firewalld) firewall-cmd --remove-rich-rule="rule family='ipv4' source address='$ip' reject" --permanent >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1 ;;
        iptables)
            local line
            line=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep "RAQIB-BLOCK-$ip" | awk '{print $1}' | head -1)
            [ -n "$line" ] && iptables -D INPUT "$line" >/dev/null 2>&1
            ;;
    esac
    return $?
}

case "$opt" in
    1)
        read -rp "$(t ipb_prompt_ip)" ip
        if ! is_valid_ip "$ip"; then
            echo -e "${RED}$(t mon5_invalid_ip)${NC}"; exit 1
        fi
        read -rp "$(tf ipb_confirm_block "$ip")" confirm
        [ "$confirm" != "y" ] && { echo -e "${YELLOW}$(t qe_cancelled)${NC}"; exit 0; }
        if block_ip "$ip"; then
            echo -e "${GREEN}$(tf ipb_blocked "$ip")${NC}"
            echo "$ip|$(date '+%Y-%m-%d %H:%M')" >> "$STATE_FILE"
            save_report "$(tf ipb_report_title "$(date)")
$(t ipb_prompt_ip)$ip
$(t ipb_using_fw) $fw" "ip_block_${ip//./_}.txt" "$(t ipb_title)"
        else
            echo -e "${RED}$(tf ipb_block_failed "$ip")${NC}"
        fi
        ;;
    2)
        read -rp "$(t ipb_prompt_ip)" ip
        if ! is_valid_ip "$ip"; then
            echo -e "${RED}$(t mon5_invalid_ip)${NC}"; exit 1
        fi
        if unblock_ip "$ip"; then
            echo -e "${GREEN}$(tf ipb_unblocked "$ip")${NC}"
            grep -v "^${ip}|" "$STATE_FILE" > "${STATE_FILE}.tmp" 2>/dev/null && mv "${STATE_FILE}.tmp" "$STATE_FILE"
        else
            echo -e "${RED}$(tf ipb_unblock_failed "$ip")${NC}"
        fi
        ;;
    3)
        echo -e "${YELLOW}$(t ipb_current_list)${NC}"
        if [ -s "$STATE_FILE" ]; then
            while IFS='|' read -r ip ts; do
                [ -z "$ip" ] && continue
                echo -e "  ${CYAN}${ip}${NC}  (${ts})"
            done < "$STATE_FILE"
        else
            echo -e "  ${GREEN}$(t ipb_list_empty)${NC}"
        fi
        ;;
    0) exit 0 ;;
    *) echo -e "${RED}$(t invalid_choice)${NC}" ;;
esac
