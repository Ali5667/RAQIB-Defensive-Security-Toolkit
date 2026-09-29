#!/bin/bash
# =====================================================
#  Firewall Status Checker — مدقق حالة الجدار الناري
#  يفحص: UFW، firewalld، iptables، nftables، ipset
#  يحلل: القواعد الفعلية، السياسة الافتراضية،
#         منافذ مكشوفة للإنترنت، قواعد متضاربة،
#         Allow ALL rules، منافذ خطيرة مفتوحة
# =====================================================
finding_reset

TOOL_TITLE="$(t har5_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""
fw_found=0

# ─── منافذ خطيرة يجب عدم كشفها ─────────────────────────────
DANGEROUS_PORTS="23|445|2375|4444|6379|9200|11211|27017|9300|50070|8888"

# ─── 1. UFW ───────────────────────────────────────────────────
if command -v ufw >/dev/null 2>&1; then
    fw_found=1
    echo -e "${BOLD}${CYAN}━━ UFW (Uncomplicated Firewall) ━━${NC}"
    ufw_status=$(ufw status verbose 2>/dev/null)

    if echo "$ufw_status" | grep -qi "Status: inactive"; then
        echo -e "  ${RED}[CRITICAL] UFW معطّل!${NC}"
        finding_add critical "UFW firewall is DISABLED"
    else
        echo -e "  ${GREEN}[✓] UFW نشط${NC}"
    fi

    echo ""
    echo "$ufw_status"

    # تحليل: هل هناك ALLOW للمنافذ الخطيرة؟
    echo ""
    echo -e "${YELLOW}  ◉ فحص قواعد المنافذ الخطيرة:${NC}"
    echo "$ufw_status" | grep -iE "ALLOW" | while IFS= read -r rule; do
        for dp in 23 445 2375 4444 6379 9200 11211 27017; do
            if echo "$rule" | grep -qE "\b${dp}\b"; then
                echo -e "  ${RED}[CRITICAL] منفذ خطير مسموح: $rule${NC}"
                finding_add critical "Dangerous port $dp allowed through UFW"
            fi
        done
    done

    # السياسة الافتراضية
    default_in=$(echo "$ufw_status" | grep "Default:" | grep -i "incoming" | grep -oi "allow\|deny\|reject")
    if [ "${default_in,,}" = "allow" ]; then
        echo -e "  ${RED}[CRITICAL] السياسة الافتراضية لـ INPUT هي ALLOW — خطر شديد!${NC}"
        finding_add critical "UFW default INPUT policy is ALLOW — all incoming traffic permitted"
    fi

    REPORT+="=== UFW ===
$ufw_status

"
fi

# ─── 2. firewalld ─────────────────────────────────────────────
if command -v firewall-cmd >/dev/null 2>&1; then
    fw_found=1
    echo ""
    echo -e "${BOLD}${CYAN}━━ firewalld ━━${NC}"

    fwd_state=$(firewall-cmd --state 2>/dev/null)
    if [ "$fwd_state" != "running" ]; then
        echo -e "  ${RED}[CRITICAL] firewalld معطّل! (حالة: $fwd_state)${NC}"
        finding_add critical "firewalld is not running"
    else
        echo -e "  ${GREEN}[✓] firewalld نشط${NC}"
    fi

    echo ""
    active_zones=$(firewall-cmd --list-all 2>/dev/null)
    echo "$active_zones"

    # فحص: منافذ مفتوحة للإنترنت بـ zone public
    pub_services=$(firewall-cmd --zone=public --list-services 2>/dev/null)
    pub_ports=$(firewall-cmd --zone=public --list-ports 2>/dev/null)
    echo -e "  ${YELLOW}Public Zone Services: $pub_services${NC}"
    echo -e "  ${YELLOW}Public Zone Ports: $pub_ports${NC}"

    if echo "$pub_services" | grep -qiE "telnet|ftp"; then
        echo -e "  ${RED}[HIGH] خدمة خطيرة مكشوفة للـ public zone${NC}"
        finding_add high "Dangerous service exposed in public zone"
    fi

    REPORT+="=== firewalld ===
State: $fwd_state
$active_zones

"
fi

# ─── 3. iptables ──────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ iptables ━━${NC}"

if command -v iptables >/dev/null 2>&1; then
    iptables_out=$(iptables -L -n -v --line-numbers 2>/dev/null || echo "$(t c_needs_root)")
    echo "$iptables_out"

    # فحص السياسة الافتراضية
    input_policy=$(iptables -L INPUT 2>/dev/null | head -1 | grep -oE 'policy [A-Z]+' | awk '{print $2}')
    forward_policy=$(iptables -L FORWARD 2>/dev/null | head -1 | grep -oE 'policy [A-Z]+' | awk '{print $2}')

    echo ""
    echo -e "${YELLOW}  السياسات الافتراضية:${NC}"
    if [ "$input_policy" = "ACCEPT" ]; then
        echo -e "  ${RED}[CRITICAL] INPUT policy = ACCEPT — كل الاتصالات الواردة مسموح!${NC}"
        finding_add critical "iptables INPUT default policy is ACCEPT — allows all incoming"
    else
        echo -e "  ${GREEN}[✓] INPUT policy = ${input_policy:-DROP/REJECT}${NC}"
    fi

    if [ "$forward_policy" = "ACCEPT" ]; then
        echo -e "  ${ORANGE}[HIGH] FORWARD policy = ACCEPT${NC}"
        finding_add high "iptables FORWARD policy is ACCEPT"
    fi

    # فحص: قواعد ACCEPT للمنافذ الخطيرة
    echo ""
    echo -e "${YELLOW}  ◉ فحص قواعد ACCEPT للمنافذ الخطيرة:${NC}"
    dangerous_rules=$(iptables -L -n 2>/dev/null | grep "ACCEPT" | \
        grep -E "dpt:($(echo $DANGEROUS_PORTS | tr '|' '|'))") 2>/dev/null
    if [ -n "$dangerous_rules" ]; then
        echo -e "  ${RED}قواعد خطيرة:${NC}"
        while IFS= read -r dr; do
            echo -e "  ${RED}  ▸ $dr${NC}"
            finding_add high "iptables ACCEPT rule for dangerous port: $dr"
        done <<< "$dangerous_rules"
    else
        echo -e "  ${GREEN}لا توجد قواعد ACCEPT للمنافذ الخطيرة${NC}"
    fi

    # فحص: قاعدة ACCEPT لكل شيء (0.0.0.0/0)
    accept_all=$(iptables -L -n 2>/dev/null | grep "ACCEPT.*0\.0\.0\.0/0" | head -5)
    if [ -n "$accept_all" ]; then
        echo -e "  ${ORANGE}[MEDIUM] قواعد ACCEPT مفتوحة (0.0.0.0/0):${NC}"
        echo "$accept_all" | while IFS= read -r aa; do
            echo -e "  ${ORANGE}  ▸ $aa${NC}"
        done
    fi

    REPORT+="=== iptables ===
$iptables_out

"
else
    echo -e "  ${YELLOW}$(t har5_iptables_not_installed)${NC}"
fi

# ─── 4. nftables ──────────────────────────────────────────────
if command -v nft >/dev/null 2>&1; then
    echo ""
    echo -e "${BOLD}${CYAN}━━ nftables ━━${NC}"
    nft_out=$(nft list ruleset 2>/dev/null || echo "$(t c_needs_root)")
    echo "$nft_out" | head -40
    REPORT+="=== nftables ===
$nft_out

"
fi

# ─── 5. ما في جدار ناري ──────────────────────────────────────
if [ "$fw_found" -eq 0 ]; then
    echo -e "${RED}[CRITICAL] لا يوجد جدار ناري مُفعّل! (UFW/firewalld/iptables)${NC}"
    finding_add critical "No active firewall detected on this system"
fi

# ─── 6. ipset ─────────────────────────────────────────────────
if command -v ipset >/dev/null 2>&1; then
    ipset_list=$(ipset list 2>/dev/null | head -30)
    if [ -n "$ipset_list" ]; then
        echo ""
        echo -e "${BOLD}${CYAN}━━ ipset (IP Sets) ━━${NC}"
        echo "$ipset_list"
        REPORT+="=== ipset ===
$ipset_list

"
    fi
fi

# ─── 7. ملخص ─────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Firewall Audit — $(date)

$REPORT" "firewall_status.txt" "$TOOL_TITLE"
