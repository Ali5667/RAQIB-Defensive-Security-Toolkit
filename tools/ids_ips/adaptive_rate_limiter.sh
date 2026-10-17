#!/bin/bash
# =====================================================
#  Adaptive Rate Limiter & Tarpit — الدفاع الديناميكي المتكيف
#  بدلاً من الحظر المباشر فقط (iptables DROP)، يدعم:
#    1) Rate Limiting متكيف حسب سلوك الـ IP
#    2) Tarpit (كتم الاتصال) — تأخير الردود لإبطاء المهاجم
#    3) تصعيد تدريجي: warn -> rate-limit -> tarpit -> block
#    4) القائمة البيضاء (Whitelist) للـ IPs الموثوقة
#    5) دعم nftables الحديث بالإضافة لـ iptables
#
#  الآلية: يراقب معدل الاتصالات لكل IP، ويصعّد الإجراء
#  تلقائياً حسب مستوى التهديد (بدلاً من القطع الفوري).
# =====================================================
finding_reset

TOOL_TITLE="$(t ids8_title 2>/dev/null || echo 'Adaptive Rate Limiter & Tarpit')"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

STATE_DIR="${SCRIPT_DIR:-.}/state"
mkdir -p "$STATE_DIR" 2>/dev/null
RATE_STATE="$STATE_DIR/.raqib_rate_state.json"
WHITELIST_FILE="$STATE_DIR/.raqib_rate_whitelist.txt"

# ─── اكتشاف جدار الحماية المتوفر ──────────────────────────────
detect_firewall() {
    if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
        echo "nftables"
    elif command -v iptables >/dev/null 2>&1; then
        echo "iptables"
    else
        echo "none"
    fi
}

FW_TYPE=$(detect_firewall)
echo -e "  ${GREY}Firewall backend: $FW_TYPE${NC}"

# ─── دوال جدار الحماية (تدعم nftables و iptables) ─────────────

# إنشاء سلسلة RAQIB لو ما كانت موجودة
fw_init_chain() {
    if [ "$FW_TYPE" = "nftables" ]; then
        # إنشاء جدول وسلسلة nftables
        nft list table inet raqib_defense >/dev/null 2>&1 || \
            nft add table inet raqib_defense 2>/dev/null
        nft list chain inet raqib_defense rate_control >/dev/null 2>&1 || \
            nft add chain inet raqib_defense rate_control \
                '{ type filter hook input priority 0; policy accept; }' 2>/dev/null
        echo -e "  ${GREEN}[nftables] RAQIB chain initialized${NC}"
    elif [ "$FW_TYPE" = "iptables" ]; then
        iptables -N RAQIB_RATE 2>/dev/null || true
        iptables -C INPUT -j RAQIB_RATE 2>/dev/null || \
            iptables -I INPUT -j RAQIB_RATE 2>/dev/null
        echo -e "  ${GREEN}[iptables] RAQIB chain initialized${NC}"
    fi
}

# تطبيق Rate Limit على IP
fw_rate_limit() {
    local ip="$1" rate="${2:-10}" burst="${3:-20}"
    if [ "$FW_TYPE" = "nftables" ]; then
        nft add rule inet raqib_defense rate_control \
            ip saddr "$ip" limit rate "$rate"/second burst "$burst" packets accept 2>/dev/null
        nft add rule inet raqib_defense rate_control \
            ip saddr "$ip" drop 2>/dev/null
    elif [ "$FW_TYPE" = "iptables" ]; then
        iptables -A RAQIB_RATE -s "$ip" -m limit \
            --limit "${rate}/sec" --limit-burst "$burst" -j ACCEPT 2>/dev/null
        iptables -A RAQIB_RATE -s "$ip" -j DROP 2>/dev/null
    fi
}

# تطبيق Tarpit (تأخير) على IP
fw_tarpit() {
    local ip="$1"
    if [ "$FW_TYPE" = "nftables" ]; then
        # nftables: استخدام queue لتأخير الحزم (يحتاج nfqueue)
        # أو بديل: rate limit شديد جداً (حزمة واحدة/ثانية)
        nft add rule inet raqib_defense rate_control \
            ip saddr "$ip" limit rate 1/second accept 2>/dev/null
        nft add rule inet raqib_defense rate_control \
            ip saddr "$ip" drop 2>/dev/null
        echo -e "  ${ORANGE}[nftables] Tarpit applied: $ip (1 pkt/sec)${NC}"
    elif [ "$FW_TYPE" = "iptables" ]; then
        # iptables TARPIT target (لو موجود xt_TARPIT)
        if iptables -j TARPIT --help 2>&1 | grep -q 'TARPIT'; then
            iptables -A RAQIB_RATE -s "$ip" -p tcp -j TARPIT 2>/dev/null
            echo -e "  ${ORANGE}[iptables] TARPIT applied: $ip${NC}"
        else
            # بديل: rate limit شديد
            iptables -A RAQIB_RATE -s "$ip" -m limit \
                --limit 1/sec --limit-burst 1 -j ACCEPT 2>/dev/null
            iptables -A RAQIB_RATE -s "$ip" -j DROP 2>/dev/null
            echo -e "  ${ORANGE}[iptables] Slow-rate applied: $ip (1 pkt/sec)${NC}"
        fi
    fi
}

# حظر IP بالكامل
fw_block() {
    local ip="$1"
    if [ "$FW_TYPE" = "nftables" ]; then
        nft add rule inet raqib_defense rate_control \
            ip saddr "$ip" drop 2>/dev/null
    elif [ "$FW_TYPE" = "iptables" ]; then
        iptables -A RAQIB_RATE -s "$ip" -j DROP 2>/dev/null
    fi
}

# رفع الحظر عن IP
fw_unblock() {
    local ip="$1"
    if [ "$FW_TYPE" = "nftables" ]; then
        # حذف كل القواعد المتعلقة بهذا الـ IP
        local handles
        handles=$(nft -a list chain inet raqib_defense rate_control 2>/dev/null | \
                  grep "$ip" | grep -oE 'handle [0-9]+' | awk '{print $2}')
        for h in $handles; do
            nft delete rule inet raqib_defense rate_control handle "$h" 2>/dev/null
        done
    elif [ "$FW_TYPE" = "iptables" ]; then
        while iptables -D RAQIB_RATE -s "$ip" -j DROP 2>/dev/null; do :; done
        while iptables -D RAQIB_RATE -s "$ip" -j ACCEPT 2>/dev/null; do :; done
    fi
}

# ─── تحليل السلوك وتصعيد الإجراء ────────────────────────────────
analyze_and_respond() {
    echo -e "${YELLOW}◉ Analyzing connection rates...${NC}"
    echo ""

    LOGFILE=$(find_auth_log 2>/dev/null) || LOGFILE="/var/log/auth.log"

    # القائمة البيضاء
    local -A whitelist
    if [ -f "$WHITELIST_FILE" ]; then
        while IFS= read -r wip; do
            [ -z "$wip" ] && continue
            case "$wip" in \#*) continue ;; esac
            whitelist["$wip"]=1
        done < "$WHITELIST_FILE"
    fi

    # تحليل معدل المحاولات لكل IP في آخر 5 دقائق
    local now_epoch
    now_epoch=$(date +%s)

    # جمع IPs المشبوهة من سجلات المصادقة والشبكة
    local -A ip_counts
    local -A ip_types

    # من سجلات SSH
    while IFS= read -r line; do
        local ip count
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        [ -z "$ip" ] && continue
        ip_counts["$ip"]=$((${ip_counts["$ip"]:-0} + count))
        ip_types["$ip"]="${ip_types["$ip"]:-}ssh,"
    done < <(grep -iE "Failed password|Invalid user" "$LOGFILE" 2>/dev/null | \
             grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -50)

    # من اتصالات SYN الحالية (SYN flood detection)
    while IFS= read -r line; do
        local ip count
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        [ -z "$ip" ] && continue
        ip_counts["$ip"]=$((${ip_counts["$ip"]:-0} + count))
        ip_types["$ip"]="${ip_types["$ip"]:-}syn,"
    done < <(ss -tn state syn-recv 2>/dev/null | \
             awk '{print $4}' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
             sort | uniq -c | sort -rn | head -50)

    if [ ${#ip_counts[@]} -eq 0 ]; then
        echo -e "  ${GREEN}No suspicious connection patterns detected${NC}"
        return
    fi

    echo -e "  ${GREY}IP Address          Attempts  Type          Action${NC}"
    echo -e "  ${GREY}──────────────────  ────────  ────────────  ──────────────${NC}"

    local total_warned=0 total_limited=0 total_tarpitted=0 total_blocked=0

    for ip in "${!ip_counts[@]}"; do
        local count=${ip_counts[$ip]}
        local types=${ip_types[$ip]}

        # تجاهل القائمة البيضاء
        if [ -n "${whitelist[$ip]:-}" ]; then
            continue
        fi

        # تصعيد تدريجي حسب عدد المحاولات
        local action badge
        if [ "$count" -ge 500 ]; then
            action="BLOCK"
            badge="${RED}[BLOCKED]${NC}"
            fw_block "$ip"
            ((total_blocked++))
            finding_add critical 2>/dev/null
        elif [ "$count" -ge 100 ]; then
            action="TARPIT"
            badge="${ORANGE}[TARPIT]${NC}"
            fw_tarpit "$ip"
            ((total_tarpitted++))
            finding_add high 2>/dev/null
        elif [ "$count" -ge 20 ]; then
            action="RATE-LIMIT"
            badge="${YELLOW}[LIMITED]${NC}"
            fw_rate_limit "$ip" 5 10
            ((total_limited++))
            finding_add medium 2>/dev/null
        else
            action="WARN"
            badge="${GREEN}[WARN]${NC}"
            ((total_warned++))
        fi

        printf "  %s %-18s %-8s %-13s %s\n" "$badge" "$ip" "$count" "$types" "$action"
    done

    # ملخص
    echo ""
    echo -e "  ${BOLD}Summary:${NC}"
    echo -e "    Warned: $total_warned | Rate-Limited: $total_limited | Tarpitted: $total_tarpitted | Blocked: $total_blocked"

    # تسجيل بسجل الأحداث
    raqib_log_event "adaptive_rate_limiter" "medium" \
        "Processed ${#ip_counts[@]} IPs: $total_blocked blocked, $total_tarpitted tarpitted, $total_limited limited" \
        2>/dev/null
}

# ─── إدارة القائمة البيضاء ──────────────────────────────────────
manage_whitelist() {
    echo -e "${CYAN}◉ Whitelist Management${NC}"
    echo ""
    echo -e "  ${CYAN}1)${NC} Show whitelist"
    echo -e "  ${CYAN}2)${NC} Add IP to whitelist"
    echo -e "  ${CYAN}3)${NC} Remove IP from whitelist"
    echo ""
    read -rp "  Choose [1-3]: " wl_choice

    case "$wl_choice" in
        1)
            if [ -f "$WHITELIST_FILE" ] && [ -s "$WHITELIST_FILE" ]; then
                echo ""
                echo -e "  ${GREEN}Whitelisted IPs:${NC}"
                grep -v '^#' "$WHITELIST_FILE" | while IFS= read -r ip; do
                    [ -n "$ip" ] && echo -e "    ✓ $ip"
                done
            else
                echo -e "  ${YELLOW}Whitelist is empty${NC}"
            fi
            ;;
        2)
            read -rp "  IP to whitelist: " new_ip
            if is_valid_ip "$new_ip" 2>/dev/null; then
                echo "$new_ip" >> "$WHITELIST_FILE"
                fw_unblock "$new_ip"
                echo -e "  ${GREEN}Added $new_ip to whitelist${NC}"
            else
                echo -e "${RED}  Invalid IP${NC}"
            fi
            ;;
        3)
            read -rp "  IP to remove: " del_ip
            if [ -f "$WHITELIST_FILE" ]; then
                grep -v "^${del_ip}$" "$WHITELIST_FILE" > "${WHITELIST_FILE}.tmp" 2>/dev/null
                mv "${WHITELIST_FILE}.tmp" "$WHITELIST_FILE"
                echo -e "  ${YELLOW}Removed $del_ip from whitelist${NC}"
            fi
            ;;
    esac
}

# ─── القائمة الرئيسية ─────────────────────────────────────────
echo -e "  ${CYAN}1)${NC} Auto-analyze & respond    — تحليل وتصعيد تلقائي"
echo -e "  ${CYAN}2)${NC} Manual rate-limit IP      — تحديد معدل يدوي"
echo -e "  ${CYAN}3)${NC} Manual tarpit IP          — كتم اتصال يدوي"
echo -e "  ${CYAN}4)${NC} Manual block IP           — حظر يدوي"
echo -e "  ${CYAN}5)${NC} Unblock IP                — رفع الحظر"
echo -e "  ${CYAN}6)${NC} Manage whitelist          — إدارة القائمة البيضاء"
echo -e "  ${CYAN}7)${NC} Show firewall status      — حالة جدار الحماية"
echo ""
read -rp "  Choose [1-7]: " main_choice

case "$main_choice" in
    1) fw_init_chain; analyze_and_respond ;;
    2)
        read -rp "  IP: " ip
        read -rp "  Rate (pkts/sec) [10]: " rate; rate=${rate:-10}
        fw_init_chain; fw_rate_limit "$ip" "$rate"
        echo -e "${GREEN}  Rate-limited: $ip at ${rate}/sec${NC}"
        ;;
    3)
        read -rp "  IP: " ip
        fw_init_chain; fw_tarpit "$ip"
        ;;
    4)
        read -rp "  IP: " ip
        fw_init_chain; fw_block "$ip"
        echo -e "${RED}  Blocked: $ip${NC}"
        ;;
    5)
        read -rp "  IP to unblock: " ip
        fw_unblock "$ip"
        echo -e "${GREEN}  Unblocked: $ip${NC}"
        ;;
    6) manage_whitelist ;;
    7)
        echo ""
        if [ "$FW_TYPE" = "nftables" ]; then
            nft list chain inet raqib_defense rate_control 2>/dev/null || \
                echo -e "  ${YELLOW}No RAQIB nftables chain found${NC}"
        elif [ "$FW_TYPE" = "iptables" ]; then
            iptables -L RAQIB_RATE -n -v 2>/dev/null || \
                echo -e "  ${YELLOW}No RAQIB iptables chain found${NC}"
        else
            echo -e "  ${RED}No firewall detected${NC}"
        fi
        ;;
    *) echo -e "${RED}  Invalid choice${NC}" ;;
esac

echo ""
pause 2>/dev/null || read -rp "Press Enter to continue..."
