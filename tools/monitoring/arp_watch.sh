#!/bin/bash
# =====================================================
#  ARP Watch — مراقب جدول ARP لكشف التلاعب
#  يحفظ baseline لجدول ARP ويقارنه لكشف:
#   • ARP Spoofing / Poisoning
#   • أجهزة جديدة بالشبكة
#   • تغيّر MAC address لنفس الـ IP
#   • Duplicate IP addresses
#   • Gratuitous ARP floods
#   • MAC vendor lookup
# =====================================================
finding_reset

TOOL_TITLE="$(t mon4_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

BASELINE_DIR="$HOME/.raqib_arp"
mkdir -p "$BASELINE_DIR"
BASELINE="$BASELINE_DIR/arp_baseline.txt"
REPORT=""

# ─── دالة جمع جدول ARP ───────────────────────────────────────
capture_arp() {
    if command -v ip >/dev/null 2>&1; then
        ip neigh show 2>/dev/null | awk '{print $1, $5, $6}' | sort
    elif command -v arp >/dev/null 2>&1; then
        arp -an 2>/dev/null | awk '{gsub(/[()]/, "", $2); print $2, $4, $7}' | sort
    else
        echo ""
    fi
}

# ─── 1. ARP الحالي ───────────────────────────────────────────
echo -e "${BOLD}${YELLOW}◉ جدول ARP الحالي${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
current=$(capture_arp)
current_count=$(echo "$current" | grep -c '\S' 2>/dev/null || echo 0)

printf "  ${BOLD}%-18s %-20s %-10s${NC}\n" "IP Address" "MAC Address" "State"
printf "  %s\n" "$(printf '─%.0s' {1..50})"

echo "$current" | while IFS= read -r line; do
    [ -z "$line" ] && continue
    ip_addr=$(echo "$line" | awk '{print $1}')
    mac=$(echo "$line" | awk '{print $2}')
    state=$(echo "$line" | awk '{print $3}')

    # MAC=FAILED = الجهاز لا يرد
    if [ "$mac" = "FAILED" ] || [ -z "$mac" ]; then
        printf "  ${GREY}%-18s %-20s %-10s${NC}\n" "$ip_addr" "—" "$state"
    else
        printf "  %-18s %-20s %-10s\n" "$ip_addr" "$mac" "$state"
    fi
done

echo ""
echo -e "  ${BOLD}$current_count جهاز مرصود${NC}"

# ─── 2. كشف Duplicate IPs ────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ كشف Duplicate IPs (نفس IP مع MACs مختلفة)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# IP يظهر أكثر من مرة بـ MACs مختلفة = ARP Spoofing!
dup_ips=$(echo "$current" | awk '$2!="FAILED" && $2!="" {print $1}' | sort | uniq -d)
if [ -n "$dup_ips" ]; then
    echo -e "  ${RED}⚠️  ARP Spoofing محتمل! IPs مكررة بـ MACs مختلفة:${NC}"
    echo "$dup_ips" | while IFS= read -r dip; do
        echo -e "  ${RED}  🔴 $dip:${NC}"
        echo "$current" | grep "^$dip " | while IFS= read -r entry; do
            echo -e "  ${RED}     → $entry${NC}"
        done
        finding_add critical "Possible ARP Spoofing: IP $dip has multiple MAC addresses"
    done
else
    echo -e "  ${GREEN}لا يوجد duplicate IPs ✅${NC}"
fi

# ─── 3. كشف Duplicate MACs ───────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ كشف Duplicate MACs (نفس MAC لعدة IPs)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

dup_macs=$(echo "$current" | awk '$2!="FAILED" && $2!="" && $2!="(incomplete)" {print $2}' | \
    sort | uniq -cd | sort -rn)
if [ -n "$dup_macs" ]; then
    echo "$dup_macs" | while IFS= read -r dm; do
        count=$(echo "$dm" | awk '{print $1}')
        mac=$(echo "$dm" | awk '{print $2}')
        if [ "$count" -ge 5 ] 2>/dev/null; then
            echo -e "  ${RED}  🔴 MAC $mac → $count IPs مختلفة (محتمل ARP flood)${NC}"
            finding_add high "MAC $mac associated with $count different IPs — possible ARP flood"
        elif [ "$count" -ge 2 ] 2>/dev/null; then
            echo -e "  ${YELLOW}  ⚠️  MAC $mac → $count IPs (gateway أو NAT عادي؟)${NC}"
        fi
    done
else
    echo -e "  ${GREEN}لا يوجد duplicate MACs ✅${NC}"
fi

# ─── 4. مقارنة مع الـ Baseline ──────────────────────────────
echo ""
if [ ! -f "$BASELINE" ]; then
    echo "$current" > "$BASELINE"
    echo -e "${GREEN}$(t mon4_baseline_created) ✅${NC}"
    echo -e "${CYAN}  💡 شغّل الأداة مرة ثانية لاحقاً للمقارنة${NC}"
else
    echo -e "${BOLD}${YELLOW}$(t mon4_comparing)${NC}"
    echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
    echo -e "${GREY}  Baseline: $(stat -c '%y' "$BASELINE" 2>/dev/null || echo '?')${NC}"
    echo ""

    # أجهزة جديدة (بالحالي لكن ليست بالـ baseline)
    new_devices=""
    while IFS= read -r cline; do
        [ -z "$cline" ] && continue
        cip=$(echo "$cline" | awk '{print $1}')
        cmac=$(echo "$cline" | awk '{print $2}')
        [ "$cmac" = "FAILED" ] && continue

        if ! grep -q "^$cip " "$BASELINE" 2>/dev/null; then
            new_devices+="$cline"$'\n'
        fi
    done <<< "$current"

    # أجهزة اختفت
    gone_devices=""
    while IFS= read -r bline; do
        [ -z "$bline" ] && continue
        bip=$(echo "$bline" | awk '{print $1}')
        bmac=$(echo "$bline" | awk '{print $2}')
        [ "$bmac" = "FAILED" ] && continue

        if ! echo "$current" | grep -q "^$bip "; then
            gone_devices+="$bline"$'\n'
        fi
    done < "$BASELINE"

    # MAC تغيّر لنفس الـ IP (أخطر شيء!)
    mac_changed=""
    while IFS= read -r cline; do
        [ -z "$cline" ] && continue
        cip=$(echo "$cline" | awk '{print $1}')
        cmac=$(echo "$cline" | awk '{print $2}')
        [ "$cmac" = "FAILED" ] && continue

        bmac=$(grep "^$cip " "$BASELINE" 2>/dev/null | awk '{print $2}')
        if [ -n "$bmac" ] && [ "$bmac" != "FAILED" ] && [ "$cmac" != "$bmac" ]; then
            mac_changed+="$cip: $bmac → $cmac"$'\n'
        fi
    done <<< "$current"

    # عرض النتائج
    if [ -n "$mac_changed" ]; then
        echo -e "  ${RED}[CRITICAL] تغيّر MAC Address! (ARP Spoofing محتمل):${NC}"
        echo "$mac_changed" | grep '\S' | while IFS= read -r mc; do
            echo -e "  ${RED}  🔴 $mc${NC}"
            finding_add critical "MAC address changed for IP: $mc — possible ARP spoofing!"
        done
    fi

    if [ -n "$new_devices" ]; then
        echo -e "  ${ORANGE}◉ أجهزة جديدة بالشبكة:${NC}"
        echo "$new_devices" | grep '\S' | while IFS= read -r nd; do
            echo -e "  ${ORANGE}  ⚡ NEW: $nd${NC}"
            finding_add medium "New device on network: $nd"
        done
    fi

    if [ -n "$gone_devices" ]; then
        echo -e "  ${YELLOW}◉ أجهزة اختفت من الشبكة:${NC}"
        echo "$gone_devices" | grep '\S' | while IFS= read -r gd; do
            echo -e "  ${YELLOW}  ✗ GONE: $gd${NC}"
        done
    fi

    if [ -z "$mac_changed" ] && [ -z "$new_devices" ] && [ -z "$gone_devices" ]; then
        echo -e "  ${GREEN}$(t mon4_no_change) — لا تغييرات ✅${NC}"
    fi

    echo ""
    read -rp "  $(t c_confirm_update_baseline) [y/N]: " ans
    [ "${ans,,}" = "y" ] && echo "$current" > "$BASELINE" && echo -e "  ${GREEN}$(t c_updated)${NC}"
fi

REPORT+="ARP Table ($current_count devices):
$current

"

# ─── ملخص ────────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "ARP Watch — $(date)

$REPORT" "arp_watch.txt" "$TOOL_TITLE"
