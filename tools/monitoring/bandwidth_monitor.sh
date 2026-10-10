#!/bin/bash
# =====================================================
#  Bandwidth Monitor — مراقب عرض النطاق الترددي
#  يراقب: RX/TX بالثانية لواجهة الشبكة مع رسم بياني
#  يحلل: طفرات مفاجئة (spikes)، حد bandwidth مرتفع
#  يدعم: مراقبة مستمرة، كل الواجهات، ملخص تراكمي
# =====================================================
finding_reset

TOOL_TITLE="$(t mon3_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

if [ ! -d /sys/class/net ]; then
    echo -e "${RED}$(t mon3_no_sysfs)${NC}"
    exit 1
fi

# ─── عرض الواجهات المتوفرة ────────────────────────────────────
echo -e "${YELLOW}◉ واجهات الشبكة المتوفرة:${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
printf "  ${BOLD}%-12s %-18s %-10s %-15s %s${NC}\n" "INTERFACE" "IP" "STATUS" "RX Total" "TX Total"
printf "  %s\n" "$(printf '─%.0s' {1..70})"

for iface_path in /sys/class/net/*/; do
    iface=$(basename "$iface_path")
    [ "$iface" = "lo" ] && continue

    # حالة الواجهة
    status=$(cat "/sys/class/net/$iface/operstate" 2>/dev/null || echo "?")
    ip_addr=$(ip -4 addr show "$iface" 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1)
    ip_addr="${ip_addr:-—}"

    # إحصاءات تراكمية
    rx_total=$(cat "/sys/class/net/$iface/statistics/rx_bytes" 2>/dev/null || echo 0)
    tx_total=$(cat "/sys/class/net/$iface/statistics/tx_bytes" 2>/dev/null || echo 0)

    # تحويل لوحدات مقروءة
    rx_human=$(awk "BEGIN{printf \"%.1f MB\", $rx_total/1048576}")
    tx_human=$(awk "BEGIN{printf \"%.1f MB\", $tx_total/1048576}")

    # تلوين الحالة
    if [ "$status" = "up" ]; then
        printf "  ${GREEN}%-12s${NC} %-18s ${GREEN}%-10s${NC} %-15s %s\n" \
            "$iface" "$ip_addr" "$status" "$rx_human" "$tx_human"
    else
        printf "  ${GREY}%-12s${NC} %-18s ${GREY}%-10s${NC} %-15s %s\n" \
            "$iface" "$ip_addr" "$status" "$rx_human" "$tx_human"
    fi
done
echo ""

# ─── اختيار الواجهة ───────────────────────────────────────────
read -rp "$(t mon3_prompt_iface) " iface
if [ -z "$iface" ]; then
    iface=$(raqib_default_iface)
fi
if [ -z "$iface" ] || [ ! -d "/sys/class/net/$iface" ]; then
    echo -e "${RED}$(t mon3_iface_not_found)${NC}"
    ls /sys/class/net/
    exit 1
fi

# مدة المراقبة
read -rp "  مدة المراقبة بالثواني [افتراضي: 30]: " duration
duration="${duration:-30}"
[[ "$duration" =~ ^[0-9]+$ ]] || duration=30

echo ""
echo -e "${YELLOW}$(tf mon3_monitoring "$iface") — $duration ثانية${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
printf "  ${BOLD}%-5s %-12s %-12s %-30s${NC}\n" "SEC" "↓ RX KB/s" "↑ TX KB/s" "GRAPH"
printf "  %s\n" "$(printf '─%.0s' {1..60})"

rx1=$(cat /sys/class/net/"$iface"/statistics/rx_bytes)
tx1=$(cat /sys/class/net/"$iface"/statistics/tx_bytes)

# تتبع البيانات للملخص
total_rx_delta=0
total_tx_delta=0
max_rx=0
max_tx=0
spike_count=0
REPORT=""

for i in $(seq 1 "$duration"); do
    sleep 1
    rx2=$(cat /sys/class/net/"$iface"/statistics/rx_bytes)
    tx2=$(cat /sys/class/net/"$iface"/statistics/tx_bytes)
    rx_rate=$(( (rx2 - rx1) / 1024 ))
    tx_rate=$(( (tx2 - tx1) / 1024 ))

    total_rx_delta=$((total_rx_delta + rx_rate))
    total_tx_delta=$((total_tx_delta + tx_rate))
    [ "$rx_rate" -gt "$max_rx" ] && max_rx=$rx_rate
    [ "$tx_rate" -gt "$max_tx" ] && max_tx=$tx_rate

    # رسم بار
    bar_rx=""
    bar_tx=""
    rx_blocks=$((rx_rate / 50 + 1))
    tx_blocks=$((tx_rate / 50 + 1))
    [ "$rx_blocks" -gt 15 ] && rx_blocks=15
    [ "$tx_blocks" -gt 15 ] && tx_blocks=15
    bar_rx=$(printf '▓%.0s' $(seq 1 "$rx_blocks") 2>/dev/null || echo "=")
    bar_tx=$(printf '░%.0s' $(seq 1 "$tx_blocks") 2>/dev/null || echo "-")

    # تلوين حسب الحجم
    if [ "$rx_rate" -gt 5000 ]; then
        rx_color="$RED"
        spike_count=$((spike_count + 1))
    elif [ "$rx_rate" -gt 1000 ]; then
        rx_color="$ORANGE"
    else
        rx_color="$GREEN"
    fi

    printf "\r\033[K  ${rx_color}%-5s %-12s %-12s %s${NC}\n" \
        "$i" "${rx_rate} KB/s" "${tx_rate} KB/s" "${bar_rx}${bar_tx}"

    rx1=$rx2; tx1=$tx2
    draw_progress_bar "$i" "$duration" "$iface" 2>/dev/null
done
finish_progress_bar 2>/dev/null

# ─── ملخص المراقبة ───────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ ملخص المراقبة ($duration ثانية) ━━${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

avg_rx=$((total_rx_delta / duration))
avg_tx=$((total_tx_delta / duration))
total_rx_mb=$(awk "BEGIN{printf \"%.2f\", $total_rx_delta/1024}")
total_tx_mb=$(awk "BEGIN{printf \"%.2f\", $total_tx_delta/1024}")

echo -e "  ${CYAN}الواجهة:${NC}   $iface"
echo -e "  ${CYAN}المدة:${NC}     $duration ثانية"
echo ""
echo -e "  ${GREEN}↓ Download:${NC}"
echo -e "    المعدل:     ${BOLD}$avg_rx KB/s${NC}"
echo -e "    الأعلى:     ${BOLD}$max_rx KB/s${NC}"
echo -e "    الإجمالي:   ${BOLD}$total_rx_mb MB${NC}"
echo ""
echo -e "  ${ORANGE}↑ Upload:${NC}"
echo -e "    المعدل:     ${BOLD}$avg_tx KB/s${NC}"
echo -e "    الأعلى:     ${BOLD}$max_tx KB/s${NC}"
echo -e "    الإجمالي:   ${BOLD}$total_tx_mb MB${NC}"

if [ "$spike_count" -gt 0 ]; then
    echo ""
    echo -e "  ${RED}⚠️  $spike_count طفرات (>5 MB/s) — تحقق من DDoS أو تنزيل ضخم${NC}"
    finding_add medium "Bandwidth spikes detected: $spike_count times over 5 MB/s on $iface"
fi

if [ "$avg_rx" -gt 10000 ]; then
    finding_add high "Very high average download rate: $avg_rx KB/s on $iface"
fi

# ─── خلاصة ──────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Bandwidth Monitor — $(date)
Interface: $iface
Duration: ${duration}s
Avg RX: $avg_rx KB/s | Max RX: $max_rx KB/s | Total RX: $total_rx_mb MB
Avg TX: $avg_tx KB/s | Max TX: $max_tx KB/s | Total TX: $total_tx_mb MB
Spikes: $spike_count" "bandwidth_monitor_${iface}.txt" "$TOOL_TITLE"
