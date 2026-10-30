#!/bin/bash
# =====================================================
#  Bandwidth Monitor — مراقب عرض النطاق الترددي
#  يراقب: RX/TX بالثانية لواجهة الشبكة مع رسم بياني
#  يحلل: طفرات مفاجئة (spikes)، حد bandwidth مرتفع
#  يدعم: مراقبة مستمرة، كل الواجهات، ملخص تراكمي
#  المنصات: Linux (/sys/class/net) · macOS (netstat -ib) · Windows (Get-NetAdapterStatistics)
# =====================================================
finding_reset

TOOL_TITLE="$(t mon3_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ============================================================================
#  دوال العدّادات حسب المنصة:
#   Linux   : /sys/class/net/<iface>/statistics/{rx,tx}_bytes
#   macOS   : netstat -ib   (أعمدة Ibytes/Obytes من صف <Link>)
#   Windows : Get-NetAdapterStatistics (Received / Sent bytes)
#  (WSL يعامل كLinux — لينكس أصلي)
# ============================================================================
if raqib_is_macos; then
    bw_rx_bytes() { netstat -ib 2>/dev/null | awk -v IF="$1" '$1 == IF && $3 ~ /^<|^Link/ {print $7; exit}'; }
    bw_tx_bytes() { netstat -ib 2>/dev/null | awk -v IF="$1" '$1 == IF && $3 ~ /^<|^Link/ {print $10; exit}'; }
    bw_list_ifaces() { netstat -ib 2>/dev/null | awk '$1 != "Name" && NF >= 10 {print $1}' | sort -u | grep -v '^lo0$'; }
    bw_iface_ip()     { ipconfig getifaddr "$1" 2>/dev/null; }
    bw_iface_status() { ifconfig "$1" 2>/dev/null | awk '/status/ {print $2}'; }
elif raqib_is_windows && raqib_has_windows_bridge; then
    bw_win_counters() {
        raqib_win_ps "
            try {
                \$s = Get-NetAdapterStatistics -Name '$1' -ErrorAction Stop
                \"{0}|{1}\" -f \$s.ReceivedBytes, \$s.SentBytes
            } catch { }
        " 2>/dev/null
    }
    bw_rx_bytes() {
        _bwcc="$(bw_win_counters "$1")"
        printf '%s' "${_bwcc%%|*}"
    }
    bw_tx_bytes() {
        _bwcc="$(bw_win_counters "$1")"
        printf '%s' "${_bwcc#*|}"
    }
    bw_list_ifaces() {
        raqib_win_ps '
            Get-NetAdapterStatistics | ForEach-Object { $_.Name }
        ' 2>/dev/null
    }
    bw_iface_ip() {
        raqib_win_ps "
            try {
                (Get-NetIPAddress -InterfaceAlias '$1' -AddressFamily IPv4 -ErrorAction Stop).IPAddress
            } catch { }
        " 2>/dev/null
    }
    bw_iface_status() {
        raqib_win_ps "
            try {
                (Get-NetAdapter -Name '$1' -ErrorAction Stop).Status
            } catch { }
        " 2>/dev/null
    }
else
    # Linux / WSL — عدّادات sysfs الأصلية
    if [ ! -d /sys/class/net ]; then
        echo -e "${RED}$(t mon3_no_sysfs)${NC}"
        exit 1
    fi
    bw_rx_bytes() { cat "/sys/class/net/$1/statistics/rx_bytes" 2>/dev/null || echo 0; }
    bw_tx_bytes() { cat "/sys/class/net/$1/statistics/tx_bytes" 2>/dev/null || echo 0; }
    bw_list_ifaces() { ls /sys/class/net/ 2>/dev/null | grep -v '^lo$'; }
    bw_iface_ip()     { ip -4 addr show "$1" 2>/dev/null | grep -oE 'inet [0-9.]+' | awk '{print $2}' | head -1; }
    bw_iface_status() { cat "/sys/class/net/$1/operstate" 2>/dev/null || echo "?"; }
fi

# ─── عرض الواجهات المتوفرة ────────────────────────────────────
echo -e "${YELLOW}◉ واجهات الشبكة المتوفرة:${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
printf "  ${BOLD}%-12s %-18s %-10s %-15s %s${NC}\n" "INTERFACE" "IP" "STATUS" "RX Total" "TX Total"
printf "  %s\n" "$(printf '─%.0s' {1..70})"

IFACE_LIST="$(bw_list_ifaces 2>/dev/null | grep -v '^lo$' || true)"

printf '%s\n' "$IFACE_LIST" | while IFS= read -r bw_iface; do
    [ -z "$bw_iface" ] && continue

    # حالة الواجهة + IP
    status=$(bw_iface_status "$bw_iface")
    ip_addr=$(bw_iface_ip "$bw_iface")
    ip_addr="${ip_addr:-—}"

    # إحصاءات تراكمية
    rx_total=$(bw_rx_bytes "$bw_iface")
    tx_total=$(bw_tx_bytes "$bw_iface")
    case "$rx_total" in ''|*[!0-9]*) rx_total=0 ;; esac
    case "$tx_total" in ''|*[!0-9]*) tx_total=0 ;; esac

    # تحويل لوحدات مقروءة
    rx_human=$(awk "BEGIN{printf \"%.1f MB\", $rx_total/1048576}")
    tx_human=$(awk "BEGIN{printf \"%.1f MB\", $tx_total/1048576}")

    # تلوين الحالة
    if [ "$status" = "up" ] || [ "$status" = "active" ]; then
        printf "  ${GREEN}%-12s${NC} %-18s ${GREEN}%-10s${NC} %-15s %s\n" \
            "$bw_iface" "$ip_addr" "$status" "$rx_human" "$tx_human"
    else
        printf "  ${GREY}%-12s${NC} %-18s ${GREY}%-10s${NC} %-15s %s\n" \
            "$bw_iface" "$ip_addr" "$status" "$rx_human" "$tx_human"
    fi
done
echo ""

# ─── اختيار الواجهة ───────────────────────────────────────────
read -rp "$(t mon3_prompt_iface) " iface
if [ -z "$iface" ]; then
    iface="$(printf '%s\n' "$IFACE_LIST" | head -1)"
fi
_iface_ok=0
if [ -n "$iface" ]; then
    printf '%s\n' "$IFACE_LIST" | grep -qx "$iface" && _iface_ok=1
fi
if [ "$_iface_ok" -ne 1 ]; then
    echo -e "${RED}$(t mon3_iface_not_found)${NC}"
    printf '%s\n' "$IFACE_LIST"
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

rx1=$(bw_rx_bytes "$iface")
tx1=$(bw_tx_bytes "$iface")
case "$rx1" in ''|*[!0-9]*) rx1=0 ;; esac
case "$tx1" in ''|*[!0-9]*) tx1=0 ;; esac

# تتبع البيانات للملخص
total_rx_delta=0
total_tx_delta=0
max_rx=0
max_tx=0
spike_count=0
REPORT=""

for i in $(seq 1 "$duration"); do
    sleep 1
    rx2=$(bw_rx_bytes "$iface")
    tx2=$(bw_tx_bytes "$iface")
    case "$rx2" in ''|*[!0-9]*) rx2=$rx1 ;; esac
    case "$tx2" in ''|*[!0-9]*) tx2=$tx1 ;; esac
    rx_rate=$(( (rx2 - rx1) / 1024 ))
    if [ "$rx_rate" -lt 0 ]; then rx_rate=0; fi
    tx_rate=$(( (tx2 - tx1) / 1024 ))
    if [ "$tx_rate" -lt 0 ]; then tx_rate=0; fi

    total_rx_delta=$((total_rx_delta + rx_rate))
    total_tx_delta=$((total_tx_delta + tx_rate))
    [ "$rx_rate" -gt "$max_rx" ] && max_rx=$rx_rate
    [ "$tx_rate" -gt "$max_tx" ] && max_tx=$tx_rate

    # رسم بار
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
Platform: $(raqib_os_label 2>/dev/null || echo "${RAQIB_OS:-unknown}")
Interface: $iface
Duration: ${duration}s
Avg RX: $avg_rx KB/s | Max RX: $max_rx KB/s | Total RX: $total_rx_mb MB
Avg TX: $avg_tx KB/s | Max TX: $max_tx KB/s | Total TX: $total_tx_mb MB
Spikes: $spike_count" "bandwidth_monitor_${iface}.txt" "$TOOL_TITLE"
