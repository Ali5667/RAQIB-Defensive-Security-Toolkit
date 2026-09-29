#!/bin/bash
# =====================================================
#  Connection Rate Watcher — مراقب معدل الاتصالات
#  يأخذ 3 لقطات بفاصل زمني ويحلل:
#   • ارتفاع مفاجئ في الاتصالات (DDoS/scan)
#   • IP واحد بعدد اتصالات كبير جداً
#   • بورت معين تحت ضغط
#   • معدل اتصالات في الثانية
#   • كشف port scan (IPs تتصل بمنافذ متعددة)
# =====================================================
finding_reset

TOOL_TITLE="$(t ids5_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${YELLOW}$(t ids5_desc)${NC}"
echo ""

# إعدادات تنبيه
SPIKE_THRESHOLD=50    # زيادة >50 اتصال بين لقطتين = تنبيه
IP_THRESHOLD=20       # >20 اتصال من IP واحد = تنبيه
SCAN_THRESHOLD=10     # >10 منافذ مختلفة من IP = port scan

REPORT=""

# ─── دالة جمع إحصاءات الاتصالات ────────────────────────────
take_snapshot() {
    if command -v ss >/dev/null 2>&1; then
        ss -tn state established 2>/dev/null
    else
        netstat -tn 2>/dev/null | grep ESTABLISHED
    fi
}

# ─── دالة تحليل الاتصالات ────────────────────────────────────
analyze_connections() {
    local data="$1"
    # عدد الاتصالات لكل Remote IP (بدون port)
    echo "$data" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
        sort | uniq -c | sort -rn
}

# ─── دالة كشف Port Scan ──────────────────────────────────────
detect_port_scan() {
    local data="$1"
    # كم منفذ مختلف من كل IP
    if command -v ss >/dev/null 2>&1; then
        echo "$data" | awk 'NR>1 {print $4}' | \
            sed -E 's/.*:([0-9]+)/\1/' | sort -u
    fi
}

# ─── لقطة 1 ─────────────────────────────────────────────────
echo -e "${CYAN}$(t ids5_first_snapshot) [$(date '+%H:%M:%S')]${NC}"
snap1_raw=$(take_snapshot)
snap1_count=$(echo "$snap1_raw" | grep -c '.' 2>/dev/null || echo 0)
snap1_by_ip=$(analyze_connections "$snap1_raw")

echo -e "  ${BOLD}$snap1_count اتصال نشط${NC}"
echo ""
echo -e "  ${YELLOW}أعلى IPs:${NC}"
echo "$snap1_by_ip" | head -10 | while IFS= read -r line; do
    count=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line" | awk '{print $2}')
    printf "  %-6s اتصال  →  %s\n" "$count" "$ip"
done

REPORT+="=== Snapshot 1 [$(date '+%H:%M:%S')] ===
Total: $snap1_count
$snap1_by_ip

"

# ─── انتظار ──────────────────────────────────────────────────
WAIT_SECS=5
echo ""
for i in $(seq $WAIT_SECS -1 1); do
    printf "\r  ${YELLOW}⏳ انتظار $i ثانية...${NC}  "
    sleep 1
done
printf "\r$(printf ' %.0s' {1..40})\r"

# ─── لقطة 2 ─────────────────────────────────────────────────
echo -e "${CYAN}$(t ids5_second_snapshot) [$(date '+%H:%M:%S')]${NC}"
snap2_raw=$(take_snapshot)
snap2_count=$(echo "$snap2_raw" | grep -c '.' 2>/dev/null || echo 0)
snap2_by_ip=$(analyze_connections "$snap2_raw")

echo -e "  ${BOLD}$snap2_count اتصال نشط${NC}"
echo ""
echo -e "  ${YELLOW}أعلى IPs:${NC}"
echo "$snap2_by_ip" | head -10 | while IFS= read -r line; do
    count=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line" | awk '{print $2}')

    # فحص: هل هذا IP كان موجوداً باللقطة الأولى؟
    prev_count=$(echo "$snap1_by_ip" | awk -v target="$ip" '$2==target {print $1}')
    prev_count="${prev_count:-0}"
    delta=$((count - prev_count))

    if [ "$count" -ge "$IP_THRESHOLD" ]; then
        echo -e "  ${RED}⚠️  $count اتصال (+${delta})  →  $ip${NC}"
        finding_add high "High connection count from single IP: $ip ($count connections)"
    elif [ "$delta" -ge 10 ] 2>/dev/null; then
        echo -e "  ${ORANGE}📈 $count اتصال (+${delta})  →  $ip${NC}"
        finding_add medium "Connection spike from $ip: +$delta new connections"
    else
        printf "  %-6s اتصال (+%s)  →  %s\n" "$count" "$delta" "$ip"
    fi
done

REPORT+="=== Snapshot 2 [$(date '+%H:%M:%S')] ===
Total: $snap2_count
$snap2_by_ip

"

# ─── تحليل Delta ──────────────────────────────────────────────
echo ""
delta_total=$((snap2_count - snap1_count))
echo -e "${YELLOW}$(t ids5_high_conn)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
echo -e "  لقطة 1: $snap1_count اتصال"
echo -e "  لقطة 2: $snap2_count اتصال"
echo -e "  الفرق:  $([ "$delta_total" -ge 0 ] && echo "+")$delta_total اتصال في $WAIT_SECS ثانية"
echo -e "  معدل:   $(echo "scale=1; $delta_total / $WAIT_SECS" | bc 2>/dev/null || echo "?") اتصال/ثانية"

if [ "$delta_total" -ge "$SPIKE_THRESHOLD" ] 2>/dev/null; then
    echo -e "  ${RED}[CRITICAL] ارتفاع مفاجئ! ${delta_total}+ اتصال خلال ${WAIT_SECS} ثوانٍ — محتمل DDoS/Scan${NC}"
    finding_add critical "Connection spike: +$delta_total connections in ${WAIT_SECS}s — possible DDoS"
elif [ "$delta_total" -ge 20 ] 2>/dev/null; then
    echo -e "  ${ORANGE}[HIGH] ارتفاع ملحوظ في الاتصالات${NC}"
    finding_add high "Connection surge: +$delta_total connections in ${WAIT_SECS}s"
elif [ "$snap2_count" -ge 500 ] 2>/dev/null; then
    echo -e "  ${ORANGE}[HIGH] عدد اتصالات عالٍ جداً: $snap2_count${NC}"
    finding_add high "Very high connection count: $snap2_count"
else
    echo -e "  ${GREEN}الاتصالات طبيعية${NC}"
fi

# ─── كشف Port Scan ───────────────────────────────────────────
echo ""
echo -e "${YELLOW}◉ كشف Port Scan (IP يتصل بمنافذ متعددة جداً)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# استخرج Remote IPs ومنافذها (Local port)
if command -v ss >/dev/null 2>&1; then
    port_scan_check=$(ss -tn state established 2>/dev/null | awk 'NR>1 {
        local=$4; remote=$5
        split(remote, rparts, ":")
        remote_ip = rparts[1]
        split(local, lparts, ":")
        local_port = lparts[length(lparts)]
        print remote_ip, local_port
    }' | sort | uniq | awk '{print $1}' | sort | uniq -c | sort -rn | head -10)
else
    port_scan_check=$(netstat -tn 2>/dev/null | awk '$6=="ESTABLISHED" {
        split($4, lparts, ":")
        split($5, rparts, ":")
        print rparts[1], lparts[length(lparts)]
    }' | sort | uniq | awk '{print $1}' | sort | uniq -c | sort -rn | head -10)
fi

if [ -n "$port_scan_check" ]; then
    echo "$port_scan_check" | while IFS= read -r psline; do
        port_count=$(echo "$psline" | awk '{print $1}')
        scan_ip=$(echo "$psline" | awk '{print $2}')
        if [ "$port_count" -ge "$SCAN_THRESHOLD" ] 2>/dev/null; then
            echo -e "  ${RED}[HIGH] Port Scan من $scan_ip — $port_count منافذ مختلفة${NC}"
            finding_add high "Port scan detected from $scan_ip: $port_count distinct ports"
        fi
    done
else
    echo -e "  ${GREEN}لا يوجد port scan مكشوف حالياً${NC}"
fi

# ─── لقطة 3 (اختيارية) ──────────────────────────────────────
echo ""
read -rp "  هل تريد لقطة ثالثة بعد 10 ثوانٍ للتأكيد؟ [y/N]: " third_ans
if [ "${third_ans,,}" = "y" ]; then
    for i in $(seq 10 -1 1); do
        printf "\r  ${YELLOW}⏳ انتظار $i ثانية...${NC}  "
        sleep 1
    done
    printf "\r$(printf ' %.0s' {1..40})\r"
    snap3_raw=$(take_snapshot)
    snap3_count=$(echo "$snap3_raw" | grep -c '.' 2>/dev/null || echo 0)
    snap3_delta=$((snap3_count - snap2_count))
    echo -e "\n  ${BOLD}لقطة 3 [$(date '+%H:%M:%S')]: $snap3_count اتصال ($([ "$snap3_delta" -ge 0 ] && echo "+")${snap3_delta})${NC}"

    if [ "$snap3_delta" -ge "$SPIKE_THRESHOLD" ] 2>/dev/null; then
        echo -e "  ${RED}[CRITICAL] الهجوم مستمر! ارتفاع $snap3_delta اتصال${NC}"
        finding_add critical "Ongoing attack: +$snap3_delta connections in second interval"
    fi
fi

# ─── ملخص وتوصيات ────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

[ -n "$snap1_by_ip" ] && save_report "$REPORT" "connection_rate_watch.txt" "$TOOL_TITLE"
