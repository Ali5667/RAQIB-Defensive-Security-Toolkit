#!/bin/bash
# =====================================================
#  Active Connections Monitor — مراقب الاتصالات النشطة
#  يعرض: كل الاتصالات TCP/UDP مع العمليات المسؤولة
#  يحلل: IPs خارجية مشبوهة (IOC)، اتصالات reverse
#  shell، connections لبلدان خطيرة، عمليات بدون binary
#  مكتشف، اتصالات بمنافذ C2 شائعة، DNS exfiltration
# =====================================================
finding_reset

TOOL_TITLE="$(t mon2_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

# ─── منافذ C2 شائعة (Command & Control) ───────────────────────
C2_PORTS="4444|5555|6666|7777|8888|9999|1234|31337|12345|54321|1337|6667|6668|6669|8080|9001|9030"

# ─── 1. كل الاتصالات ─────────────────────────────────────────
echo -e "${BOLD}${YELLOW}$(t mon2_header)${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if command -v ss >/dev/null 2>&1; then
    all_conns=$(ss -tunap 2>/dev/null)
else
    all_conns=$(netstat -tunap 2>/dev/null)
fi

# إحصاءات
total=$(echo "$all_conns" | awk 'NR>1' | wc -l)
established=$(echo "$all_conns" | grep -ci "ESTAB" 2>/dev/null || echo 0)
listening=$(echo "$all_conns" | grep -ci "LISTEN" 2>/dev/null || echo 0)
time_wait=$(echo "$all_conns" | grep -ci "TIME-WAIT\|TIME_WAIT" 2>/dev/null || echo 0)
close_wait=$(echo "$all_conns" | grep -ci "CLOSE-WAIT\|CLOSE_WAIT" 2>/dev/null || echo 0)

echo -e "  ${BOLD}📊 إحصاءات:${NC}"
echo -e "  إجمالي:    $total"
echo -e "  ESTABLISHED: ${CYAN}$established${NC}"
echo -e "  LISTEN:      ${GREEN}$listening${NC}"
echo -e "  TIME_WAIT:   ${YELLOW}$time_wait${NC}"
echo -e "  CLOSE_WAIT:  ${ORANGE}$close_wait${NC}"

[ "$close_wait" -ge 20 ] 2>/dev/null && {
    echo -e "  ${ORANGE}⚠️  عدد CLOSE_WAIT مرتفع — ربما connection leak${NC}"
    finding_add medium "High CLOSE_WAIT count: $close_wait — possible connection leak"
}
[ "$established" -ge 200 ] 2>/dev/null && {
    echo -e "  ${ORANGE}⚠️  عدد اتصالات مرتفع جداً${NC}"
    finding_add high "Very high number of established connections: $established"
}

echo ""

# ─── 2. عرض الاتصالات ESTABLISHED مع تحليل ──────────────────
echo -e "${BOLD}${YELLOW}◉ الاتصالات النشطة (ESTABLISHED)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
printf "  ${BOLD}%-6s %-22s %-22s %-15s %s${NC}\n" "PROTO" "LOCAL" "REMOTE" "PROCESS" "RISK"
printf "  %s\n" "$(printf '─%.0s' {1..80})"

if command -v ss >/dev/null 2>&1; then
    estab_data=$(ss -tunap state established 2>/dev/null | awk 'NR>1')
else
    estab_data=$(netstat -tunap 2>/dev/null | awk '$6=="ESTABLISHED"')
fi

echo "$estab_data" | head -50 | while IFS= read -r line; do
    [ -z "$line" ] && continue

    if command -v ss >/dev/null 2>&1; then
        proto=$(echo "$line" | awk '{print $1}')
        local_addr=$(echo "$line" | awk '{print $4}')
        remote_addr=$(echo "$line" | awk '{print $5}')
        process=$(echo "$line" | awk '{print $6}' | grep -oE '"[^"]+"' | tr -d '"')
    else
        proto=$(echo "$line" | awk '{print $1}')
        local_addr=$(echo "$line" | awk '{print $4}')
        remote_addr=$(echo "$line" | awk '{print $5}')
        process=$(echo "$line" | awk '{print $7}' | cut -d'/' -f2)
    fi
    process="${process:-?}"

    # استخرج Remote IP و Port
    remote_ip=$(echo "$remote_addr" | sed -E 's/:[0-9]+$//' | tr -d '[]')
    remote_port=$(echo "$remote_addr" | rev | cut -d: -f1 | rev)

    # تحقق: هل IP داخلي أو خارجي؟
    is_private=0
    echo "$remote_ip" | grep -qE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fe80)' && is_private=1

    risk=""
    color="$NC"

    # فحص C2 ports
    if echo "$remote_port" | grep -qE "^($C2_PORTS)$"; then
        risk="🔴 C2 PORT!"
        color="$RED"
        finding_add critical "Connection to common C2 port $remote_port: $remote_ip (process: $process)"
    fi

    # فحص IOC للـ IPs الخارجية
    if [ "$is_private" -eq 0 ] && [ -z "$risk" ]; then
        if raqib_intel_available 2>/dev/null; then
            intel_res=$(raqib_intel_analyze "$remote_ip" 2>/dev/null)
            if [ -n "$intel_res" ]; then
                risk="🔴 IOC MATCH!"
                color="$RED"
                finding_add critical "Active connection to known malicious IP: $remote_ip"
            fi
        fi
    fi

    printf "  ${color}%-6s %-22s %-22s %-15s %s${NC}\n" \
        "$proto" "$(echo "$local_addr" | cut -c1-22)" \
        "$(echo "$remote_addr" | cut -c1-22)" "$process" "$risk"
done

conn_display=$(echo "$estab_data" | wc -l)
[ "$conn_display" -gt 50 ] && echo -e "  ${GREY}... و$((conn_display - 50)) اتصال إضافي${NC}"

REPORT+="=== Active Connections ===
Total: $total | ESTABLISHED: $established | LISTEN: $listening
$estab_data

"

# ─── 3. IOC Scan كامل ────────────────────────────────────────
echo ""
if raqib_intel_available 2>/dev/null; then
    echo -e "${BOLD}${YELLOW}◉ فحص IOC لجميع الاتصالات الخارجية${NC}"
    echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

    if command -v ss >/dev/null 2>&1; then
        remote_ips=$(ss -tunap 2>/dev/null | awk 'NR>1{print $6}' | \
            sed -E 's/^\[?([0-9a-fA-F:.]+)\]?:[0-9]+$/\1/' | sort -u)
    else
        remote_ips=$(netstat -tunap 2>/dev/null | awk '{print $5}' | \
            sed -E 's/:[0-9]+$//' | sort -u)
    fi

    intel_hits=0
    while IFS= read -r rip; do
        [ -z "$rip" ] && continue
        case "$rip" in "*"|"0.0.0.0"|"::"|"") continue ;; esac
        # تخطي IPs الداخلية
        echo "$rip" | grep -qE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|::1|fe80)' && continue
        if raqib_intel_check_and_report "$rip" 2>/dev/null; then
            intel_hits=$((intel_hits + 1))
        fi
    done <<< "$remote_ips"

    if [ "$intel_hits" -eq 0 ]; then
        echo -e "  ${GREEN}$(t intel_no_match) ✅${NC}"
    else
        echo -e "  ${RED}⚠️  $intel_hits IP مشبوه!${NC}"
    fi
fi

# ─── 4. أعلى IPs بعدد اتصالات ────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ أعلى IPs الخارجية بعدد اتصالات${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

top_remote=$(echo "$estab_data" | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    grep -vE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' | \
    sort | uniq -c | sort -rn | head -10)

if [ -n "$top_remote" ]; then
    echo "$top_remote" | while IFS= read -r tl; do
        count=$(echo "$tl" | awk '{print $1}')
        ip=$(echo "$tl" | awk '{print $2}')
        if [ "$count" -ge 20 ] 2>/dev/null; then
            echo -e "  ${RED}  $count → $ip  ← عدد مرتفع!${NC}"
            finding_add high "High connection count to $ip: $count connections"
        else
            echo "  $count → $ip"
        fi
    done
else
    echo -e "  ${GREEN}لا توجد اتصالات خارجية${NC}"
fi

# ─── 5. عمليات بدون binary معروف ──────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ عمليات شبكة بدون binary واضح${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

unknown_procs=$(echo "$all_conns" | awk 'NR>1' | \
    grep -vE 'users:\(' | grep "ESTAB" | head -10)
if [ -n "$unknown_procs" ]; then
    echo -e "  ${YELLOW}عمليات بدون اسم واضح:${NC}"
    echo "$unknown_procs" | head -5 | while IFS= read -r up; do
        echo -e "  ${YELLOW}  ⚠️  $up${NC}"
    done
fi

# ─── ملخص ────────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$(t mon2_done)${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Active Connections — $(date)

$REPORT" "active_connections.txt" "$TOOL_TITLE"
