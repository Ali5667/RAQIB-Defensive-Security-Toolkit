#!/bin/bash
# =====================================================
#  Listening Ports Auditor — مدقق المنافذ المفتوحة
#  يراقب كل المنافذ المفتوحة، يربطها بالعمليات،
#  يحلل: منافذ خطيرة، خدمات بدون مصادقة، منافذ
#  غريبة، اتصالات خارجية مشبوهة، منافذ مفتوحة لعامة
# =====================================================
finding_reset

TOOL_TITLE="$(t ids2_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

# ─── ثوابت: منافذ وخدماتها ─────────────────────────────────
declare -A HIGH_RISK_PORTS
HIGH_RISK_PORTS[23]="Telnet — لا تشفير"
HIGH_RISK_PORTS[445]="SMB — ثغرات EternalBlue/WannaCry"
HIGH_RISK_PORTS[2375]="Docker API — بدون TLS!"
HIGH_RISK_PORTS[4444]="Metasploit/Backdoor"
HIGH_RISK_PORTS[6379]="Redis — بدون مصادقة افتراضياً"
HIGH_RISK_PORTS[9200]="Elasticsearch — بيانات مكشوفة"
HIGH_RISK_PORTS[11211]="Memcached — يُستخدم بهجمات DRDoS"
HIGH_RISK_PORTS[27017]="MongoDB — بدون مصادقة افتراضياً"
HIGH_RISK_PORTS[50070]="Hadoop NameNode — واجهة إدارة مكشوفة"
HIGH_RISK_PORTS[8500]="Consul — واجهة إدارة"
HIGH_RISK_PORTS[8200]="Vault — خزنة الأسرار!"
HIGH_RISK_PORTS[9090]="Prometheus — بيانات نظام مكشوفة"
HIGH_RISK_PORTS[5601]="Kibana — لوحة بيانات مكشوفة"
HIGH_RISK_PORTS[4200]="Angular CLI — dev server بالإنتاج!"
HIGH_RISK_PORTS[3000]="Dev Server بالإنتاج"
HIGH_RISK_PORTS[8888]="Jupyter Notebook — تنفيذ كود مكشوف!"

declare -A MEDIUM_RISK_PORTS
MEDIUM_RISK_PORTS[21]="FTP — نص واضح"
MEDIUM_RISK_PORTS[25]="SMTP — قد يُستغل لـ spam"
MEDIUM_RISK_PORTS[3306]="MySQL — تحقق من IP binding"
MEDIUM_RISK_PORTS[5432]="PostgreSQL — تحقق من IP binding"
MEDIUM_RISK_PORTS[1521]="Oracle DB"
MEDIUM_RISK_PORTS[1433]="MSSQL"
MEDIUM_RISK_PORTS[5900]="VNC — تأكد من كلمة سر قوية"
MEDIUM_RISK_PORTS[3389]="RDP — هدف شائع للبرمجيات الخبيثة"
MEDIUM_RISK_PORTS[111]="RPC Portmapper"
MEDIUM_RISK_PORTS[2049]="NFS — تحقق من exports"

# ─── 1. جمع بيانات المنافذ ────────────────────────────────────
echo -e "${YELLOW}$(t ids2_header)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if command -v ss >/dev/null 2>&1; then
    raw_ports=$(ss -tulnp 2>/dev/null)
    PORT_DATA=$(echo "$raw_ports" | awk 'NR>1 {
        proto=$1; local=$5; state=$2; proc=$7
        split(local, addr, ":")
        port = addr[length(addr)]
        gsub(/.*:/, "", local)
        # استخرج اسم العملية
        match(proc, /\"[^\"]+\"/, m)
        proc_name = m[0]
        gsub(/"/, "", proc_name)
        if (proc_name == "") proc_name = "unknown"
        print port, proto, local, state, proc_name
    }')
else
    raw_ports=$(netstat -tulnp 2>/dev/null)
    PORT_DATA=$(echo "$raw_ports" | awk 'NR>2 {
        proto=$1; local=$4; state=$6; proc=$7
        split(local, addr, ":")
        port = addr[length(addr)]
        split(proc, pparts, "/")
        proc_name = pparts[2]
        if (proc_name == "") proc_name = "unknown"
        print port, proto, local, state, proc_name
    }')
fi

# طباعة جدول منسق
printf "  %-8s %-6s %-25s %-12s %s\n" "PORT" "PROTO" "ADDRESS" "STATE" "PROCESS"
printf "  %s\n" "$(printf '─%.0s' {1..70})"

echo "$PORT_DATA" | sort -n | while IFS= read -r pline; do
    port=$(echo "$pline" | awk '{print $1}')
    proto=$(echo "$pline" | awk '{print $2}')
    addr=$(echo "$pline" | awk '{print $3}')
    proc=$(echo "$pline" | awk '{print $5}')

    [[ "$port" =~ ^[0-9]+$ ]] || continue

    # تحديد مستوى الخطورة
    risk_label=""
    risk_color="$NC"

    if [ -n "${HIGH_RISK_PORTS[$port]}" ]; then
        risk_label=" ← ⚠️  ${HIGH_RISK_PORTS[$port]}"
        risk_color="$RED"
        finding_add critical "High-risk port $port open: ${HIGH_RISK_PORTS[$port]} (process: $proc)"
    elif [ -n "${MEDIUM_RISK_PORTS[$port]}" ]; then
        risk_label=" ← ⚡ ${MEDIUM_RISK_PORTS[$port]}"
        risk_color="$ORANGE"
        finding_add medium "Potentially risky port $port: ${MEDIUM_RISK_PORTS[$port]}"
    fi

    printf "  ${risk_color}%-8s %-6s %-25s %-12s %s%s${NC}\n" \
        "$port" "$proto" "$addr" "LISTEN" "$proc" "$risk_label"
done

REPORT+="=== Listening Ports ===
$raw_ports

"

# ─── 2. اتصالات ESTABLISHED المشبوهة ──────────────────────────
echo ""
echo -e "${YELLOW}◉ الاتصالات المتصلة حالياً (ESTABLISHED)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if command -v ss >/dev/null 2>&1; then
    established=$(ss -tnp state established 2>/dev/null | awk 'NR>1 {print $4, $5, $6}')
else
    established=$(netstat -tnp 2>/dev/null | awk '$6=="ESTABLISHED" {print $4, $5, $7}')
fi

if [ -n "$established" ]; then
    conn_count=$(echo "$established" | wc -l)
    echo -e "  $conn_count اتصال نشط"
    echo "$established" | head -20 | while IFS= read -r conn; do
        remote=$(echo "$conn" | awk '{print $2}')
        remote_ip=$(echo "$remote" | sed 's/:.*//')

        # فحص IOC للـ IPs الخارجية
        if raqib_intel_available 2>/dev/null && \
           ! echo "$remote_ip" | grep -qE '^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
            intel_res=$(raqib_intel_analyze "$remote_ip" 2>/dev/null)
            if [ -n "$intel_res" ]; then
                echo -e "  ${RED}[IOC MATCH] $conn ← $remote_ip is malicious!${NC}"
                finding_add critical "Active connection to known malicious IP: $remote_ip"
                raqib_intel_check_and_report "$remote_ip" 2>/dev/null
                continue
            fi
        fi
        echo "  $conn"
    done
    [ "$conn_count" -gt 20 ] && echo -e "  ${GREY}... و$((conn_count - 20)) اتصال إضافي${NC}"
else
    echo -e "  ${GREEN}لا توجد اتصالات خارجية نشطة${NC}"
fi

REPORT+="=== Active Connections ===
$established

"

# ─── 3. البحث عن عملية بسمها ─────────────────────────────────
echo ""
echo -e "${YELLOW}$(t ids2_ask_process)${NC}"
read -rp "  $(t ids2_prompt_pname) [Enter للتخطي]: " pname
if [ -n "$pname" ]; then
    echo -e "${CYAN}  نتائج البحث عن '$pname':${NC}"
    ps aux 2>/dev/null | head -1
    ps aux 2>/dev/null | grep -i "$pname" | grep -v grep | while IFS= read -r psline; do
        echo "  $psline"
    done
    lsof -i 2>/dev/null | grep -i "$pname" | while IFS= read -r lline; do
        echo -e "  ${CYAN}↳ $lline${NC}"
    done
fi

# ─── 4. ملخص ────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$REPORT" "listening_ports.txt" "$TOOL_TITLE"
