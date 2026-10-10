#!/bin/bash
# =====================================================
#  Open Ports vs Services — فحص المنافذ والخدمات
#  يربط كل منفذ مفتوح بالعملية المسؤولة عنه
#  يحلل: منافذ خطيرة مكشوفة، خدمات تعمل بـ root،
#  منافذ bound لـ 0.0.0.0 (كل الواجهات)، خدمات
#  بدون TLS، مقارنة مع قاعدة بيانات IANA
# =====================================================
finding_reset

TOOL_TITLE="$(t vul1_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

# ─── قاعدة بيانات المنافذ والخدمات الشائعة ────────────────────
declare -A PORT_INFO
PORT_INFO[21]="FTP|high|نص واضح — استخدم SFTP"
PORT_INFO[22]="SSH|low|آمن — تحقق من الإعدادات"
PORT_INFO[23]="Telnet|critical|لا تشفير — يجب إيقافه!"
PORT_INFO[25]="SMTP|medium|تحقق من relay مفتوح"
PORT_INFO[53]="DNS|low|تحقق من zone transfer"
PORT_INFO[80]="HTTP|medium|بدون تشفير — أضف HTTPS"
PORT_INFO[110]="POP3|high|نص واضح — استخدم POP3S"
PORT_INFO[111]="RPC/Portmap|high|قد يكشف خدمات داخلية"
PORT_INFO[135]="MS-RPC|high|هدف شائع لـ EternalBlue"
PORT_INFO[139]="NetBIOS|high|مشاركة ملفات خطيرة"
PORT_INFO[143]="IMAP|medium|تحقق من STARTTLS"
PORT_INFO[389]="LDAP|medium|تحقق من التشفير"
PORT_INFO[443]="HTTPS|low|آمن"
PORT_INFO[445]="SMB|critical|هدف WannaCry/EternalBlue!"
PORT_INFO[993]="IMAPS|low|آمن"
PORT_INFO[995]="POP3S|low|آمن"
PORT_INFO[1433]="MSSQL|high|قاعدة بيانات مكشوفة"
PORT_INFO[1521]="Oracle|high|قاعدة بيانات مكشوفة"
PORT_INFO[2049]="NFS|high|تحقق من exports"
PORT_INFO[3306]="MySQL|high|قاعدة بيانات — لا تكشف للإنترنت"
PORT_INFO[3389]="RDP|high|هدف شائع للبرمجيات الخبيثة"
PORT_INFO[4444]="Metasploit/Backdoor|critical|منفذ مشبوه جداً!"
PORT_INFO[5432]="PostgreSQL|high|قاعدة بيانات مكشوفة"
PORT_INFO[5900]="VNC|high|remote desktop — تحقق من كلمة السر"
PORT_INFO[6379]="Redis|critical|بدون مصادقة افتراضياً!"
PORT_INFO[8080]="HTTP-Alt|medium|proxy أو dev server"
PORT_INFO[8443]="HTTPS-Alt|low|عادة آمن"
PORT_INFO[8888]="Jupyter|critical|تنفيذ كود مكشوف!"
PORT_INFO[9200]="Elasticsearch|critical|بيانات مكشوفة!"
PORT_INFO[11211]="Memcached|critical|يُستخدم بهجمات DRDoS!"
PORT_INFO[27017]="MongoDB|critical|بدون مصادقة افتراضياً!"

# ─── 1. جمع بيانات المنافذ المفتوحة ──────────────────────────
echo -e "${BOLD}${YELLOW}$(t vul1_header)${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
printf "  ${BOLD}%-8s %-6s %-22s %-10s %-15s %s${NC}\n" "PORT" "PROTO" "BIND ADDRESS" "STATE" "PROCESS" "RISK"
printf "  %s\n" "$(printf '─%.0s' {1..85})"

if command -v ss >/dev/null 2>&1; then
    raw_data=$(ss -tulnp 2>/dev/null | awk 'NR>1')
else
    raw_data=$(netstat -tulnp 2>/dev/null | awk 'NR>2')
fi

port_count=0
high_risk_count=0

echo "$raw_data" | while IFS= read -r line; do
    [ -z "$line" ] && continue

    if command -v ss >/dev/null 2>&1; then
        proto=$(echo "$line" | awk '{print $1}')
        local_addr=$(echo "$line" | awk '{print $5}')
        process=$(echo "$line" | awk '{print $7}' | grep -oE '"[^"]+"' | tr -d '"')
    else
        proto=$(echo "$line" | awk '{print $1}')
        local_addr=$(echo "$line" | awk '{print $4}')
        process=$(echo "$line" | awk '{print $7}' | cut -d'/' -f2)
    fi

    # استخرج المنفذ
    port=$(echo "$local_addr" | rev | cut -d: -f1 | rev)
    bind_addr=$(echo "$local_addr" | rev | cut -d: -f2- | rev)

    [ -z "$port" ] && continue
    [[ "$port" =~ ^[0-9]+$ ]] || continue

    process="${process:-unknown}"
    port_count=$((port_count + 1))

    # معلومات المنفذ من القاعدة
    info="${PORT_INFO[$port]}"
    if [ -n "$info" ]; then
        svc_name=$(echo "$info" | cut -d'|' -f1)
        sev=$(echo "$info" | cut -d'|' -f2)
        desc=$(echo "$info" | cut -d'|' -f3)
    else
        svc_name="Unknown"
        sev="low"
        desc=""
    fi

    # خطر إضافي: مفتوح على كل الواجهات (0.0.0.0 أو ::)
    exposed=""
    if echo "$bind_addr" | grep -qE '^0\.0\.0\.0$|^\*$|^::$|^\[::\]$'; then
        exposed=" [ALL INTERFACES]"
        # رفع الخطورة لو كان مفتوح لكل الواجهات
        [ "$sev" = "low" ] && sev="medium"
    fi

    # تلوين حسب الخطورة
    case "$sev" in
        critical)
            color="$RED"
            risk_badge="🔴 CRITICAL"
            finding_add critical "Critical port $port ($svc_name) open: $desc (process: $process)$exposed"
            high_risk_count=$((high_risk_count + 1))
            ;;
        high)
            color="$ORANGE"
            risk_badge="⚠️  HIGH"
            finding_add high "Risky port $port ($svc_name) open: $desc$exposed"
            high_risk_count=$((high_risk_count + 1))
            ;;
        medium)
            color="$YELLOW"
            risk_badge="⚡ MEDIUM"
            finding_add medium "Port $port ($svc_name): $desc$exposed"
            ;;
        *)
            color="$GREEN"
            risk_badge="✓ OK"
            ;;
    esac

    printf "  ${color}%-8s %-6s %-22s %-10s %-15s %s${NC}\n" \
        "$port" "$proto" "$bind_addr$exposed" "LISTEN" "$process" "$risk_badge — $svc_name"
done

REPORT+="=== Open Ports ===
$raw_data

"

# ─── 2. المنافذ الخطيرة (ملخص) ───────────────────────────────
echo ""
echo -e "${BOLD}${RED}$(t vul1_risky_ports)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

RISKY_PORTS="21|23|445|3389|135|139|1433|3306|5432|4444|6379|9200|27017|11211|8888"
if command -v ss >/dev/null 2>&1; then
    risky_lines=$(ss -tuln 2>/dev/null | grep -E ":(${RISKY_PORTS})\b")
else
    risky_lines=$(netstat -tuln 2>/dev/null | grep -E ":(${RISKY_PORTS})\b")
fi

if [ -n "$risky_lines" ]; then
    echo "$risky_lines" | while IFS= read -r rl; do
        echo -e "  ${RED}[!] $rl${NC}"
    done
else
    echo -e "  ${GREEN}لا توجد منافذ خطيرة مفتوحة${NC}"
fi

# ─── 3. خدمات تعمل بـ root ───────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ خدمات الشبكة تعمل بصلاحية root:${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if command -v ss >/dev/null 2>&1; then
    root_services=$(ss -tulnp 2>/dev/null | awk 'NR>1' | grep -i "root\|uid:0" | head -15)
else
    root_services=$(netstat -tulnp 2>/dev/null | awk 'NR>2 {print}' | head -15)
fi

if [ -n "$root_services" ]; then
    echo "$root_services" | while IFS= read -r rs; do
        echo -e "  ${YELLOW}  ⚡ $rs${NC}"
    done
else
    echo -e "  ${GREY}(تحتاج صلاحية root لعرض أسماء العمليات)${NC}"
fi

# ─── 4. توصيات ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}💡 توصيات:${NC}"
echo -e "  ${CYAN}▸${NC} أغلق أي منفذ غير ضروري بالجدار الناري"
echo -e "  ${CYAN}▸${NC} المنافذ الحمراء يجب إيقافها أو حمايتها فوراً"
echo -e "  ${CYAN}▸${NC} قواعد البيانات يجب ألا تكون مفتوحة على 0.0.0.0"
echo -e "  ${CYAN}▸${NC} استخدم SSH tunneling للوصول لخدمات داخلية"

echo ""
echo -e "${GREEN}$(t vul1_ensure_protected)${NC}"

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Open Ports vs Services — $(date)

$REPORT" "open_ports_audit.txt" "$TOOL_TITLE"
