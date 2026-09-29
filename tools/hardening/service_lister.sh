#!/bin/bash
# =====================================================
#  Service Lister — قائمة الخدمات والتحليل الأمني
#  يفحص: systemd services، SysV، xinetd
#  يحلل: خدمات قديمة/خطيرة، خدمات dev بالإنتاج،
#         خدمات مجهولة، إعدادات أمان systemd،
#         خدمات تعمل بصلاحية root غير ضرورية
# =====================================================
finding_reset

TOOL_TITLE="$(t har3_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

# ─── قواميس الخدمات الخطيرة ───────────────────────────────
declare -A DANGEROUS_SERVICES
DANGEROUS_SERVICES["telnet"]="critical|Telnet: لا تشفير — استبدل بـ SSH"
DANGEROUS_SERVICES["telnetd"]="critical|Telnet daemon مكشوف"
DANGEROUS_SERVICES["rsh"]="critical|rsh: مصادقة ضعيفة جداً — end-of-life"
DANGEROUS_SERVICES["rlogin"]="critical|rlogin: بروتوكول قديم خطير"
DANGEROUS_SERVICES["rexec"]="critical|rexec: بروتوكول قديم خطير"
DANGEROUS_SERVICES["tftp"]="high|TFTP: بدون مصادقة"
DANGEROUS_SERVICES["tftpd"]="high|TFTP daemon — بدون مصادقة"
DANGEROUS_SERVICES["ftp"]="high|FTP: بيانات بنص واضح"
DANGEROUS_SERVICES["vsftpd"]="medium|FTP — تأكد من الإعدادات الأمنية"
DANGEROUS_SERVICES["proftpd"]="medium|FTP server — تأكد من الإعدادات"
DANGEROUS_SERVICES["finger"]="high|finger: يكشف معلومات المستخدمين"
DANGEROUS_SERVICES["nfs"]="medium|NFS: تحقق من exports"
DANGEROUS_SERVICES["rpcbind"]="medium|RPC Portmapper — قد يُستغل"
DANGEROUS_SERVICES["portmap"]="medium|Portmapper قديم"
DANGEROUS_SERVICES["ypserv"]="high|NIS server قديم وغير آمن"
DANGEROUS_SERVICES["snmpd"]="medium|SNMP — تأكد من community strings"
DANGEROUS_SERVICES["inetd"]="high|inetd super-server — يفتح خدمات متعددة"
DANGEROUS_SERVICES["xinetd"]="high|xinetd — راجع services المُشغَّلة"
DANGEROUS_SERVICES["sendmail"]="medium|Sendmail — كثير من الثغرات التاريخية"
DANGEROUS_SERVICES["popd"]="medium|POP3 — نص واضح"
DANGEROUS_SERVICES["imapd"]="medium|IMAP — تحقق من التشفير"
DANGEROUS_SERVICES["chargen"]="critical|CHARGEN — يُستخدم بهجمات DRDoS"
DANGEROUS_SERVICES["discard"]="high|Discard service — غير ضروري"
DANGEROUS_SERVICES["echo"]="high|Echo service — يُستخدم بهجمات"
DANGEROUS_SERVICES["daytime"]="low|Daytime service — غير ضروري"
DANGEROUS_SERVICES["time"]="low|Time service — استبدل بـ NTP"

declare -A DEV_SERVICES
DEV_SERVICES["apache2-dev"]="high|Apache dev mode"
DEV_SERVICES["jupyter"]="critical|Jupyter Notebook — تنفيذ كود مكشوف!"
DEV_SERVICES["jupyter-notebook"]="critical|Jupyter Notebook في بيئة production"
DEV_SERVICES["rstudio-server"]="high|RStudio Server — dev tool"
DEV_SERVICES["netdata"]="medium|NetData — بيانات النظام مكشوفة"
DEV_SERVICES["grafana-server"]="medium|Grafana — تحقق من المصادقة"
DEV_SERVICES["prometheus"]="medium|Prometheus — بيانات النظام مكشوفة"

# ─── 1. systemd: الخدمات المُفعَّلة ──────────────────────────
echo -e "${BOLD}${CYAN}━━ $(t har3_at_boot) (systemd enabled) ━━${NC}"

if command -v systemctl >/dev/null 2>&1; then
    enabled_services=$(systemctl list-unit-files --type=service --state=enabled \
        2>/dev/null | awk 'NR>1 && NF>=1 {print $1}' | sed 's/\.service$//' | sort)

    echo "$enabled_services" | while IFS= read -r svc; do
        [ -z "$svc" ] && continue

        # هل هي خطيرة؟
        risk="${DANGEROUS_SERVICES[$svc]}"
        dev_risk="${DEV_SERVICES[$svc]}"

        if [ -n "$risk" ]; then
            sev=$(echo "$risk" | cut -d'|' -f1)
            desc=$(echo "$risk" | cut -d'|' -f2)
            case "$sev" in
                critical) echo -e "  ${RED}[CRITICAL] $svc — $desc${NC}" ;;
                high)     echo -e "  ${ORANGE}[HIGH]     $svc — $desc${NC}" ;;
                medium)   echo -e "  ${YELLOW}[MEDIUM]   $svc — $desc${NC}" ;;
                *)        echo -e "  ${CYAN}[LOW]      $svc — $desc${NC}" ;;
            esac
            finding_add "$sev" "Dangerous/legacy service enabled: $svc — $desc"
        elif [ -n "$dev_risk" ]; then
            dsev=$(echo "$dev_risk" | cut -d'|' -f1)
            ddesc=$(echo "$dev_risk" | cut -d'|' -f2)
            echo -e "  ${ORANGE}[${dsev^^}] $svc — $ddesc${NC}"
            finding_add "$dsev" "Dev service in production: $svc — $ddesc"
        else
            echo -e "  ${GREEN}  ✓${NC} $svc"
        fi
    done

    REPORT+="=== Enabled Services ===
$enabled_services

"
fi

# ─── 2. systemd: الخدمات الجارية حالياً ────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ $(t har3_currently_running) ━━${NC}"

if command -v systemctl >/dev/null 2>&1; then
    running=$(systemctl list-units --type=service --state=running \
        2>/dev/null | awk 'NR>1 {print $1}' | sed 's/\.service$//' | head -40)

    run_count=$(echo "$running" | wc -l)
    echo -e "  ${BOLD}$run_count خدمة نشطة${NC}"
    echo ""

    echo "$running" | while IFS= read -r svc; do
        [ -z "$svc" ] && continue

        risk="${DANGEROUS_SERVICES[$svc]}"
        if [ -n "$risk" ]; then
            sev=$(echo "$risk" | cut -d'|' -f1)
            desc=$(echo "$risk" | cut -d'|' -f2)
            echo -e "  ${RED}  ⚠️  [${sev^^}] $svc — $desc${NC}"
        else
            echo -e "  ${GREY}     $svc${NC}"
        fi
    done
fi

# ─── 3. التحقق من خدمات risky نشطة (قديم) ─────────────────
echo ""
echo -e "${BOLD}${RED}$(t har3_risky_warning)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

RISKY_PATTERN="telnet|rsh|rlogin|finger|tftp|ypserv|chargen|daytime|echo|discard|inetd|xinetd"
risky_active=""

if command -v systemctl >/dev/null 2>&1; then
    risky_active=$(systemctl list-units --state=running 2>/dev/null | \
        grep -iE "$RISKY_PATTERN" | awk '{print $1}')
fi

# فحص إضافي عبر ps
risky_ps=$(ps aux 2>/dev/null | grep -iE "$RISKY_PATTERN" | grep -v grep | head -10)

if [ -n "$risky_active" ] || [ -n "$risky_ps" ]; then
    all_risky="${risky_active}
${risky_ps}"
    echo -e "  ${RED}⚠️  خدمات خطيرة نشطة!${NC}"
    echo "$all_risky" | grep -v '^$' | while IFS= read -r r; do
        echo -e "  ${RED}  🔴 $r${NC}"
        finding_add critical "Dangerous legacy service running: $r"
    done
else
    echo -e "  ${GREEN}$(t har3_all_good)${NC}"
fi

# ─── 4. فحص systemd unit security settings ──────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ فحص إعدادات الأمان في systemd Units ━━${NC}"

if command -v systemd-analyze >/dev/null 2>&1; then
    echo -e "${YELLOW}  تحليل security score لأهم الخدمات:${NC}"
    for svc in sshd nginx apache2 mysql postgresql redis; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            score=$(systemd-analyze security "$svc" 2>/dev/null | grep "→" | tail -1 | awk '{print $NF}')
            [ -n "$score" ] && echo -e "  ${CYAN}  $svc: score $score${NC}"
        fi
    done
fi

# ─── 5. ملخص ─────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

if [ -n "$risky_active" ] || [ -n "$risky_ps" ]; then
    save_report "$(t har3_report_title)

Dangerous services:
${risky_active:-None}
${risky_ps:-}

$REPORT" "risky_services.txt" "$TOOL_TITLE"
fi
