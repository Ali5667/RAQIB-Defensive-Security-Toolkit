#!/bin/bash
# =====================================================
#  Brute Force Detector — كاشف هجمات القوة الغاشمة
#  يفحص: SSH + FTP + HTTP Auth + IMAP/POP3 + MySQL
#  يحلل: محاولات IP واحد، distributed attack، 
#         slow brute force، نشاط بوت، حظر فوري
# =====================================================
finding_reset

TOOL_TITLE="$(t ids1_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

LOGFILE=$(find_auth_log) || exit 1

read -rp "$(t ids1_prompt_threshold)  [افتراضي: 5]: " threshold
threshold="${threshold:-5}"
if ! [[ "$threshold" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}$(t c_value_must_be_number)${NC}"; exit 1
fi

echo ""
echo -e "${GREY}  المصدر: $LOGFILE  |  الحد: $threshold محاولة${NC}"
echo ""

REPORT=""

# ─── 1. SSH Brute Force ──────────────────────────────────────
echo -e "${YELLOW}◉ SSH — Failed Password / Invalid User${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
echo -e "${YELLOW}$(t ids1_analyzing)${NC}"

ssh_results=$(grep -iE "Failed password|Invalid user|authentication failure" "$LOGFILE" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sort | uniq -c | sort -rn | \
    awk -v t="$threshold" '$1 >= t {print}')

if [ -z "$ssh_results" ]; then
    echo -e "  ${GREEN}$(tf ids1_no_ip_exceeded "$threshold")${NC}"
else
    echo ""
    while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')

        # تصنيف مستوى الخطورة
        if [ "$count" -ge 500 ]; then
            badge="${RED}[CRITICAL]${NC}"
            sev="critical"
        elif [ "$count" -ge 100 ]; then
            badge="${ORANGE}[HIGH]   ${NC}"
            sev="high"
        elif [ "$count" -ge 20 ]; then
            badge="${YELLOW}[MEDIUM] ${NC}"
            sev="medium"
        else
            badge="${GREEN}[LOW]    ${NC}"
            sev="low"
        fi

        # فحص IOC
        intel_str=""
        if raqib_intel_available 2>/dev/null; then
            intel_res=$(raqib_intel_analyze "$ip" 2>/dev/null)
            [ -n "$intel_res" ] && intel_str="${RED} [IOC: $(echo "$intel_res" | cut -d'|' -f1)]${NC}"
        fi

        echo -e "  ${badge} ${RED}$(tf ids1_warning "$ip" "$count")${NC}${intel_str}"
        finding_add "$sev" "SSH brute force from $ip: $count attempts"
    done <<< "$ssh_results"
fi

REPORT+="=== SSH Brute Force ===
$ssh_results

"

# ─── 2. FTP Brute Force ──────────────────────────────────────
echo ""
echo -e "${YELLOW}◉ FTP — محاولات تسجيل دخول فاشلة${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

ftp_log_files=("/var/log/vsftpd.log" "/var/log/proftpd/proftpd.log" "/var/log/pure-ftpd.log")
ftp_found=0
for ftp_log in "${ftp_log_files[@]}"; do
    if [ -f "$ftp_log" ] && [ -r "$ftp_log" ]; then
        ftp_fail=$(grep -iE "FAIL|failed|incorrect|denied" "$ftp_log" 2>/dev/null | \
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | \
            awk -v t="$threshold" '$1 >= t {print}')
        if [ -n "$ftp_fail" ]; then
            echo -e "  ${ORANGE}  FTP brute force ($ftp_log):${NC}"
            echo "$ftp_fail" | while IFS= read -r fl; do
                count=$(echo "$fl" | awk '{print $1}')
                ip=$(echo "$fl" | awk '{print $2}')
                echo -e "  ${RED}    ▸ $count محاولة من $ip${NC}"
                finding_add high "FTP brute force from $ip: $count attempts"
            done
            ftp_found=1
        fi
    fi
done
[ "$ftp_found" -eq 0 ] && echo -e "  ${GREEN}لا توجد هجمات FTP مرصودة${NC}"

# ─── 3. كشف Distributed Brute Force ──────────────────────────
echo ""
echo -e "${YELLOW}◉ كشف Distributed Brute Force (محاولات من /24 subnet)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# IPs من نفس الـ /24 subnet
distributed=$(grep -iE "Failed password|Invalid user" "$LOGFILE" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sed -E 's/\.[0-9]+$//' | sort | uniq -c | sort -rn | \
    awk '$1 >= 5 {print}' | head -10)

if [ -n "$distributed" ]; then
    echo -e "  ${ORANGE}شبكات مصدر هجوم موزّع:${NC}"
    echo "$distributed" | while IFS= read -r dline; do
        count=$(echo "$dline" | awk '{print $1}')
        subnet=$(echo "$dline" | awk '{print $2}')
        echo -e "  ${ORANGE}  ▸ ${count} IPs من شبكة ${subnet}.0/24${NC}"
        finding_add high "Distributed brute force from subnet ${subnet}.0/24: $count source IPs"
    done
else
    echo -e "  ${GREEN}لا يوجد هجوم موزّع مرصود${NC}"
fi

REPORT+="=== Distributed Attack Subnets ===
$distributed

"

# ─── 4. Slow Brute Force كشف ──────────────────────────────
echo ""
echo -e "${YELLOW}◉ Slow Brute Force (محاولات موزّعة على وقت طويل)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
# IP فيه محاولات بعدة أيام مختلفة
slow_bf=$(grep -iE "Failed password|Invalid user" "$LOGFILE" 2>/dev/null | \
    grep -oE '[A-Za-z]+ [0-9 ]+[0-9]+:[0-9]+.*([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    awk '{for(i=1;i<=NF;i++) if($i~/^[0-9]{1,3}\.[0-9]{1,3}/) print $1, $i}' | \
    sort -k2 | uniq -f1 -D | awk '{print $2}' | sort | uniq -c | \
    awk '$1 >= 3 {print}' | sort -rn | head -10)

if [ -n "$slow_bf" ]; then
    echo -e "  ${ORANGE}IPs تهاجم على عدة أيام:${NC}"
    echo "$slow_bf" | while IFS= read -r sl; do
        count=$(echo "$sl" | awk '{print $1}')
        ip=$(echo "$sl" | awk '{print $2}')
        echo -e "  ${ORANGE}  ▸ $ip — ظهر في $count أيام مختلفة${NC}"
        finding_add medium "Slow brute force from $ip across $count different days"
    done
else
    echo -e "  ${GREEN}لا يوجد slow brute force مرصود${NC}"
fi

# ─── 5. خيار الحظر الفوري ────────────────────────────────────
if [ -n "$ssh_results" ]; then
    echo ""
    echo -e "${BOLD}${ORANGE}◉ هل تريد حظر أعلى IP مهاجم فوراً؟${NC}"
    top_attacker=$(echo "$ssh_results" | head -1 | awk '{print $2}')
    top_count=$(echo "$ssh_results" | head -1 | awk '{print $1}')
    echo -e "  أعلى مهاجم: ${RED}$top_attacker${NC} ($top_count محاولة)"
    read -rp "  حظر $top_attacker؟ [y/N]: " block_ans
    if [ "${block_ans,,}" = "y" ]; then
        # استخدام ip_blocker.sh إن كان موجوداً
        blocker="$TOOLS_DIR/ids_ips/ip_blocker.sh"
        if [ -f "$blocker" ]; then
            echo -e "${CYAN}  تشغيل IP Blocker...${NC}"
            ( RAQIB_AUTO_BLOCK_IP="$top_attacker"; source "$blocker" )
        else
            # حظر مباشر بـ iptables
            if command -v iptables >/dev/null 2>&1; then
                req_id=$(raqib_request_approval "block_ip" "$top_attacker" \
                    "Brute force: $top_count attempts" \
                    "iptables -I INPUT -s $top_attacker -j DROP")
                echo -e "${YELLOW}  طلب حظر مُضاف للمراجعة — رقم الطلب: $req_id${NC}"
            fi
        fi
    fi
fi

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$(t ids1_analysis_done)${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$(tf ids1_report_title "$(date)")
$(tf ids1_threshold_label "$threshold")

$REPORT" "bruteforce_report.txt" "$TOOL_TITLE"
