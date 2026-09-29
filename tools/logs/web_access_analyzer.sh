#!/bin/bash
# =====================================================
#  Web Access Log Analyzer — محلل سجلات الويب
#  يحلل: Apache/Nginx access logs
#  يكشف: DDoS attacks، path traversal، SQL injection
#  attempts، XSS attempts، scanner activity (nmap/nikto)،
#  credential stuffing، suspicious user agents،
#  slow loris attacks، geolocation of top attackers
# =====================================================
finding_reset

TOOL_TITLE="$(t log5_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -rp "$(t log5_prompt_path): " logfile
if [ ! -f "$logfile" ]; then
    echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1
fi

FILE_SIZE=$(raqib_stat_size "$logfile" 2>/dev/null || echo "?")
TOTAL_LINES=$(wc -l < "$logfile" 2>/dev/null || echo "?")
echo -e "${GREY}  الملف: $logfile  |  $TOTAL_LINES سطر  |  $FILE_SIZE bytes${NC}"
echo ""

REPORT=""

# ─── 1. إحصاءات عامة ─────────────────────────────────────────
echo -e "${BOLD}${YELLOW}◉ $(t log5_top_ips) (أعلى 15 IP)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
top_ips=$(awk '{print $1}' "$logfile" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sort | uniq -c | sort -rn | head -15)

if [ -n "$top_ips" ]; then
    max_count=$(echo "$top_ips" | head -1 | awk '{print $1}')
    echo "$top_ips" | while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')

        # رسم بار
        if [ -n "$max_count" ] && [ "$max_count" -gt 0 ]; then
            bar_len=$((count * 20 / max_count))
            bar=$(printf '█%.0s' $(seq 1 $((bar_len + 1))) 2>/dev/null || printf '=')
        fi

        if [ "$count" -ge 10000 ]; then
            echo -e "  ${RED}$count\t$(printf '%-20s' "$bar")  $ip  ${RED}← DDoS candidate${NC}"
            finding_add critical "Possible DDoS source: $ip ($count requests)"
        elif [ "$count" -ge 1000 ]; then
            echo -e "  ${ORANGE}$count\t$(printf '%-20s' "$bar")  $ip${NC}"
            finding_add high "High request rate from: $ip ($count requests)"
        else
            echo "  $count	$bar  $ip"
        fi
    done
else
    echo -e "  ${GREY}لا توجد بيانات${NC}"
fi

REPORT+="$(t log5_top_ips)
$top_ips

"

# ─── 2. توزيع Status Codes ───────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ $(t log5_status_dist)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
status_codes=$(awk '{print $9}' "$logfile" 2>/dev/null | \
    grep -E '^[0-9]{3}$' | sort | uniq -c | sort -rn)
echo "$status_codes" | while IFS= read -r sline; do
    count=$(echo "$sline" | awk '{print $1}')
    code=$(echo "$sline" | awk '{print $2}')
    case "${code:0:1}" in
        2) color="$GREEN" ;;
        3) color="$CYAN" ;;
        4) color="$ORANGE" ;;
        5) color="$RED"; finding_add medium "High server error rate: $code ($count occurrences)" ;;
        *) color="$NC" ;;
    esac
    echo -e "  ${color}$code${NC}  $count"
done

# Rate of 4xx/5xx
total_4xx=$(awk '$9~/^4[0-9][0-9]$/{count++} END{print count+0}' "$logfile" 2>/dev/null)
total_5xx=$(awk '$9~/^5[0-9][0-9]$/{count++} END{print count+0}' "$logfile" 2>/dev/null)
echo ""
echo -e "  4xx: $total_4xx  |  5xx: $total_5xx"
[ "${total_5xx:-0}" -ge 100 ] && {
    echo -e "  ${RED}⚠️  معدل 5xx مرتفع — مشكلة بالخادم؟${NC}"
    finding_add high "High 5xx error rate: $total_5xx server errors"
}

REPORT+="$(t log5_status_dist)
$status_codes

"

# ─── 3. أكثر المسارات طلباً ──────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ $(t log5_top_paths) (أعلى 15 مسار)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
top_paths=$(awk '{print $7}' "$logfile" 2>/dev/null | \
    cut -d'?' -f1 | sort | uniq -c | sort -rn | head -15)
echo "$top_paths"

REPORT+="$(t log5_top_paths)
$top_paths

"

# ─── 4. كشف هجمات محتملة ─────────────────────────────────────
echo ""
echo -e "${BOLD}${RED}◉ كشف هجمات وطلبات مشبوهة${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# Path traversal
echo -e "  ${YELLOW}▸ Path Traversal / Directory Traversal:${NC}"
path_traversal=$(grep -iE '(\.\./|%2e%2e|%252e%252e)' "$logfile" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -5)
if [ -n "$path_traversal" ]; then
    echo "$path_traversal" | while IFS= read -r pt; do
        echo -e "  ${RED}    $pt${NC}"
        finding_add high "Path traversal attempt from: $pt"
    done
else
    echo -e "  ${GREEN}    لا يوجد${NC}"
fi

# SQL Injection
echo -e "  ${YELLOW}▸ SQL Injection Patterns:${NC}"
sqli=$(grep -iE "(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|'\s*or\s+'1'='1|1=1|exec\s*\()" \
    "$logfile" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -5)
if [ -n "$sqli" ]; then
    echo "$sqli" | while IFS= read -r si; do
        echo -e "  ${RED}    $si${NC}"
        finding_add critical "SQL injection attempt from: $si"
    done
else
    echo -e "  ${GREEN}    لا يوجد${NC}"
fi

# XSS
echo -e "  ${YELLOW}▸ XSS Attempts:${NC}"
xss=$(grep -iE "(<script|javascript:|onerror=|onload=|alert\(|document\.cookie)" \
    "$logfile" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -5)
if [ -n "$xss" ]; then
    echo "$xss" | while IFS= read -r xs; do
        echo -e "  ${RED}    $xs${NC}"
        finding_add high "XSS attempt from: $xs"
    done
else
    echo -e "  ${GREEN}    لا يوجد${NC}"
fi

# Scanner User-Agents
echo -e "  ${YELLOW}▸ أدوات فحص معروفة (Scanner User-Agents):${NC}"
scanner_uas=$(grep -iE "(nmap|nikto|sqlmap|masscan|nessus|openvas|zap|burp|acunetix|w3af|dirbuster|gobuster|wfuzz)" \
    "$logfile" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -5)
if [ -n "$scanner_uas" ]; then
    echo -e "  ${RED}⚠️  فحص نشط من:${NC}"
    echo "$scanner_uas" | while IFS= read -r sc; do
        echo -e "  ${RED}    $sc${NC}"
        finding_add high "Active scanner detected from: $sc"
    done
else
    echo -e "  ${GREEN}    لا يوجد${NC}"
fi

# WordPress attacks
echo -e "  ${YELLOW}▸ WordPress Attacks (xmlrpc/wp-login brute):${NC}"
wp_attacks=$(grep -iE "(wp-login\.php|xmlrpc\.php)" "$logfile" 2>/dev/null | \
    grep "POST" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sort | uniq -c | sort -rn | head -5)
if [ -n "$wp_attacks" ]; then
    echo "$wp_attacks" | while IFS= read -r wa; do
        count=$(echo "$wa" | awk '{print $1}')
        ip=$(echo "$wa" | awk '{print $2}')
        [ "$count" -ge 5 ] && {
            echo -e "  ${ORANGE}    $count POST → wp-login/xmlrpc من $ip${NC}"
            finding_add high "WordPress brute force from $ip: $count POST requests"
        }
    done
else
    echo -e "  ${GREEN}    لا يوجد${NC}"
fi

# ─── 5. عناوين 4xx/5xx المشبوهة ─────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ $(t log5_suspicious_4xx5xx)${NC}"
suspicious=$(awk '$9~/^[45][0-9][0-9]$/{print $1}' "$logfile" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -10)
echo "$suspicious" | while IFS= read -r sl; do
    count=$(echo "$sl" | awk '{print $1}')
    ip=$(echo "$sl" | awk '{print $2}')
    if [ "$count" -ge 100 ] 2>/dev/null; then
        echo -e "  ${RED}  $count 4xx/5xx ← $ip${NC}"
        finding_add medium "Suspicious 4xx/5xx rate from $ip: $count errors"
    else
        echo "  $count $ip"
    fi
done

# ─── 6. أكثر User-Agents ─────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ أكثر User-Agents (أعلى 10)${NC}"
top_uas=$(awk -F'"' '{print $6}' "$logfile" 2>/dev/null | \
    sort | uniq -c | sort -rn | head -10)
echo "$top_uas" | while IFS= read -r ua; do
    echo "  $ua"
done

REPORT+="$(t log5_suspicious_4xx5xx)
$suspicious

"

# ─── 7. ملخص ─────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$(tf log5_report_title "$logfile" "$(date)")

$REPORT" "web_access_analysis.txt" "$TOOL_TITLE"
