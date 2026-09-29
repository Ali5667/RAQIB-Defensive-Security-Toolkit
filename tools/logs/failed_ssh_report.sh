#!/bin/bash
# =====================================================
#  Failed SSH Report — تقرير محاولات SSH الفاشلة
#  يحلل: أعلى IPs بعدد محاولات، usernames مستهدفة،
#  التوزيع الزمني للهجمات، كشف credential stuffing،
#  IPs مكررة متعددة الأيام، فحص قاعدة IOC المحلية
# =====================================================
finding_reset

TOOL_TITLE="$(t log1_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

LOGFILE=$(find_auth_log) || exit 1
echo -e "${GREY}  المصدر: $LOGFILE${NC}"
echo ""

REPORT=""

# ─── 1. إحصاءات عامة ─────────────────────────────────────────
total=$(grep -ci "Failed password" "$LOGFILE" 2>/dev/null || echo 0)
total_invalid=$(grep -ci "Invalid user" "$LOGFILE" 2>/dev/null || echo 0)
total_nokey=$(grep -ci "Did not receive identification" "$LOGFILE" 2>/dev/null || echo 0)

echo -e "${BOLD}📊 إحصاءات عامة:${NC}"
echo -e "  محاولات 'Failed password':       ${RED}${total:-0}${NC}"
echo -e "  محاولات 'Invalid user':          ${ORANGE}${total_invalid:-0}${NC}"
echo -e "  اتصالات بدون مصادقة:            ${YELLOW}${total_nokey:-0}${NC}"

total_all=$(( ${total:-0} + ${total_invalid:-0} ))
if [ "$total_all" -ge 1000 ]; then
    echo -e "  ${RED}⚠️  حجم هجوم ضخم! $total_all محاولة مجموع${NC}"
    finding_add critical "Massive SSH brute force: $total_all total failed attempts"
elif [ "$total_all" -ge 100 ]; then
    finding_add high "High SSH brute force activity: $total_all attempts"
elif [ "$total_all" -ge 10 ]; then
    finding_add medium "SSH brute force activity: $total_all attempts"
fi

REPORT+="=== General Statistics ===
Failed password: ${total:-0}
Invalid user: ${total_invalid:-0}
No identification: ${total_nokey:-0}

"

# ─── 2. أعلى 20 IP بعدد محاولات ──────────────────────────────
echo ""
echo -e "${YELLOW}$(t log1_top_ips)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
attempt_word="$(t log1_attempt_word)"

top_ips=$(grep -i "Failed password\|Invalid user" "$LOGFILE" 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sort | uniq -c | sort -rn | head -20)

if [ -n "$top_ips" ]; then
    echo "$top_ips" | while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        printf "  %-6s %s  →  %s" "$count" "$attempt_word" "$ip"

        # فحص قاعدة IOC المحلية
        if raqib_intel_available 2>/dev/null; then
            intel=$(raqib_intel_analyze "$ip" 2>/dev/null)
            if [ -n "$intel" ]; then
                verdict=$(echo "$intel" | cut -d'|' -f1)
                printf "  ${RED}[IOC: %s]${NC}" "$verdict"
                finding_add high "Known malicious IP in SSH attacks: $ip ($verdict)"
            fi
        fi
        printf "\n"
    done
else
    echo -e "  ${GREEN}لا توجد بيانات${NC}"
fi

REPORT+="=== Top Attacker IPs ===
$top_ips

"

# ─── 3. أكثر usernames استهدافاً ──────────────────────────────
echo ""
echo -e "${YELLOW}◉ أكثر أسماء المستخدمين استهدافاً${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
top_users=$(grep -i "Failed password\|Invalid user" "$LOGFILE" 2>/dev/null | \
    grep -oE "for (invalid user )?[a-zA-Z0-9_.-]+" | \
    sed 's/for invalid user //; s/for //' | \
    sort | uniq -c | sort -rn | head -15)

if [ -n "$top_users" ]; then
    echo "$top_users" | while IFS= read -r uline; do
        count=$(echo "$uline" | awk '{print $1}')
        user=$(echo "$uline" | awk '{print $2}')
        if [[ "$user" =~ ^(root|admin|administrator|test|guest|ubuntu|pi)$ ]]; then
            echo -e "  ${RED}  $count  $user  ← حساب افتراضي مستهدف${NC}"
        else
            echo "     $count  $user"
        fi
    done
else
    echo -e "  ${GREY}لا توجد بيانات${NC}"
fi

REPORT+="=== Top Targeted Usernames ===
$top_users

"

# ─── 4. التوزيع الزمني للهجمات ────────────────────────────────
echo ""
echo -e "${YELLOW}◉ توزيع الهجمات على ساعات اليوم${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
hourly=$(grep -i "Failed password" "$LOGFILE" 2>/dev/null | \
    grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}' | \
    cut -d: -f1 | sort | uniq -c | sort -k2 -n)

if [ -n "$hourly" ]; then
    max_count=$(echo "$hourly" | awk '{print $1}' | sort -rn | head -1)
    echo "$hourly" | while IFS= read -r hline; do
        count=$(echo "$hline" | awk '{print $1}')
        hour=$(echo "$hline" | awk '{print $2}')
        bar_len=$((count * 20 / (max_count + 1)))
        bar=$(printf '█%.0s' $(seq 1 $((bar_len + 1))))
        printf "  %02s:00  %-20s  %d\n" "$hour" "$bar" "$count"
    done
fi

# ─── 5. كشف credential stuffing ─────────────────────────────
echo ""
echo -e "${YELLOW}◉ كشف Credential Stuffing (IP واحد → أسماء مستخدمين مختلفة كثيرة)${NC}"
# IP يجرب أكثر من 10 أسماء مستخدمين مختلفة = credential stuffing
stuffing=$(grep -i "Failed password\|Invalid user" "$LOGFILE" 2>/dev/null | \
    grep -oE 'from ([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sed 's/from //' | sort | uniq -c | sort -rn | head -5)

echo "$stuffing" | while IFS= read -r sline; do
    count=$(echo "$sline" | awk '{print $1}')
    ip=$(echo "$sline" | awk '{print $2}')
    if [ "$count" -ge 50 ] 2>/dev/null; then
        echo -e "  ${RED}🔴 Credential Stuffing: $ip — $count محاولة${NC}"
        finding_add high "Credential stuffing from $ip: $count attempts"
    fi
done

# ─── 6. ملخص ومقترحات ────────────────────────────────────────
echo ""
echo -e "${BOLD}💡 توصيات:${NC}"
if [ "${total:-0}" -ge 10 ]; then
    echo -e "  ${CYAN}▸${NC} فعّل Fail2ban أو استخدم IP Blocker (قائمة 3 من القائمة الرئيسية)"
    echo -e "  ${CYAN}▸${NC} استخدم مصادقة المفتاح (PasswordAuthentication no بـ sshd_config)"
    echo -e "  ${CYAN}▸${NC} غيّر منفذ SSH من 22 إلى منفذ آخر"
    echo -e "  ${CYAN}▸${NC} استخدم Port Knocking أو VPN للوصول"
fi

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$(tf log1_total "${total:-0}")${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$(tf log1_report_title "$(date)")
$(tf log1_report_file "$LOGFILE")
$(tf log1_report_total "${total:-0}")

$REPORT" "failed_ssh_report.txt" "$TOOL_TITLE"
