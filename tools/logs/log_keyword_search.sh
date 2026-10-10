#!/bin/bash
# =====================================================
#  Log Keyword Search — بحث ذكي في سجلات النظام
#  يدعم: بحث regex، highlight ملوّن، سياق الأسطر،
#  فلترة بوقت، إحصاء التوزيع الزمني، تصدير ملوّن،
#  بحث متعدد الملفات، كشف أنماط خطيرة تلقائياً
# =====================================================
finding_reset

TOOL_TITLE="$(t log2_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ─── 1. اختيار الملف ─────────────────────────────────────────
echo -e "${YELLOW}◉ مسارات سجلات شائعة:${NC}"
echo -e "  ${CYAN}1)${NC} /var/log/syslog"
echo -e "  ${CYAN}2)${NC} /var/log/auth.log"
echo -e "  ${CYAN}3)${NC} /var/log/kern.log"
echo -e "  ${CYAN}4)${NC} /var/log/messages"
echo -e "  ${CYAN}5)${NC} /var/log/apache2/access.log"
echo -e "  ${CYAN}6)${NC} /var/log/apache2/error.log"
echo -e "  ${CYAN}7)${NC} /var/log/nginx/access.log"
echo -e "  ${CYAN}8)${NC} /var/log/nginx/error.log"
echo -e "  ${CYAN}9)${NC} إدخال مسار يدوي"
echo ""
read -rp "  اختر رقم أو اكتب المسار: " log_choice

case "$log_choice" in
    1) logfile="/var/log/syslog" ;;
    2) logfile="/var/log/auth.log" ;;
    3) logfile="/var/log/kern.log" ;;
    4) logfile="/var/log/messages" ;;
    5) logfile="/var/log/apache2/access.log" ;;
    6) logfile="/var/log/apache2/error.log" ;;
    7) logfile="/var/log/nginx/access.log" ;;
    8) logfile="/var/log/nginx/error.log" ;;
    *) logfile="$log_choice" ;;
esac

if [ ! -f "$logfile" ]; then
    read -rp "$(t log2_prompt_path) " logfile
fi
if [ ! -f "$logfile" ]; then
    echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1
fi

FILE_SIZE=$(raqib_stat_size "$logfile" 2>/dev/null || echo "?")
LINE_COUNT=$(wc -l < "$logfile" 2>/dev/null || echo "?")
echo -e "${GREY}  الملف: $logfile  |  $LINE_COUNT سطر  |  $FILE_SIZE bytes${NC}"
echo ""

# ─── 2. اختيار الكلمة المفتاحية ──────────────────────────────
echo -e "${YELLOW}◉ أنماط بحث شائعة:${NC}"
echo -e "  ${CYAN}1)${NC} error|fail|critical          (أخطاء عامة)"
echo -e "  ${CYAN}2)${NC} denied|unauthorized|forbidden (رفض وصول)"
echo -e "  ${CYAN}3)${NC} segfault|kernel|panic         (أخطاء نظام)"
echo -e "  ${CYAN}4)${NC} login|auth|session            (مصادقة)"
echo -e "  ${CYAN}5)${NC} بحث مخصص"
echo ""
read -rp "  اختر رقم أو اكتب الكلمة المفتاحية: " kw_choice

case "$kw_choice" in
    1) keyword="error|fail|critical" ;;
    2) keyword="denied|unauthorized|forbidden" ;;
    3) keyword="segfault|kernel.*panic|oom-killer" ;;
    4) keyword="login|auth|session" ;;
    *) keyword="$kw_choice" ;;
esac

if [ -z "$keyword" ]; then
    read -rp "$(t log2_prompt_keyword) " keyword
fi
if [ -z "$keyword" ]; then
    echo -e "${RED}$(t log2_need_keyword)${NC}"; exit 1
fi

# ─── 3. إعدادات البحث ────────────────────────────────────────
read -rp "  عدد أسطر السياق قبل/بعد كل تطابق [افتراضي: 2]: " ctx
ctx="${ctx:-2}"

read -rp "  هل تريد بحث case-insensitive؟ [Y/n]: " ci_ans
ci_flag="-i"
[ "${ci_ans,,}" = "n" ] && ci_flag=""

echo ""
REPORT=""

# ─── 4. البحث الفعلي ─────────────────────────────────────────
echo -e "${YELLOW}$(tf log2_results_for "$keyword")${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# grep مع regex support
if raqib_pcre_ok 2>/dev/null; then
    search_results=$(grep -nP $ci_flag -B"$ctx" -A"$ctx" --color=always -- "$keyword" "$logfile" 2>/dev/null)
    plain_results=$(grep -nP $ci_flag -- "$keyword" "$logfile" 2>/dev/null)
else
    search_results=$(grep -nE $ci_flag -B"$ctx" -A"$ctx" --color=always -- "$keyword" "$logfile" 2>/dev/null)
    plain_results=$(grep -nE $ci_flag -- "$keyword" "$logfile" 2>/dev/null)
fi

if [ -n "$search_results" ]; then
    echo "$search_results" | head -200
    count=$(echo "$plain_results" | wc -l)
    echo ""
    echo -e "${GREEN}$(tf log2_match_count "$count")${NC}"

    if [ "$count" -gt 200 ]; then
        echo -e "${YELLOW}  (عرض أول 200 نتيجة من أصل $count)${NC}"
    fi
else
    count=0
    echo -e "${GREEN}  لا توجد نتائج مطابقة${NC}"
fi

REPORT+="Search: $keyword in $logfile
Matches: $count

"

# ─── 5. التوزيع الزمني (لو فيه نتائج كافية) ─────────────────
if [ "$count" -ge 5 ] 2>/dev/null; then
    echo ""
    echo -e "${YELLOW}◉ التوزيع الزمني للتطابقات (حسب الساعة):${NC}"
    echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

    hourly=$(echo "$plain_results" | grep -oE '[0-9]{2}:[0-9]{2}:[0-9]{2}' | \
        cut -d: -f1 | sort | uniq -c | sort -k2 -n)

    if [ -n "$hourly" ]; then
        max_h=$(echo "$hourly" | awk '{print $1}' | sort -rn | head -1)
        echo "$hourly" | while IFS= read -r hline; do
            hcount=$(echo "$hline" | awk '{print $1}')
            hour=$(echo "$hline" | awk '{print $2}')
            bar_len=$((hcount * 25 / (max_h + 1)))
            bar=$(printf '█%.0s' $(seq 1 $((bar_len + 1))) 2>/dev/null || echo "=")
            printf "  %02s:00  %-25s  %d\n" "$hour" "$bar" "$hcount"
        done
    fi

    REPORT+="Hourly distribution:
$hourly
"
fi

# ─── 6. كشف أنماط خطيرة تلقائياً ────────────────────────────
if [ "$count" -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}◉ تحليل الخطورة التلقائي:${NC}"
    echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

    # أخطاء حرجة
    crit_count=$(echo "$plain_results" | grep -ciE "critical|emergency|panic|oom-killer|segfault" 2>/dev/null || echo 0)
    err_count=$(echo "$plain_results" | grep -ciE "error|fail" 2>/dev/null || echo 0)
    warn_count=$(echo "$plain_results" | grep -ciE "warn" 2>/dev/null || echo 0)
    auth_count=$(echo "$plain_results" | grep -ciE "denied|unauthorized|forbidden|invalid" 2>/dev/null || echo 0)

    echo -e "  ${RED}● Critical/Panic: $crit_count${NC}"
    echo -e "  ${ORANGE}● Error/Fail: $err_count${NC}"
    echo -e "  ${YELLOW}● Warning: $warn_count${NC}"
    echo -e "  ${CYAN}● Auth denied: $auth_count${NC}"

    [ "$crit_count" -gt 0 ] && finding_add critical "Found $crit_count critical entries in $logfile"
    [ "$err_count" -gt 10 ] && finding_add high "Found $err_count error entries in $logfile"
    [ "$auth_count" -gt 10 ] && finding_add medium "Found $auth_count auth denial entries in $logfile"
fi

# ─── 7. خلاصة ────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

if [ "$count" -gt 0 ]; then
    save_report "Log Keyword Search — $(date)
File: $logfile
Keyword: $keyword
Matches: $count

$REPORT

=== Results (first 500 lines) ===
$(echo "$plain_results" | head -500)" "keyword_search_${keyword// /_}.txt" "$TOOL_TITLE"
fi
