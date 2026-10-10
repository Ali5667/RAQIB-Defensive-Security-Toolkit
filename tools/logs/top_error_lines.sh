#!/bin/bash
# =====================================================
#  Top Error Lines — أكثر أسطر الأخطاء تكراراً
#  يحلل: أعلى 30 رسالة خطأ/تحذير متكررة مع التصنيف
#  يدعم: تطبيع الرسائل (حذف timestamps/PIDs) لتجميع
#  الرسائل المتشابهة، التوزيع الزمني، فلترة بنمط
# =====================================================
finding_reset

TOOL_TITLE="$(t log3_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ─── اختيار الملف ─────────────────────────────────────────────
echo -e "${YELLOW}◉ اختر السجل:${NC}"
echo -e "  ${CYAN}1)${NC} /var/log/syslog"
echo -e "  ${CYAN}2)${NC} /var/log/messages"
echo -e "  ${CYAN}3)${NC} /var/log/kern.log"
echo -e "  ${CYAN}4)${NC} /var/log/apache2/error.log"
echo -e "  ${CYAN}5)${NC} /var/log/nginx/error.log"
echo -e "  ${CYAN}6)${NC} إدخال مسار يدوي"
echo ""
read -rp "  اختر رقم أو اكتب المسار: " log_choice

case "$log_choice" in
    1) logfile="/var/log/syslog" ;;
    2) logfile="/var/log/messages" ;;
    3) logfile="/var/log/kern.log" ;;
    4) logfile="/var/log/apache2/error.log" ;;
    5) logfile="/var/log/nginx/error.log" ;;
    *) logfile="$log_choice" ;;
esac

[ -z "$logfile" ] && { read -rp "$(t log2_prompt_path) " logfile; }
if [ ! -f "$logfile" ]; then
    echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1
fi

FILE_SIZE=$(raqib_stat_size "$logfile" 2>/dev/null || echo "?")
LINE_COUNT=$(wc -l < "$logfile" 2>/dev/null || echo "?")
echo -e "${GREY}  الملف: $logfile  |  $LINE_COUNT سطر  |  $FILE_SIZE bytes${NC}"
echo ""

# ─── فلترة (اختياري) ──────────────────────────────────────────
echo -e "${YELLOW}◉ فلترة:${NC}"
echo -e "  ${CYAN}1)${NC} الكل (بدون فلتر)"
echo -e "  ${CYAN}2)${NC} أخطاء فقط (error|fail|critical)"
echo -e "  ${CYAN}3)${NC} تحذيرات فقط (warn)"
echo -e "  ${CYAN}4)${NC} أمان فقط (denied|unauthorized|invalid)"
echo -e "  ${CYAN}5)${NC} فلتر مخصص"
echo ""
read -rp "  اختر: " filter_choice

case "$filter_choice" in
    1) filter="" ;;
    2) filter="error|fail|critical" ;;
    3) filter="warn" ;;
    4) filter="denied|unauthorized|invalid" ;;
    5) read -rp "$(t log3_prompt_filter) " filter ;;
    *) filter="$filter_choice" ;;
esac

REPORT=""

# ─── 1. تحليل الأسطر الأكثر تكراراً ─────────────────────────
echo ""
echo -e "${YELLOW}$(t log3_top20) (أعلى 30 رسالة)${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# تطبيع الرسائل: حذف التاريخ والـ PID لتجميع المتشابه
normalize_line() {
    # حذف syslog timestamp (MMM DD HH:MM:SS hostname)
    sed -E 's/^[A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\s+[A-Za-z0-9._-]+\s+//' | \
    # حذف PID
    sed -E 's/\[[0-9]+\]//g' | \
    # حذف أرقام عشوائية (session IDs, PIDs)
    sed -E 's/[0-9]{5,}/NNN/g'
}

if [ -n "$filter" ]; then
    raw=$(grep -iE -- "$filter" "$logfile" 2>/dev/null)
else
    raw=$(cat "$logfile" 2>/dev/null)
fi

if [ -z "$raw" ]; then
    echo -e "${GREEN}  لا توجد نتائج${NC}"
    exit 0
fi

total_matched=$(echo "$raw" | wc -l)
echo -e "  ${BOLD}$total_matched سطر مطابق${NC}"
echo ""

# أعلى 30 رسالة متكررة (بالتطبيع)
top_normalized=$(echo "$raw" | normalize_line | sort | uniq -c | sort -rn | head -30)

# عرض مع التصنيف
rank=1
echo "$top_normalized" | while IFS= read -r tline; do
    count=$(echo "$tline" | awk '{print $1}')
    msg=$(echo "$tline" | sed 's/^\s*[0-9]*\s*//')

    # تحديد مستوى الخطورة
    if echo "$msg" | grep -qiE "critical|emergency|panic|segfault|oom"; then
        badge="${RED}[CRIT]${NC}"
        finding_add critical "Repeated critical error ($count times): $(echo "$msg" | head -c 80)"
    elif echo "$msg" | grep -qiE "error|fail|denied|refused"; then
        badge="${ORANGE}[ERR] ${NC}"
        [ "$count" -ge 50 ] && finding_add high "Repeated error ($count times): $(echo "$msg" | head -c 80)"
    elif echo "$msg" | grep -qiE "warn"; then
        badge="${YELLOW}[WARN]${NC}"
    else
        badge="${GREY}[INFO]${NC}"
    fi

    printf "  ${BOLD}#%-3d${NC} ${badge} %-6d  %s\n" "$rank" "$count" "$(echo "$msg" | head -c 100)"
    rank=$((rank + 1))
done

REPORT+="=== Top Error Lines ===
$top_normalized

"

# ─── 2. التوزيع الزمني لأكثر رسالة ───────────────────────────
echo ""
echo -e "${YELLOW}◉ التوزيع الزمني لأكثر رسالة تكراراً:${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
top_msg=$(echo "$top_normalized" | head -1 | sed 's/^\s*[0-9]*\s*//')
if [ -n "$top_msg" ]; then
    # ابحث عن الرسالة الأصلية (قبل التطبيع) لعمل التوزيع الزمني
    # استخدم أول 40 حرف من الرسالة
    search_pat=$(echo "$top_msg" | head -c 40 | sed 's/[.*+?^${}()|[\]\\]/\\&/g; s/NNN/[0-9]*/g')
    hourly=$(grep -E "$search_pat" "$logfile" 2>/dev/null | \
        grep -oE '[0-9]{2}:[0-9]{2}' | cut -d: -f1 | sort | uniq -c | sort -k2 -n)

    if [ -n "$hourly" ]; then
        max_h=$(echo "$hourly" | awk '{print $1}' | sort -rn | head -1)
        echo "$hourly" | while IFS= read -r hline; do
            hcount=$(echo "$hline" | awk '{print $1}')
            hour=$(echo "$hline" | awk '{print $2}')
            bar_len=$((hcount * 20 / (max_h + 1)))
            bar=$(printf '█%.0s' $(seq 1 $((bar_len + 1))) 2>/dev/null || echo "=")
            printf "  %02s:00  %-20s  %d\n" "$hour" "$bar" "$hcount"
        done
    fi
fi

# ─── 3. ملخص سريع ────────────────────────────────────────────
echo ""
echo -e "${YELLOW}◉ ملخص سريع:${NC}"
total_errors=$(echo "$raw" | grep -ciE "error|fail|critical" 2>/dev/null || echo 0)
total_warns=$(echo "$raw" | grep -ciE "warn" 2>/dev/null || echo 0)
unique_msgs=$(echo "$top_normalized" | wc -l)
echo -e "  إجمالي الأسطر: $total_matched"
echo -e "  أخطاء: ${RED}$total_errors${NC}"
echo -e "  تحذيرات: ${YELLOW}$total_warns${NC}"
echo -e "  رسائل فريدة (بعد التطبيع): $unique_msgs"

# ─── 4. خلاصة ─────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Top Error Lines — $(date)
File: $logfile
Filter: ${filter:-none}
Total matched: $total_matched

$REPORT" "top_error_lines.txt" "$TOOL_TITLE"
