#!/bin/bash
# =====================================================
#  Log Timeline — خط زمني للسجلات بين وقتين
#  يدعم: syslog format (MMM DD HH:MM:SS)،
#  ISO 8601، timestamps رقمية
#  يحلل: معدل الأحداث، كشف burst، spike detection،
#  فلترة بنوع الحدث، تمييز الأحداث الحرجة بالألوان
# =====================================================
finding_reset

TOOL_TITLE="$(t log4_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -rp "$(t log2_prompt_path) " logfile
if [ ! -f "$logfile" ]; then
    echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1
fi

FILE_SIZE=$(raqib_stat_size "$logfile" 2>/dev/null || echo "?")
LINE_COUNT=$(wc -l < "$logfile" 2>/dev/null || echo "?")
echo -e "${GREY}  الملف: $logfile  |  $LINE_COUNT سطر${NC}"
echo ""

# ─── تحديد نطاق الوقت ────────────────────────────────────────
echo -e "${YELLOW}◉ أمثلة على صيغ الوقت:${NC}"
echo -e "  ${GREY}• syslog:  Sep 27 14:30:00${NC}"
echo -e "  ${GREY}• ISO:     2026-09-27T14:30${NC}"
echo -e "  ${GREY}• ساعة:    14:30:00${NC}"
echo ""

read -rp "$(t log4_prompt_from) " from_time
read -rp "$(t log4_prompt_to) " to_time
if [ -z "$from_time" ] || [ -z "$to_time" ]; then
    echo -e "${RED}$(t log4_need_both)${NC}"; exit 1
fi

# هل يريد فلترة إضافية؟
read -rp "  فلترة بكلمة مفتاحية إضافية (Enter للتخطي): " extra_filter

echo ""
echo -e "${YELLOW}$(tf log4_events_between "$from_time" "$to_time")${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

REPORT=""

# ─── استخراج الأحداث في النطاق الزمني ────────────────────────
result=$(awk -v from="$from_time" -v to="$to_time" '
    $0 ~ from {flag=1}
    flag {print}
    $0 ~ to {flag=0}
' "$logfile")

if [ -n "$extra_filter" ]; then
    result=$(echo "$result" | grep -iE "$extra_filter" 2>/dev/null)
fi

if [ -z "$result" ]; then
    echo -e "${GREEN}  لا توجد أحداث في هذا النطاق الزمني${NC}"
    echo ""
    echo -e "${YELLOW}  💡 جرب:${NC}"
    echo -e "  ${GREY}  • تأكد من صيغة الوقت (مثال: Sep 27 14:30)${NC}"
    echo -e "  ${GREY}  • استخدم head/tail لعرض أول/آخر سطر بالملف${NC}"
    echo -e "  ${GREY}  • أول سطر:${NC} $(head -1 "$logfile" 2>/dev/null)"
    echo -e "  ${GREY}  • آخر سطر:${NC} $(tail -1 "$logfile" 2>/dev/null)"
    exit 0
fi

total_events=$(echo "$result" | wc -l)
echo -e "  ${BOLD}$total_events حدث في النطاق الزمني المحدد${NC}"
echo ""

# ─── طباعة ملوّنة ────────────────────────────────────────────
echo "$result" | head -200 | while IFS= read -r line; do
    # تلوين حسب مستوى الخطورة
    if echo "$line" | grep -qiE "critical|emergency|panic|CRIT|EMERG"; then
        echo -e "${RED}$line${NC}"
    elif echo "$line" | grep -qiE "error|err|fail"; then
        echo -e "${ORANGE}$line${NC}"
    elif echo "$line" | grep -qiE "warn|WARNING"; then
        echo -e "${YELLOW}$line${NC}"
    elif echo "$line" | grep -qiE "denied|unauthorized|invalid"; then
        echo -e "${CRIMSON:-$RED}$line${NC}"
    else
        echo "$line"
    fi
done

[ "$total_events" -gt 200 ] && echo -e "\n${GREY}  ... و$((total_events - 200)) حدث إضافي${NC}"

REPORT+="Events between $from_time — $to_time
Total: $total_events
Filter: ${extra_filter:-none}

"

# ─── تحليل: التوزيع بالثانية (burst detection) ──────────────
echo ""
echo -e "${YELLOW}◉ كشف الطفرات (Burst Detection):${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

per_minute=$(echo "$result" | grep -oE '[0-9]{2}:[0-9]{2}' | sort | uniq -c | sort -rn | head -10)
if [ -n "$per_minute" ]; then
    max_m=$(echo "$per_minute" | head -1 | awk '{print $1}')
    echo "$per_minute" | while IFS= read -r mline; do
        count=$(echo "$mline" | awk '{print $1}')
        minute=$(echo "$mline" | awk '{print $2}')
        bar_len=$((count * 25 / (max_m + 1)))
        bar=$(printf '█%.0s' $(seq 1 $((bar_len + 1))) 2>/dev/null || echo "=")
        if [ "$count" -ge 50 ] 2>/dev/null; then
            printf "  ${RED}%s  %-25s  %d events ← BURST!${NC}\n" "$minute" "$bar" "$count"
            finding_add high "Event burst at $minute: $count events/minute"
        elif [ "$count" -ge 20 ] 2>/dev/null; then
            printf "  ${ORANGE}%s  %-25s  %d events${NC}\n" "$minute" "$bar" "$count"
            finding_add medium "High event rate at $minute: $count events/minute"
        else
            printf "  %s  %-25s  %d events\n" "$minute" "$bar" "$count"
        fi
    done
fi

# ─── ملخص الخطورة ────────────────────────────────────────────
echo ""
echo -e "${YELLOW}◉ ملخص مستويات الخطورة في النطاق:${NC}"
crit=$(echo "$result" | grep -ciE "critical|emergency|panic|crit|emerg" || echo 0)
err=$(echo "$result" | grep -ciE "error|err\b|fail" || echo 0)
warn=$(echo "$result" | grep -ciE "warn" || echo 0)
auth=$(echo "$result" | grep -ciE "denied|unauthorized|invalid|forbidden" || echo 0)

echo -e "  ${RED}● Critical/Emergency: $crit${NC}"
echo -e "  ${ORANGE}● Error/Fail: $err${NC}"
echo -e "  ${YELLOW}● Warning: $warn${NC}"
echo -e "  ${CYAN}● Auth Issues: $auth${NC}"

[ "$crit" -gt 0 ] && finding_add critical "$crit critical events in timeline"
[ "$err" -gt 10 ] && finding_add high "$err error events in timeline"

# ─── خلاصة ──────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

[ -n "$result" ] && save_report "Log Timeline — $(date)
File: $logfile
From: $from_time → To: $to_time
Total events: $total_events

$REPORT

=== Events ===
$(echo "$result" | head -1000)" "log_timeline_${from_time//[: ]/_}.txt" "$TOOL_TITLE"
