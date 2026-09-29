#!/bin/bash
# =====================================================
#  Login History Report — تقرير سجل تسجيل الدخول
#  يجمع: last + lastb + lastlog + wtmp + utmp
#  يحلل: أنماط تسجيل الدخول المشبوهة، الساعات الغريبة،
#         IPs غير المعتادة، محاولات الفاشلة المتكررة
# =====================================================
finding_reset

TOOL_TITLE="$(t for1_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

# ─── 1. آخر 30 تسجيل دخول ناجح ─────────────────────────────
echo -e "${YELLOW}$(t for1_successful)${NC}"
if command -v last >/dev/null 2>&1; then
    successful=$(last -n 30 -w 2>/dev/null | grep -v "^$\|^wtmp\|^btmp" | head -30)
    if [ -n "$successful" ]; then
        echo "$successful" | while IFS= read -r line; do
            # تحليل: تسجيل دخول في ساعات غريبة (23:00 - 05:00)
            hour=$(echo "$line" | grep -oE '[0-9]{2}:[0-9]{2}' | head -1 | cut -d: -f1)
            if [ -n "$hour" ] && [ "$hour" -ge 23 -o "$hour" -le 5 ] 2>/dev/null; then
                echo -e "${ORANGE}  [ساعة غريبة] $line${NC}"
                finding_add medium "Login during unusual hours: $line"
            else
                echo "  $line"
            fi
        done
    else
        echo -e "  ${GREY}(لا توجد بيانات)${NC}"
    fi
else
    echo -e "  ${YELLOW}أمر 'last' غير متوفر${NC}"
    successful=""
fi

REPORT+="$(t for1_successful)
${successful:-N/A}

"

# ─── 2. محاولات الدخول الفاشلة (lastb) ──────────────────────
echo ""
echo -e "${YELLOW}$(t for1_failed)${NC}"
if command -v lastb >/dev/null 2>&1; then
    failed=$(lastb -n 20 -w 2>/dev/null | grep -v "^$\|^btmp" | head -20)
    if [ -n "$failed" ]; then
        # حساب عدد المحاولات لكل IP
        echo ""
        echo -e "  ${BOLD}● أعلى IPs بعدد محاولات فاشلة:${NC}"
        echo "$failed" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -10 | \
        while read -r count ip; do
            if [ "$count" -ge 10 ]; then
                echo -e "  ${RED}  🔴 $count محاولة  →  $ip${NC}"
                finding_add high "Multiple failed logins from $ip: $count attempts"
            elif [ "$count" -ge 3 ]; then
                echo -e "  ${ORANGE}  🟠 $count محاولة  →  $ip${NC}"
                finding_add medium "Repeated failed logins from $ip: $count attempts"
            else
                echo -e "  ${YELLOW}  🟡 $count محاولة  →  $ip${NC}"
            fi
        done
        echo ""
        echo "$failed"
    else
        echo -e "  ${GREEN}لا توجد محاولات دخول فاشلة مسجّلة${NC}"
    fi
else
    echo -e "  ${YELLOW}$(t for1_needs_root) (يحتاج صلاحية root لأمر lastb)${NC}"
    failed=""
fi

REPORT+="$(t for1_failed)
${failed:-N/A}

"

# ─── 3. آخر تسجيل دخول لكل مستخدم ──────────────────────────
echo ""
echo -e "${YELLOW}$(t for1_last_per_user)${NC}"
if command -v lastlog >/dev/null 2>&1; then
    lastlogins=$(lastlog 2>/dev/null | grep -v "Never logged in" | head -30)
    echo "$lastlogins"
else
    # بديل: قراءة /etc/passwd + wtmp
    echo -e "  ${YELLOW}أمر lastlog غير متوفر — فحص /etc/passwd${NC}"
    lastlogins=$(awk -F: '$3>=1000 && $3<65534{print $1}' /etc/passwd 2>/dev/null | head -20)
    echo "$lastlogins"
fi

REPORT+="$(t for1_last_per_user)
${lastlogins:-N/A}

"

# ─── 4. جلسات SSH النشطة حالياً ───────────────────────────
echo ""
echo -e "${YELLOW}◉ الجلسات النشطة حالياً${NC}"
active_sessions=$(who 2>/dev/null)
if [ -n "$active_sessions" ]; then
    echo "$active_sessions" | while IFS= read -r line; do
        echo -e "  ${CYAN}▸${NC} $line"
    done
    session_count=$(echo "$active_sessions" | wc -l)
    if [ "$session_count" -gt 5 ]; then
        finding_add medium "Unusually high number of active sessions: $session_count"
        echo -e "  ${ORANGE}⚠️  $session_count جلسة نشطة — عدد مرتفع${NC}"
    fi
else
    echo -e "  ${GREEN}لا توجد جلسات نشطة${NC}"
fi

REPORT+="Active Sessions:
${active_sessions:-None}

"

# ─── 5. مستخدمون في مجموعة sudo/wheel ─────────────────────
echo ""
echo -e "${YELLOW}◉ المستخدمون بصلاحية sudo/wheel${NC}"
sudo_users=""
if command -v getent >/dev/null 2>&1; then
    sudo_users=$(getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | grep -v '^$')
fi
if [ -z "$sudo_users" ]; then
    sudo_users=$(grep -E "^sudo:|^wheel:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | grep -v '^$')
fi
if [ -n "$sudo_users" ]; then
    echo "$sudo_users" | while IFS= read -r u; do
        echo -e "  ${YELLOW}⚡ $u${NC}"
    done
else
    echo -e "  ${GREY}لا توجد بيانات (تحتاج صلاحية كافية)${NC}"
fi

REPORT+="Sudo/Wheel users:
${sudo_users:-N/A}

"

# ─── 6. UTmp/WTmp لفحص تعديلات ──────────────────────────
echo ""
echo -e "${YELLOW}◉ فحص سجلات wtmp/btmp${NC}"
for wfile in /var/log/wtmp /var/log/btmp; do
    if [ -f "$wfile" ]; then
        perm=$(raqib_stat_perm "$wfile" 2>/dev/null)
        size=$(raqib_stat_size "$wfile" 2>/dev/null)
        echo -e "  ${CYAN}$wfile${NC}  perms: $perm  size: ${size} bytes"
        # فحص: ملف فارغ أو محذوف = tamper مشبوه
        if [ "$size" -eq 0 ] 2>/dev/null; then
            echo -e "  ${RED}  ⚠️ الملف فارغ — ربما تم مسحه للتغطية على آثار الاختراق!${NC}"
            finding_add critical "$(basename "$wfile") is empty — possible log tampering"
        fi
    fi
done

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$(tf for1_report_title "$(date)")

$REPORT

=== Active Sessions ===
$(who 2>/dev/null)

=== Sudo/Wheel Users ===
$sudo_users" "login_history_report.txt" "$TOOL_TITLE"
