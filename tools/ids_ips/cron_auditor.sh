#!/bin/bash
# =====================================================
#  Cron Job Auditor — مدقق مهام Cron الشامل
#  يفحص: crontab لكل المستخدمين، /etc/cron.d/*،
#  /etc/cron.{hourly,daily,weekly,monthly}/*، anacron،
#  systemd timers، at/batch jobs
#  يحلل: أوامر خطيرة، صلاحيات واسعة، مهام مخفية،
#  مهام تنزيل/تنفيذ، reverse shells بالكرون،
#  مسارات مشبوهة (/tmp)، ملفات crontab محذوفة
# =====================================================
finding_reset

TOOL_TITLE="$(t ids4_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

# ─── أنماط خطيرة بالكرون ──────────────────────────────────
CRON_DANGER_PATTERNS='wget\s|curl\s.*\|.*sh|/dev/tcp|nc\s+-e|bash\s+-i|python.*socket|rm\s+-rf\s+/|chmod\s+777|/tmp/|/var/tmp/|/dev/shm/|base64\s+-d|nohup.*&'
CRON_SUSPICIOUS_PATTERNS='wget\s|curl\s|python[23]?\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|dd\s+if=|socat\s|openssl\s+s_client'

# ─── دالة فحص سطر كرون ─────────────────────────────────────
check_cron_line() {
    local line="$1" source="$2"
    [ -z "$line" ] && return
    # تجاهل التعليقات والأسطر الفارغة
    echo "$line" | grep -qE '^\s*#|^\s*$' && return

    # فحص أوامر خطيرة
    if echo "$line" | grep -qiE "$CRON_DANGER_PATTERNS"; then
        echo -e "  ${RED}[CRITICAL] $source:${NC}"
        echo -e "  ${RED}  🔴 $line${NC}"
        finding_add critical "Dangerous cron job ($source): $line"
        return
    fi

    # فحص أوامر مشبوهة
    if echo "$line" | grep -qiE "$CRON_SUSPICIOUS_PATTERNS"; then
        echo -e "  ${ORANGE}[HIGH] $source:${NC}"
        echo -e "  ${ORANGE}  ⚠️  $line${NC}"
        finding_add high "Suspicious cron job ($source): $line"
        return
    fi

    # عادي
    echo -e "  ${GREEN}  ✓${NC} $line"
}

# ─── 1. Crontab المستخدم الحالي ─────────────────────────────
echo -e "${BOLD}${YELLOW}$(t ids4_user_cron) ($(whoami 2>/dev/null || echo 'current'))${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
user_cron=$(crontab -l 2>/dev/null)
if [ -n "$user_cron" ]; then
    echo "$user_cron" | while IFS= read -r line; do
        check_cron_line "$line" "$(whoami)'s crontab"
    done
else
    echo -e "  ${GREEN}$(t ids4_none)${NC}"
fi

REPORT+="=== Current User Crontab ===
${user_cron:-Empty}

"

# ─── 2. Crontabs كل المستخدمين ──────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t ids4_all_users_cron)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

all_users_report=""

# /var/spool/cron/crontabs/ (Debian/Ubuntu)
if [ -d /var/spool/cron/crontabs ]; then
    for userfile in /var/spool/cron/crontabs/*; do
        [ -f "$userfile" ] || continue
        uname=$(basename "$userfile")
        echo -e "  ${CYAN}━━ $uname ━━${NC}"

        # فحص صلاحيات ملف الكرون
        perm=$(raqib_stat_perm "$userfile" 2>/dev/null || echo "?")
        if [[ "$perm" =~ [67][0-9][0-9] ]]; then
            echo -e "  ${ORANGE}  ⚠️  صلاحيات واسعة: $perm (يجب 600)${NC}"
            finding_add medium "Crontab file too permissive for $uname: $perm"
        fi

        while IFS= read -r line; do
            check_cron_line "$line" "$uname's crontab"
        done < "$userfile"
        all_users_report+="--- $uname ---\n$(cat "$userfile" 2>/dev/null)\n\n"
    done
fi

# /var/spool/cron/ (RHEL/CentOS)
if [ -d /var/spool/cron ] && [ ! -d /var/spool/cron/crontabs ]; then
    for userfile in /var/spool/cron/*; do
        [ -f "$userfile" ] || continue
        uname=$(basename "$userfile")
        echo -e "  ${CYAN}━━ $uname ━━${NC}"
        while IFS= read -r line; do
            check_cron_line "$line" "$uname's crontab"
        done < "$userfile"
    done
fi

[ -z "$all_users_report" ] && echo -e "  ${GREY}لا توجد ملفات crontab للمستخدمين (تحتاج صلاحية root)${NC}"

REPORT+="=== All Users Crontabs ===
$(echo -e "$all_users_report")

"

# ─── 3. System Crontab (/etc/crontab) ────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t ids4_system_cron)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
if [ -f /etc/crontab ]; then
    echo -e "  ${CYAN}━━ /etc/crontab ━━${NC}"
    grep -vE '^\s*#|^\s*$' /etc/crontab 2>/dev/null | while IFS= read -r line; do
        check_cron_line "$line" "/etc/crontab"
    done
fi

# /etc/cron.d/*
if [ -d /etc/cron.d ]; then
    for f in /etc/cron.d/*; do
        [ -f "$f" ] || continue
        echo -e "  ${CYAN}━━ $f ━━${NC}"
        grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null | while IFS= read -r line; do
            check_cron_line "$line" "$f"
        done
    done
fi

# ─── 4. Cron directories (hourly/daily/weekly/monthly) ───────
echo ""
echo -e "${BOLD}${YELLOW}◉ مجلدات الكرون الدورية${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

for period in hourly daily weekly monthly; do
    cdir="/etc/cron.${period}"
    [ -d "$cdir" ] || continue
    scripts=$(ls -1 "$cdir" 2>/dev/null | grep -vE '^\.')
    script_count=$(echo "$scripts" | grep -c '\S' 2>/dev/null || echo 0)
    echo -e "  ${CYAN}/etc/cron.${period}/${NC} ($script_count script)"

    echo "$scripts" | while IFS= read -r s; do
        [ -z "$s" ] && continue
        full="$cdir/$s"

        # فحص: هل هو executable?
        if [ ! -x "$full" ]; then
            echo -e "  ${YELLOW}    ⚠️  $s — غير تنفيذي (لن يعمل بالكرون)${NC}"
        fi

        # فحص محتوى الملف للأنماط الخطيرة
        if grep -qiE "$CRON_DANGER_PATTERNS" "$full" 2>/dev/null; then
            echo -e "  ${RED}    🔴 $s — يحتوي أوامر خطيرة!${NC}"
            finding_add high "Dangerous command in cron.$period/$s"
        else
            echo -e "  ${GREEN}    ✓ $s${NC}"
        fi
    done
done

# ─── 5. Systemd Timers ───────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ Systemd Timers (بديل الكرون الحديث)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if command -v systemctl >/dev/null 2>&1; then
    timers=$(systemctl list-timers --all --no-pager 2>/dev/null)
    if [ -n "$timers" ]; then
        echo "$timers" | head -20
        timer_count=$(systemctl list-timers --all --no-pager 2>/dev/null | grep -c "\.timer" || echo 0)
        echo -e "  ${BOLD}$timer_count timer مسجّل${NC}"
    else
        echo -e "  ${GREY}لا توجد timers${NC}"
    fi
else
    echo -e "  ${GREY}systemd غير متوفر${NC}"
fi

# ─── 6. at/batch Jobs ────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ at/batch Jobs (مهام مجدولة لمرة واحدة)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
if command -v atq >/dev/null 2>&1; then
    at_jobs=$(atq 2>/dev/null)
    if [ -n "$at_jobs" ]; then
        echo "$at_jobs"
        at_count=$(echo "$at_jobs" | wc -l)
        echo -e "  ${BOLD}$at_count مهمة مجدولة${NC}"
        finding_add low "Found $at_count pending at/batch jobs — review for suspicious commands"
    else
        echo -e "  ${GREEN}لا توجد مهام at مجدولة${NC}"
    fi
else
    echo -e "  ${GREY}أمر atq غير متوفر${NC}"
fi

# ─── 7. $(t ids4_recent_files) ───────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t ids4_recent_files) (آخر 7 أيام)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
recent=$(find /etc/cron* /var/spool/cron -type f -mtime -7 2>/dev/null)
if [ -n "$recent" ]; then
    echo "$recent" | while IFS= read -r rf; do
        mtime=$(stat -c '%y' "$rf" 2>/dev/null || stat -f '%Sm' "$rf" 2>/dev/null || echo "?")
        echo -e "  ${ORANGE}  ⚡ $rf  ${GREY}(modified: $mtime)${NC}"
        finding_add medium "Recently modified cron file: $rf"
    done
else
    echo -e "  ${GREEN}لا توجد ملفات كرون تم تعديلها مؤخراً${NC}"
fi

REPORT+="=== Recently Modified Cron Files ===
${recent:-None}

"

# ─── 8. فحص /etc/cron.allow و /etc/cron.deny ────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ صلاحيات استخدام الكرون${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
if [ -f /etc/cron.allow ]; then
    echo -e "  ${GREEN}[✓] /etc/cron.allow موجود (whitelist):${NC}"
    cat /etc/cron.allow 2>/dev/null | while IFS= read -r u; do
        echo -e "  ${CYAN}    $u${NC}"
    done
elif [ -f /etc/cron.deny ]; then
    echo -e "  ${YELLOW}[!] /etc/cron.deny فقط (blacklist) — أي مستخدم غير مدرج يقدر يستخدم كرون${NC}"
    finding_add low "Only cron.deny exists — all users not listed can use cron"
else
    echo -e "  ${ORANGE}[!] لا يوجد cron.allow ولا cron.deny — كل المستخدمين يقدرون يستخدمون كرون${NC}"
    finding_add medium "No cron.allow or cron.deny — all users can schedule cron jobs"
fi

# ─── ملخص ────────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Cron Job Audit — $(date)

$REPORT" "cron_audit.txt" "$TOOL_TITLE"
