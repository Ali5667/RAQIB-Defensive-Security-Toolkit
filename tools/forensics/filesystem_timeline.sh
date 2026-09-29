#!/bin/bash
# =====================================================
#  Filesystem Timeline — خط زمني شامل لنظام الملفات
#  يبني timeline دقيق يشمل: mtime/ctime/atime
#  يتعرف على: ملفات تم تعديلها مؤخراً، ملفات جديدة
#  في أماكن حساسة، ملفات مخفية مشبوهة، تغييرات
#  في أوقات غير عادية، ملفات قابلة للتنفيذ بـ /tmp
# =====================================================
finding_reset

TOOL_TITLE="$(t for3_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -rp "$(t for3_prompt_dir)  [افتراضي: /]: " dir
dir="${dir:-/}"
if [ ! -d "$dir" ]; then
    echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1
fi

read -rp "$(t for3_prompt_days)  [افتراضي: 1]: " days
days="${days:-1}"
if ! [[ "$days" =~ ^[0-9]+$ ]] || [ "$days" -eq 0 ]; then
    echo -e "${RED}$(t c_value_must_be_number)${NC}"; exit 1
fi

# هل يريد المستخدم التحليل الكامل؟
read -rp "  هل تريد الفحص الأمني المعمّق للأماكن الحساسة؟ [y/N]: " deep_ans

echo ""
REPORT=""

# ─── دالة مساعدة: طباعة ملف مع تحديد الخطورة ──────────────
check_file_risk() {
    local filepath="$1"
    local context="$2"
    local is_risky=0

    # /tmp أو /var/tmp قابل للتنفيذ
    if [[ "$filepath" == /tmp/* ]] || [[ "$filepath" == /var/tmp/* ]]; then
        if [ -x "$filepath" ] 2>/dev/null; then
            echo -e "  ${RED}[CRITICAL] ملف تنفيذي بـ /tmp: $filepath${NC}"
            finding_add critical "Executable in /tmp: $filepath"
            is_risky=1
        fi
    fi

    # ملفات مخفية في /etc أو /bin
    if [[ "$filepath" == /etc/.* ]] || [[ "$filepath" == /bin/.* ]] || [[ "$filepath" == /sbin/.* ]]; then
        echo -e "  ${RED}[HIGH] ملف مخفي في دليل نظام حساس: $filepath${NC}"
        finding_add high "Hidden file in system directory: $filepath"
        is_risky=1
    fi

    # ملف SUID/SGID جديد
    if [ -f "$filepath" ] 2>/dev/null; then
        perm=$(raqib_stat_perm "$filepath" 2>/dev/null)
        if [[ "$perm" =~ ^[467] ]]; then
            echo -e "  ${ORANGE}[HIGH] ملف SUID/SGID جديد: $filepath (perms: $perm)${NC}"
            finding_add high "New SUID/SGID file: $filepath (perms: $perm)"
            is_risky=1
        fi
    fi

    # لو ما فيه شيء غريب
    [ "$is_risky" -eq 0 ] && echo "  $filepath"
}

# ─── 1. ملفات تم تعديلها حديثاً (mtime) ─────────────────────
echo -e "${YELLOW}$(tf for3_modified_files "$days")${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if command -v find >/dev/null 2>&1; then
    # GNU find: -printf للوقت الدقيق
    if find "$dir" -maxdepth 1 -printf '%T@\n' 2>/dev/null | head -1 | grep -qE '^[0-9]'; then
        mtime_list=$(find "$dir" -xdev -type f -mtime -"$days" \
            -printf '%T@ %TY-%Tm-%Td %TH:%TM:%TS  %p\n' 2>/dev/null | \
            sort -rn | cut -d' ' -f2- | head -60)
    else
        # BSD find: بدون -printf
        mtime_list=$(find "$dir" -xdev -type f -mtime -"$days" 2>/dev/null | \
            xargs ls -lt 2>/dev/null | awk '{print $6, $7, $8, $9}' | head -60)
    fi

    if [ -n "$mtime_list" ]; then
        mtime_count=$(echo "$mtime_list" | wc -l)
        echo -e "  ${BOLD}$mtime_count ملف تم تعديله في آخر ${days} يوم:${NC}"
        echo ""
        echo "$mtime_list" | while IFS= read -r fline; do
            filepath=$(echo "$fline" | awk '{print $NF}')
            check_file_risk "$filepath" "mtime"
        done
    else
        echo -e "  ${GREEN}لا توجد ملفات معدّلة في آخر ${days} يوم${NC}"
    fi
else
    echo -e "  ${RED}أمر find غير متوفر${NC}"
    mtime_list=""
fi

REPORT+="$(t for3_content_mod)
${mtime_list:-لا يوجد}

"

# ─── 2. ملفات تم تغيير metadata/صلاحياتها (ctime) ───────────
echo ""
echo -e "${YELLOW}$(t for3_perm_changed)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if find "$dir" -maxdepth 1 -printf '%C@\n' 2>/dev/null | head -1 | grep -qE '^[0-9]'; then
    ctime_list=$(find "$dir" -xdev -type f -ctime -"$days" \
        -printf '%C@ %CY-%Cm-%Cd %CH:%CM:%CS  %p\n' 2>/dev/null | \
        sort -rn | cut -d' ' -f2- | head -40)
else
    ctime_list=$(find "$dir" -xdev -type f -newer /tmp/.raqib_ctime_ref 2>/dev/null \
        | head -40 2>/dev/null || \
        find "$dir" -xdev -type f -mtime -"$days" 2>/dev/null | head -40)
fi

if [ -n "$ctime_list" ]; then
    echo "$ctime_list" | head -40
else
    echo -e "  ${GREEN}لا توجد ملفات تغيّرت صلاحياتها${NC}"
fi

REPORT+="$(t for3_perm_own_change)
${ctime_list:-لا يوجد}

"

# ─── 3. فحص أماكن حساسة (Deep Security) ─────────────────────
if [ "${deep_ans,,}" = "y" ]; then
    echo ""
    echo -e "${YELLOW}◉ فحص أماكن النظام الحساسة (آخر ${days} يوم)${NC}"
    echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

    SENSITIVE_DIRS=(
        "/etc" "/bin" "/sbin" "/usr/bin" "/usr/sbin"
        "/lib" "/lib64" "/usr/lib" "/boot"
        "/tmp" "/var/tmp" "/dev/shm"
        "/root" "/var/spool/cron" "/etc/cron.d"
        "/etc/init.d" "/etc/systemd/system"
        "/etc/profile.d" "/etc/ld.so.conf.d"
    )

    SENSITIVE_REPORT=""
    for sdir in "${SENSITIVE_DIRS[@]}"; do
        [ -d "$sdir" ] || continue
        recent=$(find "$sdir" -maxdepth 2 -type f -mtime -"$days" 2>/dev/null | head -20)
        if [ -n "$recent" ]; then
            echo ""
            echo -e "  ${BOLD}${ORANGE}◆ $sdir${NC}"
            echo "$recent" | while IFS= read -r f; do
                check_file_risk "$f" "sensitive"
            done
            SENSITIVE_REPORT+="=== $sdir ===
$recent

"
            # خطر خاص: /tmp executable
            if [[ "$sdir" == "/tmp" ]] || [[ "$sdir" == "/var/tmp" ]] || [[ "$sdir" == "/dev/shm" ]]; then
                exec_files=$(find "$sdir" -maxdepth 2 -type f -executable -mtime -"$days" 2>/dev/null)
                if [ -n "$exec_files" ]; then
                    echo -e "  ${RED}[CRITICAL] ملفات تنفيذية جديدة بـ $sdir:${NC}"
                    echo "$exec_files" | while IFS= read -r ef; do
                        echo -e "  ${RED}  🔴 $ef${NC}"
                        finding_add critical "New executable in $sdir: $ef"
                    done
                fi
            fi
        fi
    done

    REPORT+="=== Sensitive Directories ===
$SENSITIVE_REPORT
"
fi

# ─── 4. ملفات مخفية جديدة ─────────────────────────────────
echo ""
echo -e "${YELLOW}◉ ملفات مخفية جديدة (تبدأ بنقطة) في آخر ${days} يوم${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
hidden_new=$(find /tmp /var/tmp /home /root /etc -maxdepth 3 \
    -name ".*" -type f -mtime -"$days" 2>/dev/null | head -20)
if [ -n "$hidden_new" ]; then
    echo "$hidden_new" | while IFS= read -r hf; do
        echo -e "  ${ORANGE}⚠️  $hf${NC}"
        finding_add medium "New hidden file: $hf"
    done
else
    echo -e "  ${GREEN}لا توجد ملفات مخفية جديدة${NC}"
fi

REPORT+="Hidden files:
${hidden_new:-None}

"

# ─── 5. إحصائيات ────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$(tf for3_report_title "$dir" "$days")

$REPORT" "filesystem_timeline.txt" "$TOOL_TITLE"
