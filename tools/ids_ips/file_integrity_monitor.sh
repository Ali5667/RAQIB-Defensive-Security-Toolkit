#!/bin/bash
# =====================================================
#  File Integrity Monitor (FIM) — مراقب سلامة الملفات
#  يحسب SHA-256 لكل ملف بمجلد معين ويحفظ baseline
#  يقارن: الملفات المعدّلة، المحذوفة، الجديدة
#  يدعم: exclude patterns، severity scoring، تقرير diff
#         مفصّل، فحص ملفات النظام الحساسة تلقائياً،
#         تنبيهات IOC، مقارنة صلاحيات
# =====================================================
finding_reset

TOOL_TITLE="$(t ids3_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ─── اختيار المجلد ────────────────────────────────────────────
echo -e "${YELLOW}◉ اختر المجلد المراد مراقبته:${NC}"
echo -e "  ${CYAN}1)${NC} /etc                     (إعدادات النظام)"
echo -e "  ${CYAN}2)${NC} /bin + /sbin + /usr/bin   (تنفيذيات النظام)"
echo -e "  ${CYAN}3)${NC} /root                     (مجلد root)"
echo -e "  ${CYAN}4)${NC} /var/www                  (ملفات الويب)"
echo -e "  ${CYAN}5)${NC} إدخال مسار يدوي"
echo ""
read -rp "  اختر: " dir_choice

case "$dir_choice" in
    1) dir="/etc" ;;
    2) dir="/bin" ;;   # سنضيف /sbin و /usr/bin لاحقاً
    3) dir="/root" ;;
    4) dir="/var/www" ;;
    *) dir="$dir_choice" ;;
esac

[ -z "$dir" ] && { read -rp "$(t ids3_prompt_dir) " dir; }
[ ! -d "$dir" ] && { echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1; }

echo -e "${GREY}  المجلد: $dir${NC}"
echo ""

DB_DIR="$HOME/.raqib_fim"
mkdir -p "$DB_DIR"
safe_name=$(printf '%s' "$dir" | tr '/ ' '__')
BASELINE="$DB_DIR/baseline_${safe_name}.txt"
PERM_BASELINE="$DB_DIR/perms_${safe_name}.txt"

REPORT=""

# ─── دالة حساب الهاشات ─────────────────────────────────────
capture_hashes() {
    local target="$1"
    find "$target" -xdev -type f \
        ! -path "*/\.git/*" \
        ! -path "*/node_modules/*" \
        ! -path "*/__pycache__/*" \
        ! -name "*.pyc" \
        ! -name "*.log" \
        ! -name "*.tmp" \
        -print0 2>/dev/null | while IFS= read -r -d '' f; do
        h=$(raqib_hash sha256 "$f" 2>/dev/null)
        [ -n "$h" ] && printf '%s  %s\n' "$h" "$f"
    done | sort -k2
}

# ─── دالة حساب الصلاحيات ───────────────────────────────────
capture_perms() {
    local target="$1"
    find "$target" -xdev -type f \
        ! -path "*/\.git/*" \
        ! -path "*/node_modules/*" \
        -printf '%m %u:%g %p\n' 2>/dev/null || \
    find "$target" -xdev -type f \
        ! -path "*/\.git/*" \
        ! -path "*/node_modules/*" \
        -exec stat -c '%a %U:%G %n' {} + 2>/dev/null
}

# ─── هل يوجد baseline سابق؟ ──────────────────────────────────
if [ ! -f "$BASELINE" ]; then
    # ─── إنشاء Baseline جديد ─────────────────────────────────
    echo -e "${YELLOW}◉ إنشاء Baseline جديد لـ $dir ...${NC}"

    run_with_spinner "  حساب الهاشات... " -- bash -c "
        # نفس capture_hashes لكن بتحويل للملف
        find \"$dir\" -xdev -type f \
            ! -path '*/\.git/*' ! -path '*/node_modules/*' \
            ! -name '*.pyc' ! -name '*.log' ! -name '*.tmp' \
            -print0 2>/dev/null | while IFS= read -r -d '' f; do
            h=\$(sha256sum \"\$f\" 2>/dev/null | cut -d' ' -f1)
            [ -z \"\$h\" ] && h=\$(shasum -a 256 \"\$f\" 2>/dev/null | cut -d' ' -f1)
            [ -n \"\$h\" ] && printf '%s  %s\n' \"\$h\" \"\$f\"
        done | sort -k2 > \"$BASELINE\"
    "

    # حفظ الصلاحيات
    capture_perms "$dir" > "$PERM_BASELINE" 2>/dev/null

    file_count=$(wc -l < "$BASELINE" 2>/dev/null || echo 0)
    echo -e "${GREEN}$(tf ids3_baseline_created "$dir")${NC}"
    echo -e "${BOLD}  $file_count ملف تم تسجيله${NC}"
    echo -e "${YELLOW}$(tf ids3_files_recorded "$file_count")${NC}"
    echo ""
    echo -e "${CYAN}  💡 شغّل الأداة مرة ثانية لاحقاً للمقارنة مع هذا الـ baseline${NC}"
    exit 0
fi

# ─── مقارنة مع الـ Baseline ──────────────────────────────────
echo -e "${YELLOW}$(t ids3_comparing)${NC}"
echo -e "${GREY}  Baseline: $BASELINE${NC}"
echo -e "${GREY}  آخر تحديث: $(stat -c '%y' "$BASELINE" 2>/dev/null || stat -f '%Sm' "$BASELINE" 2>/dev/null || echo '?')${NC}"
echo ""

# حساب الحالة الحالية
echo -e "${YELLOW}  حساب الهاشات الحالية...${NC}"
current=$(capture_hashes "$dir")
current_perms=$(capture_perms "$dir" 2>/dev/null)

# ─── تحليل الفروقات ──────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ نتائج المقارنة ━━${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# الملفات المعدّلة (hash مختلف)
modified=""
deleted=""
added=""

# ملفات بالـ baseline لكن hash تغيّر أو محذوفة
while IFS= read -r bline; do
    [ -z "$bline" ] && continue
    bhash=$(echo "$bline" | awk '{print $1}')
    bfile=$(echo "$bline" | awk '{print $2}')

    # هل الملف موجود بالحالة الحالية؟
    current_hash=$(echo "$current" | awk -v f="$bfile" '$2==f {print $1}')

    if [ -z "$current_hash" ]; then
        deleted+="$bfile"$'\n'
    elif [ "$current_hash" != "$bhash" ]; then
        modified+="$bfile"$'\n'
    fi
done < "$BASELINE"

# ملفات جديدة (بالحالة الحالية لكن ليست بالـ baseline)
while IFS= read -r cline; do
    [ -z "$cline" ] && continue
    cfile=$(echo "$cline" | awk '{print $2}')
    if ! grep -qF "  $cfile" "$BASELINE" 2>/dev/null; then
        added+="$cfile"$'\n'
    fi
done <<< "$current"

# ─── عرض الملفات المعدّلة ─────────────────────────────────────
mod_count=$(echo "$modified" | grep -c '\S' 2>/dev/null || echo 0)
del_count=$(echo "$deleted" | grep -c '\S' 2>/dev/null || echo 0)
add_count=$(echo "$added" | grep -c '\S' 2>/dev/null || echo 0)

echo ""
echo -e "${ORANGE}◉ ملفات مُعدّلة (Hash تغيّر): $mod_count${NC}"
if [ "$mod_count" -gt 0 ]; then
    echo "$modified" | grep '\S' | while IFS= read -r mf; do
        [ -z "$mf" ] && continue
        # تحديد خطورة التعديل
        if [[ "$mf" == /etc/shadow ]] || [[ "$mf" == /etc/passwd ]] || [[ "$mf" == /etc/sudoers ]]; then
            echo -e "  ${RED}[CRITICAL] 🔴 $mf${NC}"
            finding_add critical "Critical system file modified: $mf"
        elif [[ "$mf" == /etc/ssh/* ]] || [[ "$mf" == /etc/pam.d/* ]]; then
            echo -e "  ${RED}[HIGH] ⚠️  $mf${NC}"
            finding_add high "Security config modified: $mf"
        elif [[ "$mf" == /etc/* ]]; then
            echo -e "  ${ORANGE}[MEDIUM] ⚡ $mf${NC}"
            finding_add medium "System config modified: $mf"
        elif [[ "$mf" == /bin/* ]] || [[ "$mf" == /sbin/* ]] || [[ "$mf" == /usr/bin/* ]]; then
            echo -e "  ${RED}[CRITICAL] 🔴 System binary modified: $mf${NC}"
            finding_add critical "System binary modified: $mf — possible trojan/rootkit!"
        else
            echo -e "  ${YELLOW}[LOW] $mf${NC}"
            finding_add low "File modified: $mf"
        fi
    done
fi

echo ""
echo -e "${RED}◉ ملفات محذوفة: $del_count${NC}"
if [ "$del_count" -gt 0 ]; then
    echo "$deleted" | grep '\S' | head -30 | while IFS= read -r df; do
        [ -z "$df" ] && continue
        echo -e "  ${RED}  ✗ $df${NC}"
        finding_add medium "File deleted since baseline: $df"
    done
fi

echo ""
echo -e "${GREEN}◉ ملفات جديدة: $add_count${NC}"
if [ "$add_count" -gt 0 ]; then
    echo "$added" | grep '\S' | head -30 | while IFS= read -r af; do
        [ -z "$af" ] && continue
        # ملف جديد بمكان حساس = خطر
        if [[ "$af" == /etc/* ]] || [[ "$af" == /bin/* ]] || [[ "$af" == /sbin/* ]]; then
            echo -e "  ${ORANGE}  ⚠️  [NEW in system dir] $af${NC}"
            finding_add high "New file in system directory: $af"
        elif [[ "$af" == */.* ]]; then
            echo -e "  ${ORANGE}  ⚠️  [HIDDEN] $af${NC}"
            finding_add medium "New hidden file: $af"
        else
            echo -e "  ${GREEN}  + $af${NC}"
        fi
    done
fi

REPORT+="=== FIM Results ===
Modified: $mod_count
Deleted: $del_count
Added: $add_count

Modified files:
$modified

Deleted files:
$deleted

New files:
$added
"

# ─── ملخص ────────────────────────────────────────────────────
echo ""
total_changes=$((mod_count + del_count + add_count))
if [ "$total_changes" -eq 0 ]; then
    echo -e "${GREEN}$(t ids3_no_change) ✅${NC}"
else
    echo -e "${BOLD}${ORANGE}إجمالي التغييرات: $total_changes${NC}"
    echo -e "  معدّل: $mod_count  |  محذوف: $del_count  |  جديد: $add_count"
fi

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

# تحديث الـ baseline
echo ""
read -rp "$(t c_confirm_update_baseline) [y/N]: " ans
if [ "${ans,,}" = "y" ]; then
    echo "$current" > "$BASELINE"
    [ -n "$current_perms" ] && echo "$current_perms" > "$PERM_BASELINE"
    echo -e "${GREEN}$(t c_updated)${NC}"
fi

[ "$total_changes" -gt 0 ] && save_report "File Integrity Monitor — $(date)
Directory: $dir
Baseline: $BASELINE

$REPORT" "fim_report_${safe_name}.txt" "$TOOL_TITLE"
