#!/bin/bash
# =====================================================
#  Disk Usage Snapshot — لقطة استخدام القرص مع المقارنة
#  يلتقط baseline، يقارن مع اللقطة السابقة،
#  يحلل: نمو مفاجئ، مجلدات ضخمة جديدة، ملفات
#  ضخمة مشبوهة، امتلاء القرص، استخدام inode
# =====================================================
finding_reset

TOOL_TITLE="$(t for4_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -rp "$(t for4_prompt_dir)  [افتراضي: /]: " dir
dir="${dir:-/}"

SNAP_DIR="$HOME/.raqib_disk_snapshots"
mkdir -p "$SNAP_DIR"
safe_name=$(printf '%s' "$dir" | tr '/ ' '__')
SNAPFILE="$SNAP_DIR/snap_${safe_name}.txt"
REPORT=""

# ─── 1. استخدام القرص الكلي ─────────────────────────────────
echo -e "${YELLOW}◉ استخدام أقراص النظام${NC}"
df_out=$(df -h 2>/dev/null)
echo "$df_out"

# تحذير: قرص ممتلئ فوق 90%
echo ""
df -h 2>/dev/null | awk 'NR>1' | while IFS= read -r dfline; do
    use_pct=$(echo "$dfline" | awk '{print $5}' | tr -d '%')
    mount=$(echo "$dfline" | awk '{print $6}')
    if [[ "$use_pct" =~ ^[0-9]+$ ]]; then
        if [ "$use_pct" -ge 95 ]; then
            echo -e "${RED}[CRITICAL] قرص ممتلئ ${use_pct}%: ${mount}${NC}"
            finding_add critical "Disk ${mount} is ${use_pct}% full — CRITICAL"
        elif [ "$use_pct" -ge 90 ]; then
            echo -e "${ORANGE}[HIGH] قرص ممتلئ ${use_pct}%: ${mount}${NC}"
            finding_add high "Disk ${mount} is ${use_pct}% full"
        elif [ "$use_pct" -ge 80 ]; then
            echo -e "${YELLOW}[MEDIUM] قرص ممتلئ ${use_pct}%: ${mount}${NC}"
            finding_add medium "Disk ${mount} is ${use_pct}% full"
        fi
    fi
done

REPORT+="=== Disk Usage ===
$df_out

"

# ─── 2. استخدام inodes ──────────────────────────────────────
echo ""
echo -e "${YELLOW}◉ استخدام الـ Inodes (فيه inode نافذ = لا تقدر تكتب ملفات جديدة)${NC}"
inode_out=$(df -i 2>/dev/null)
echo "$inode_out"

df -i 2>/dev/null | awk 'NR>1' | while IFS= read -r iline; do
    use_pct=$(echo "$iline" | awk '{print $5}' | tr -d '%')
    mount=$(echo "$iline" | awk '{print $6}')
    if [[ "$use_pct" =~ ^[0-9]+$ ]] && [ "$use_pct" -ge 85 ]; then
        echo -e "${RED}[HIGH] Inode ${use_pct}% مستخدم على ${mount}${NC}"
        finding_add high "Inode exhaustion on ${mount}: ${use_pct}%"
    fi
done

REPORT+="=== Inode Usage ===
$inode_out

"

# ─── 3. أكبر المجلدات ────────────────────────────────────────
echo ""
echo -e "${YELLOW}◉ أكبر المجلدات بـ: $dir${NC}"
if command -v du >/dev/null 2>&1; then
    # GNU du
    if du --version 2>/dev/null | grep -q GNU; then
        current=$(du -ah --max-depth=2 --exclude=/proc --exclude=/sys \
            "$dir" 2>/dev/null | sort -rh | head -30)
    else
        # BSD du
        current=$(du -ahd 2 "$dir" 2>/dev/null | sort -rh | head -30)
    fi
    echo "$current"
else
    current=""
    echo -e "${YELLOW}أمر du غير متوفر${NC}"
fi

REPORT+="=== Directory Sizes ===
$current

"

# ─── 4. أكبر الملفات المفردة ─────────────────────────────────
echo ""
echo -e "${YELLOW}◉ أكبر 20 ملف بالنظام${NC}"
big_files=$(find "$dir" -xdev -type f -printf '%s\t%p\n' 2>/dev/null | \
    sort -rn | head -20 | awk '{
        if ($1 > 1073741824) printf "%.1f GB\t%s\n", $1/1073741824, $2
        else if ($1 > 1048576) printf "%.1f MB\t%s\n", $1/1048576, $2
        else printf "%.0f KB\t%s\n", $1/1024, $2
    }')
if [ -n "$big_files" ]; then
    echo "$big_files"
    # تحذير: ملفات ضخمة جداً في /tmp
    echo "$big_files" | grep -E '^[0-9.]+ [GMK]B\t/tmp' | while IFS= read -r bline; do
        echo -e "${ORANGE}⚠️  ملف ضخم في /tmp: $bline${NC}"
        finding_add medium "Large file in /tmp: $bline"
    done
else
    echo -e "${GREY}(لا توجد بيانات)${NC}"
fi

REPORT+="=== Largest Files ===
$big_files

"

# ─── 5. ملفات /tmp و /var/tmp الضخمة ──────────────────────
echo ""
echo -e "${YELLOW}◉ ملفات مشبوهة في /tmp و /var/tmp${NC}"
tmp_files=$(find /tmp /var/tmp /dev/shm -maxdepth 2 -type f \
    -printf '%s\t%m\t%p\n' 2>/dev/null | sort -rn | head -20)
if [ -n "$tmp_files" ]; then
    echo "$tmp_files" | while IFS=$'\t' read -r fsize fperm fpath; do
        # ملف تنفيذي
        if [[ "$fperm" =~ [1357] ]] || [ -x "$fpath" ] 2>/dev/null; then
            echo -e "  ${RED}[CRITICAL] تنفيذي! $fpath (perms: $fperm, size: $fsize B)${NC}"
            finding_add critical "Executable in /tmp: $fpath"
        # ملف ضخم (>50MB)
        elif [ "$fsize" -gt 52428800 ] 2>/dev/null; then
            size_mb=$((fsize/1048576))
            echo -e "  ${ORANGE}[HIGH] ملف ضخم ${size_mb}MB: $fpath${NC}"
            finding_add high "Large file in /tmp: $fpath (${size_mb}MB)"
        else
            echo "  $fpath  ($fsize B)"
        fi
    done
else
    echo -e "  ${GREEN}لا توجد ملفات مشبوهة في /tmp${NC}"
fi

REPORT+="=== /tmp Files ===
$tmp_files

"

# ─── 6. مقارنة مع اللقطة السابقة ────────────────────────────
echo ""
if [ -f "$SNAPFILE" ]; then
    echo -e "${YELLOW}$(t for4_prev_vs_current)${NC}"
    echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}$(t for4_previous)${NC}"
    cat "$SNAPFILE"
    echo ""
    echo -e "${CYAN}$(t for4_current)${NC}"
    echo "$current"

    # مقارنة بسيطة: مجلدات زاد حجمها كثيراً
    echo ""
    echo -e "${YELLOW}◉ أكبر التغييرات منذ اللقطة السابقة:${NC}"
    # استخرج بيانات المقارنة
    comm_res=$(comm -13 \
        <(sed 's/\t.*//' "$SNAPFILE" | sort) \
        <(echo "$current" | sed 's/\t.*//' | sort) 2>/dev/null | head -10)
    if [ -n "$comm_res" ]; then
        echo "$comm_res" | while IFS= read -r l; do
            echo -e "  ${ORANGE}▲ جديد/أكبر: $l${NC}"
        done
    else
        echo -e "  ${GREEN}لا تغييرات كبيرة مقارنة باللقطة السابقة${NC}"
    fi

    echo ""
    read -rp "$(t c_confirm_update_baseline) [y/N]: " ans
    [ "${ans,,}" = "y" ] && { echo "$current" > "$SNAPFILE"; echo -e "${GREEN}$(t c_updated)${NC}"; }
else
    echo "$current" > "$SNAPFILE"
    echo -e "${GREEN}$(tf for4_baseline_saved "$dir")${NC}"
    echo "$current"
fi

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$REPORT" "disk_usage_snapshot.txt" "$TOOL_TITLE"
