#!/bin/bash
# =============================================================
#  RAQIB CTF — Timeline Builder
#  أداة #13: بناء timeline من artifacts متعددة
#  يجمع: timestamps ملفات، logs، EXIF، pcap، strings
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ⏱️  Timeline Builder — Forensic Timeline        ║${NC}"
echo -e "${CYAN}║  بناء timeline زمني من artifacts متعددة          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  مسار المجلد أو الملف للتحليل: " target_path
[ ! -e "$target_path" ] && { echo -e "${RED}المسار غير موجود${NC}"; exit 1; }

echo ""
echo -e "  ${YELLOW}1)${NC} Timeline كاملة للمجلد (مع subdirs)"
echo -e "  ${YELLOW}2)${NC} Timeline من ملف واحد فقط"
echo -e "  ${YELLOW}3)${NC} Timeline من ملف log"
echo -e "  ${YELLOW}4)${NC} مقارنة بين ملفين (diff timestamps)"
read -rp "  اختر: " mode

echo ""

build_file_timeline() {
    local path="$1"
    local is_dir="$2"
    echo -e "${BOLD}══ File System Timeline ══${NC}"

    if [ "$is_dir" = "1" ]; then
        echo -e "  📁 المجلد: $path"
        echo ""
        # اجمع كل الملفات مع timestamps وافرزها زمنياً
        if command -v stat >/dev/null 2>&1; then
            (
                find "$path" -type f 2>/dev/null | while read -r f; do
                    mtime=$(stat -c '%Y|%y' -- "$f" 2>/dev/null || stat -f '%m|%Sm' -- "$f" 2>/dev/null)
                    echo "${mtime}|${f}"
                done
            ) | sort -t'|' -k1 -n | while IFS='|' read -r epoch human rest; do
                printf "  ${CYAN}%s${NC}  %s\n" "$human" "$rest"
            done | head -50
        else
            find "$path" -type f -newer /proc 2>/dev/null -ls | sort -k8,9 | head -30 || \
            ls -ltrR "$path" 2>/dev/null | head -50
        fi
    else
        echo -e "  📄 الملف: $path"
        stat -- "$path" 2>/dev/null || ls -la -- "$path"
    fi
}

extract_log_timeline() {
    local log_file="$1"
    echo -e "${BOLD}══ Log Timeline ══${NC}"
    python3 - "$log_file" <<'PYEOF'
import sys, re, collections

log_file = sys.argv[1]
events = []

# أنماط تاريخ شائعة في logs
DATE_PATTERNS = [
    (r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', '%Y-%m-%dT%H:%M:%S'),
    (r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
    (r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S'),
    (r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
    (r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})', '%m/%d/%Y %H:%M:%S'),
]

try:
    with open(log_file, 'r', errors='replace') as f:
        for line in f:
            line = line.rstrip()
            for pattern, fmt in DATE_PATTERNS:
                m = re.search(pattern, line)
                if m:
                    events.append((m.group(1), line[:120]))
                    break

    if not events:
        print("  لم يُعثر على timestamps بصيغة معروفة")
        # عرض أول 20 سطر
        with open(log_file, 'r', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= 20: break
                print(f"  {line.rstrip()}")
    else:
        print(f"  📊 إجمالي الأحداث: {len(events)}")
        print(f"\n  أول 30 حدث:")
        for ts, line in events[:30]:
            print(f"  [{ts}]  {line[:80]}")

        # بحث عن أنماط مشبوهة
        suspicious = [(ts, l) for ts, l in events if
                      re.search(r'fail|error|denied|attack|inject|malware|suspicious|unauthorized', l, re.I)]
        if suspicious:
            print(f"\n  ⚠️  أحداث مشبوهة ({len(suspicious)}):")
            for ts, l in suspicious[:10]:
                print(f"  [{ts}]  {l[:80]}")

        # flags
        flags = [l for _, l in events if re.search(r'(?:flag|FLAG|CTF|ctf)\{[^}]+\}', l)]
        if flags:
            print(f"\n  🏴 FLAGS:")
            for f in flags: print(f"  {f}")

except Exception as e:
    print(f"  خطأ: {e}")
PYEOF
}

case "$mode" in
    1) build_file_timeline "$target_path" 1 ;;
    2) build_file_timeline "$target_path" 0 ;;
    3) extract_log_timeline "$target_path" ;;
    4)
        read -rp "  مسار الملف الثاني: " target_path2
        [ ! -f "$target_path2" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }
        echo -e "${BOLD}══ مقارنة Timestamps ══${NC}"
        echo ""
        echo -e "  الملف الأول: $(ls -la "$target_path")"
        echo -e "  الملف الثاني: $(ls -la "$target_path2")"
        echo ""
        if [ "$target_path" -nt "$target_path2" ]; then
            echo -e "  ${CYAN}$target_path${NC} أحدث من $target_path2"
        elif [ "$target_path2" -nt "$target_path" ]; then
            echo -e "  ${CYAN}$target_path2${NC} أحدث من $target_path"
        else
            echo -e "  الملفان بنفس وقت التعديل"
        fi
        ;;
    *) build_file_timeline "$target_path" "$([ -d "$target_path" ] && echo 1 || echo 0)" ;;
esac

echo ""
echo -e "${BOLD}══ Metadata التحليل الإضافي ══${NC}"
if [ -f "$target_path" ]; then
    echo -e "  ${CYAN}EXIF Dates (إن وجدت):${NC}"
    if command -v exiftool >/dev/null 2>&1; then
        exiftool "$target_path" 2>/dev/null | grep -i "date\|time\|created\|modified" | head -10
    else
        python3 - "$target_path" <<'PYEOF'
import sys, re
with open(sys.argv[1], 'rb') as f:
    data = f.read()
# بحث عن تواريخ بصيغ معروفة في البيانات الثنائية
strings = re.findall(rb'[\x20-\x7e]{8,}', data)
date_strings = [s.decode('ascii') for s in strings
                if re.search(rb'\d{4}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}', s)]
if date_strings:
    for d in date_strings[:10]: print(f"  {d}")
else:
    print("  لا توجد تواريخ مضمّنة")
PYEOF
    fi
fi

echo ""
# حفظ التقرير
read -rp "  هل تريد حفظ التقرير؟ (y/n): " save_ans
if [ "$save_ans" = "y" ]; then
    out_file="/tmp/raqib_timeline_$(date +%Y%m%d_%H%M%S).txt"
    {
        echo "RAQIB CTF Timeline Report"
        echo "Target: $target_path"
        echo "Date: $(date)"
        echo "========================="
        if [ -d "$target_path" ]; then
            find "$target_path" -type f 2>/dev/null | xargs ls -la 2>/dev/null | sort -k6,7
        else
            stat -- "$target_path" 2>/dev/null
        fi
    } > "$out_file"
    echo -e "  ${GREEN}✅ حُفظ: $out_file${NC}"
fi
