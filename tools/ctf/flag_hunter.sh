#!/bin/bash
# =============================================================
#  RAQIB CTF — Flag Hunter
#  يبحث عن flags بأنماط متعددة في أي ملف أو مجلد
#  يدعم: regex مخصص + أنماط CTF شائعة + البحث في binary
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🏴 Flag Hunter — البحث الآلي عن CTF Flags       ║${NC}"
echo -e "${CYAN}║  يبحث في ملفات نصية + binary + archives          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "  ${YELLOW}1)${NC} بحث في ملف واحد"
echo -e "  ${YELLOW}2)${NC} بحث في مجلد (recursive)"
echo -e "  ${YELLOW}3)${NC} بحث بـ pattern مخصص"
echo -e "  ${YELLOW}4)${NC} فك Base64 وبحث"
echo -e "  ${YELLOW}5)${NC} بحث شامل (كل الأنماط)"
read -rp "  اختر: " mode
echo ""

# ─── أنماط flags شائعة في CTF ───
FLAG_PATTERNS=(
    'flag\{[^}]+\}'
    'FLAG\{[^}]+\}'
    'picoCTF\{[^}]+\}'
    'CTF\{[^}]+\}'
    'ctf\{[^}]+\}'
    'RAQIB\{[^}]+\}'
    'htb\{[^}]+\}'
    'HTB\{[^}]+\}'
    'THM\{[^}]+\}'
    'thm\{[^}]+\}'
    'ictf\{[^}]+\}'
    '[A-Z]{2,6}\{[A-Za-z0-9_\-+/=@!#$%^&*,.? ]+\}'
)

search_for_flags() {
    local target="$1"
    local is_dir="$2"
    local custom_pattern="${3:-}"

    local found_count=0

    if [ -n "$custom_pattern" ]; then
        patterns=("$custom_pattern")
    else
        patterns=("${FLAG_PATTERNS[@]}")
    fi

    echo -e "  🔍 البحث في: $target"
    echo ""

    for pattern in "${patterns[@]}"; do
        if [ "$is_dir" = "1" ]; then
            # بحث في ملفات نصية
            while IFS= read -r match; do
                [ -n "$match" ] || continue
                echo -e "  ${GREEN}🏴 $match${NC}"
                ((found_count++))
            done < <(grep -rl --include="*" -E "$pattern" "$target" 2>/dev/null | \
                     xargs grep -h -o -E "$pattern" 2>/dev/null | sort -u)

            # بحث في ملفات binary
            find "$target" -type f 2>/dev/null | while read -r f; do
                mime=$(file -b --mime-type "$f" 2>/dev/null)
                if [[ "$mime" != text/* ]]; then
                    result=$(strings -- "$f" 2>/dev/null | grep -o -E "$pattern")
                    if [ -n "$result" ]; then
                        echo -e "  ${GREEN}🏴 [binary] $f: $result${NC}"
                        ((found_count++))
                    fi
                fi
            done
        else
            # ملف واحد — فحص نصي
            result=$(grep -o -E "$pattern" "$target" 2>/dev/null | sort -u)
            if [ -n "$result" ]; then
                echo -e "  ${GREEN}🏴 $result${NC}"
                ((found_count++))
            fi
            # فحص binary
            result=$(strings -- "$target" 2>/dev/null | grep -o -E "$pattern" | sort -u)
            if [ -n "$result" ]; then
                echo -e "  ${GREEN}🏴 [strings] $result${NC}"
                ((found_count++))
            fi
        fi
    done

    echo ""
    if [ "$found_count" -eq 0 ]; then
        echo -e "  ${YELLOW}لم يُعثر على flags بالأنماط المعروفة${NC}"
        echo -e "  جرّب وضع 3 (pattern مخصص) إن كنت تعرف صيغة الـ flag"
    else
        echo -e "  ${GREEN}✅ وُجد $found_count flag(s)${NC}"
    fi
}

decode_and_search() {
    local target="$1"
    echo -e "  ${YELLOW}محاولة فك Base64 والبحث...${NC}"
    python3 - "$target" <<'PYEOF'
import sys, base64, re, os

target = sys.argv[1]
FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,8}\{[^}]+\}')
B64_RE  = re.compile(r'[A-Za-z0-9+/]{16,}={0,2}')

def try_decode(s):
    results = []
    # Base64
    try:
        dec = base64.b64decode(s + '==').decode('utf-8', errors='replace')
        if FLAG_RE.search(dec):
            results.append(('base64', dec))
    except: pass
    # URL-encoded base64
    try:
        dec = base64.urlsafe_b64decode(s + '==').decode('utf-8', errors='replace')
        if FLAG_RE.search(dec):
            results.append(('base64url', dec))
    except: pass
    return results

# قراءة الملف
if os.path.isfile(target):
    with open(target, 'rb') as f:
        data = f.read()
    text = data.decode('utf-8', errors='replace')

    # بحث مباشر أولاً
    direct = FLAG_RE.findall(text)
    if direct:
        print(f"  🏴 Flags مباشرة:")
        for f in direct: print(f"    {f}")

    # بحث في base64 strings
    b64_strings = B64_RE.findall(text)
    found_in_b64 = []
    for b64 in b64_strings:
        decoded_results = try_decode(b64)
        for method, decoded in decoded_results:
            flags = FLAG_RE.findall(decoded)
            if flags:
                found_in_b64.extend([(method, b64[:30]+'...', flag) for flag in flags])

    if found_in_b64:
        print(f"\n  🏴 Flags مخفية في Base64:")
        for method, enc, flag in found_in_b64:
            print(f"    [{method}] {enc} → {flag}")

    if not direct and not found_in_b64:
        print("  لم يُعثر على flags في Base64 strings")

        # اعرض أطول base64 strings موجودة
        if b64_strings:
            print(f"\n  أطول Base64 strings ({len(b64_strings)}):")
            for b in sorted(b64_strings, key=len, reverse=True)[:5]:
                try:
                    dec = base64.b64decode(b + '==').decode('utf-8', errors='replace')
                    print(f"    {b[:40]} → {dec[:60]}")
                except:
                    print(f"    {b[:40]}")
else:
    print(f"  المسار غير موجود: {target}")
PYEOF
}

case "$mode" in
    1)
        read -rp "  مسار الملف: " target
        [ ! -f "$target" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }
        search_for_flags "$target" 0
        ;;
    2)
        read -rp "  مسار المجلد: " target
        [ ! -d "$target" ] && { echo -e "${RED}المجلد غير موجود${NC}"; exit 1; }
        search_for_flags "$target" 1
        ;;
    3)
        read -rp "  المسار (ملف/مجلد): " target
        [ ! -e "$target" ] && { echo -e "${RED}المسار غير موجود${NC}"; exit 1; }
        read -rp "  Pattern (regex): " custom_pat
        [ -z "$custom_pat" ] && { echo -e "${RED}لم تدخل pattern${NC}"; exit 1; }
        is_dir=0; [ -d "$target" ] && is_dir=1
        search_for_flags "$target" "$is_dir" "$custom_pat"
        ;;
    4)
        read -rp "  مسار الملف: " target
        [ ! -f "$target" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }
        decode_and_search "$target"
        ;;
    5)
        read -rp "  المسار (ملف/مجلد): " target
        [ ! -e "$target" ] && { echo -e "${RED}المسار غير موجود${NC}"; exit 1; }
        is_dir=0; [ -d "$target" ] && is_dir=1
        echo -e "${BOLD}══ بحث شامل ══${NC}"
        search_for_flags "$target" "$is_dir"
        echo ""
        echo -e "${BOLD}══ Base64 Decode ══${NC}"
        if [ "$is_dir" = "0" ]; then
            decode_and_search "$target"
        else
            find "$target" -type f -size -10M 2>/dev/null | while read -r f; do
                decode_and_search "$f"
            done
        fi
        ;;
    *)
        echo -e "${RED}اختيار غير صحيح${NC}"
        ;;
esac
