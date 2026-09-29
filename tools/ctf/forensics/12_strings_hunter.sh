#!/bin/bash
# =============================================================
#  RAQIB CTF — Strings Hunter (Flag Finder)
#  أداة #12: بحث ذكي عن flags وstrings مثيرة للاهتمام
#  اللغة: Bash محض — strings + grep بأنماط CTF
#         shell مثالي هنا — grep أسرع من Python للبحث
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🔎 Strings Hunter — Flag Finder                  ║${NC}"
echo -e "${CYAN}║  بحث ذكي عن flags وأسرار مخفية في الملفات      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "  ${YELLOW}1)${NC} فحص ملف واحد"
echo -e "  ${YELLOW}2)${NC} فحص مجلد كامل (recursive)"
echo -e "  ${YELLOW}3)${NC} Flag Hunter mode — بحث بأنماط CTF فقط"
read -rp "  اختر: " hunt_mode

case $hunt_mode in
    1|3)
        read -rp "  مسار الملف: " target
        [ ! -f "$target" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }
        ;;
    2)
        read -rp "  مسار المجلد: " target
        [ ! -d "$target" ] && { echo -e "${RED}المجلد غير موجود${NC}"; exit 1; }
        ;;
    *)
        echo -e "${RED}اختيار غير صحيح${NC}"; exit 1 ;;
esac

echo ""

# ─── أنماط CTF Flags ─────────────────────────────────────────
FLAG_PATTERNS=(
    'picoCTF\{[^}]{1,200}\}'
    '[Ff][Ll][Aa][Gg]\{[^}]{1,200}\}'
    'CTF\{[^}]{1,200}\}'
    'flag\{[^}]{1,200}\}'
    'FLAG\{[^}]{1,200}\}'
    'HTB\{[^}]{1,200}\}'
    'THM\{[^}]{1,200}\}'
    'DUCTF\{[^}]{1,200}\}'
    'UACTF\{[^}]{1,200}\}'
    'ACSC\{[^}]{1,200}\}'
    '[A-Z0-9_]{2,10}\{[A-Za-z0-9_!@#$%^&*(){}\-+=/\\.,?~` ]{4,200}\}'
)

# ─── أنماط مثيرة للاهتمام ────────────────────────────────────
INTEREST_PATTERNS=(
    'password[=: ][^\s]{4,}'
    'passwd[=: ][^\s]{4,}'
    'secret[=: ][^\s]{4,}'
    'token[=: ][^\s]{8,}'
    'api.?key[=: ][^\s]{8,}'
    'private.?key'
    'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY'
    'ssh-rsa AAAA'
    'eyJ[A-Za-z0-9_-]{10,}'
    'https?://[^\s]{10,}'
    '/etc/passwd'
    '/etc/shadow'
    'root:x:0:0'
    'admin'
    'user[=: ][^\s]{3,}'
)

found_any=false

search_in_file() {
    local file="$1"
    local file_found=false

    # ─── Flag patterns (أعلى أولوية) ─────────────────────────
    for pat in "${FLAG_PATTERNS[@]}"; do
        results="$(grep -oE "$pat" -- "$file" 2>/dev/null)"
        if [ -n "$results" ]; then
            if ! $file_found; then
                echo -e "\n  ${BOLD}${GREEN}📄 $file${NC}"
                file_found=true
                found_any=true
            fi
            echo -e "  ${GREEN}  🏴 FLAG FOUND:${NC}"
            echo "$results" | while IFS= read -r line; do
                echo -e "  ${BOLD}${GREEN}     $line${NC}"
            done
        fi
    done

    # ─── Interesting strings ──────────────────────────────────
    if [ "$hunt_mode" != "3" ]; then
        for pat in "${INTEREST_PATTERNS[@]}"; do
            results="$(grep -oiE "$pat" -- "$file" 2>/dev/null | head -5)"
            if [ -n "$results" ]; then
                if ! $file_found; then
                    echo -e "\n  ${BOLD}${YELLOW}📄 $file${NC}"
                    file_found=true
                    found_any=true
                fi
                echo -e "  ${YELLOW}  💡 مثير للاهتمام [$pat]:${NC}"
                echo "$results" | while IFS= read -r line; do
                    echo "       $line"
                done
            fi
        done
    fi

    # ─── Printable strings (from binary) ─────────────────────
    if [ "$hunt_mode" != "3" ] && command -v strings >/dev/null 2>&1; then
        # هل الملف binary؟
        if file --brief -- "$file" 2>/dev/null | grep -qiE 'ELF|binary|data'; then
            echo -e "\n  ${BOLD}${CYAN}📄 $file (binary)${NC}"
            file_found=true
            echo -e "  ${CYAN}  📋 أطول strings مقروءة:${NC}"
            strings -n 8 -- "$file" 2>/dev/null | \
                awk 'length > 10' | \
                grep -vE '^(GCC|GLIBC|_ITM|__gmon|LIBCXX)' | \
                head -20 | \
                while IFS= read -r s; do echo "     $s"; done
        fi
    fi
}

# ─── تنفيذ البحث ─────────────────────────────────────────────
echo -e "  ${GREY}جاري البحث...${NC}"

if [ "$hunt_mode" = "2" ]; then
    # مجلد كامل
    while IFS= read -r -d '' f; do
        search_in_file "$f"
    done < <(find "$target" -type f -not -path '*/.*' -print0 2>/dev/null)
else
    search_in_file "$target"
fi

echo ""
echo "  ══════════════════════════════════════"
if $found_any; then
    echo -e "  ${GREEN}✅ اكتمل البحث — تم العثور على نتائج${NC}"
else
    echo -e "  ${YELLOW}⚠️  لم يُعثر على patterns معروفة${NC}"
    echo -e "  ${GREY}  جرب:${NC}"
    echo -e "  ${GREY}  • strings \"$target\" | less${NC}"
    echo -e "  ${GREY}  • binwalk \"$target\"${NC}"
    echo -e "  ${GREY}  • فك ضغط الملف أولاً${NC}"
fi
echo ""

pause
