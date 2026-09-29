#!/bin/bash
# =====================================================
#  Bash History Reviewer — محلل سجل أوامر الباش
#  يبحث في سجلات كل المستخدمين عن:
#   • أوامر تنزيل ملفات (wget/curl)
#   • تشغيل كود مباشرة (python -c / perl -e)
#   • حذف سجلات (history -c)
#   • اتصالات reverse shell (/dev/tcp)
#   • رفع صلاحيات (sudo su / chmod 777)
#   • أدوات اختراق شائعة (nc/ncat/socat/nmap)
#   • تعديل ملفات النظام الحساسة
#   • تشفير/ضغط مشبوه (base64/xxd/tar+wget)
# =====================================================
finding_reset

TOOL_TITLE="$(t for2_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ─── تصنيفات الأنماط المشبوهة مع مستوى الخطورة ───────────
declare -A PATTERN_SEVERITY
declare -A PATTERN_DESC

# CRITICAL — reverse shells ووصول خلفي
PATTERN_SEVERITY["CRIT_REVSHELL"]="critical"
PATTERN_DESC["CRIT_REVSHELL"]="Reverse shell / backdoor command"
PATTERNS_CRITICAL='/dev/tcp/|/dev/udp/|bash -i|bash -c.*>.*&|sh -i|nc -e|ncat -e|socat.*EXEC|python.*socket.*connect|perl.*socket|ruby.*socket|php.*fsockopen|mkfifo.*nc|openssl.*s_client.*exec'

# HIGH — تنزيل وتنفيذ
PATTERN_SEVERITY["HIGH_EXEC"]="high"
PATTERN_DESC["HIGH_EXEC"]="Download-and-execute / code execution"
PATTERNS_HIGH='wget.*-O.*\|.*sh|curl.*\|.*sh|curl.*\|.*bash|wget.*\|.*bash|python[23]?\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|node\s+-e|lua\s+-e|expect\s+-c'

# HIGH — تعديل صلاحيات / حذف مشبوه
PATTERN_SEVERITY["HIGH_PERMS"]="high"
PATTERN_DESC["HIGH_PERMS"]="Dangerous permission change or deletion"
PATTERNS_HIGH2='chmod\s+(777|4777|7777|0777|a\+s|u\+s)|chown\s+root|rm\s+-rf\s+/[a-z]|truncate\s.*--size\s+0\s+/var/log'

# HIGH — أدوات اختراق
PATTERN_SEVERITY["HIGH_TOOLS"]="high"
PATTERN_DESC["HIGH_TOOLS"]="Penetration testing / exploitation tools"
PATTERNS_HIGH3='nmap\s|masscan\s|hydra\s|john\s+.*--|hashcat\s|sqlmap\s|msfconsole|msfvenom|exploit\s|metasploit|aircrack|wifite|reaver\s'

# MEDIUM — تغطية آثار
PATTERN_SEVERITY["MED_COVER"]="medium"
PATTERN_DESC["MED_COVER"]="Log/history tampering / evidence destruction"
PATTERNS_MEDIUM='history\s+-c|history\s+-w\s*/dev/null|unset\s+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|shred\s+-u.*\.bash_history|rm\s+-f.*\.bash_history|cat\s+/dev/null\s*>\s*.*log'

# MEDIUM — استطلاع النظام
PATTERN_SEVERITY["MED_RECON"]="medium"
PATTERN_DESC["MED_RECON"]="System reconnaissance / enumeration"
PATTERNS_MEDIUM2='cat\s+/etc/passwd|cat\s+/etc/shadow|cat\s+/etc/sudoers|ls\s+-la\s+/root|find\s+/.*-perm.*[24]000|getent\s+passwd|id\s*;|uname\s+-a\s*;|whoami\s*;'

# MEDIUM — تشفير مشبوه
PATTERN_SEVERITY["MED_ENCODE"]="medium"
PATTERN_DESC["MED_ENCODE"]="Suspicious encoding/obfuscation"
PATTERNS_MEDIUM3='base64\s+-d|xxd\s+-r|openssl\s+enc.*-d|python.*b64decode|echo\s+[A-Za-z0-9+/=]\{40,\}\s*\|.*base64\s+-d'

# LOW — أدوات شبكة عادية
PATTERN_SEVERITY["LOW_NET"]="low"
PATTERN_DESC["LOW_NET"]="Network tool usage"
PATTERNS_LOW='netcat\s|nc\s+-[lzvp]|nping\s|hping\s|tcpdump\s|tshark\s|wireshark\s'

declare -A PATTERNS_MAP
PATTERNS_MAP["CRIT_REVSHELL"]="$PATTERNS_CRITICAL"
PATTERNS_MAP["HIGH_EXEC"]="$PATTERNS_HIGH"
PATTERNS_MAP["HIGH_PERMS"]="$PATTERNS_HIGH2"
PATTERNS_MAP["HIGH_TOOLS"]="$PATTERNS_HIGH3"
PATTERNS_MAP["MED_COVER"]="$PATTERNS_MEDIUM"
PATTERNS_MAP["MED_RECON"]="$PATTERNS_MEDIUM2"
PATTERNS_MAP["MED_ENCODE"]="$PATTERNS_MEDIUM3"
PATTERNS_MAP["LOW_NET"]="$PATTERNS_LOW"

BADGE_CRITICAL="${CRIMSON}[CRITICAL]${NC}"
BADGE_HIGH="${ORANGE}[HIGH]   ${NC}"
BADGE_MEDIUM="${YELLOW}[MEDIUM] ${NC}"
BADGE_LOW="${GREEN}[LOW]    ${NC}"

get_badge() {
    case "$1" in
        critical) echo "$BADGE_CRITICAL" ;;
        high)     echo "$BADGE_HIGH" ;;
        medium)   echo "$BADGE_MEDIUM" ;;
        *)        echo "$BADGE_LOW" ;;
    esac
}

REPORT_LINES=""
TOTAL_FINDINGS=0
found_any=0

# ─── قائمة ملفات السجل للفحص ──────────────────────────────
HISTFILES=()

# جمع ملفات .bash_history و .zsh_history و .sh_history
while IFS= read -r -d '' hf; do
    HISTFILES+=("$hf")
done < <(find /root /home -maxdepth 3 \( \
    -name ".bash_history" -o \
    -name ".zsh_history" -o \
    -name ".sh_history" -o \
    -name ".history" \
    \) -type f -print0 2>/dev/null)

# أضف HISTFILE الحالي لو مو موجود
[ -n "$HISTFILE" ] && [ -f "$HISTFILE" ] && \
    [[ ! " ${HISTFILES[*]} " =~ " $HISTFILE " ]] && \
    HISTFILES+=("$HISTFILE")

if [ ${#HISTFILES[@]} -eq 0 ]; then
    echo -e "${YELLOW}⚠️  لم يُعثر على ملفات سجل تاريخ الأوامر${NC}"
fi

# ─── فحص كل ملف ────────────────────────────────────────────
for histfile in "${HISTFILES[@]}"; do
    [ -f "$histfile" ] || continue
    [ -r "$histfile" ] || { echo -e "${GREY}  [لا توجد صلاحية قراءة] $histfile${NC}"; continue; }

    line_count=$(wc -l < "$histfile" 2>/dev/null || echo 0)
    file_size=$(raqib_stat_size "$histfile" 2>/dev/null || echo "?")

    echo -e "${BOLD}${CYAN}━━━ $histfile  (${line_count} سطر، ${file_size} byte) ━━━${NC}"

    file_found=0

    for pkey in "CRIT_REVSHELL" "HIGH_EXEC" "HIGH_PERMS" "HIGH_TOOLS" "MED_COVER" "MED_RECON" "MED_ENCODE" "LOW_NET"; do
        pattern="${PATTERNS_MAP[$pkey]}"
        sev="${PATTERN_SEVERITY[$pkey]}"
        desc="${PATTERN_DESC[$pkey]}"
        badge=$(get_badge "$sev")

        if raqib_pcre_ok; then
            matches=$(grep -inP "$pattern" "$histfile" 2>/dev/null)
        else
            matches=$(grep -inE "$pattern" "$histfile" 2>/dev/null)
        fi

        if [ -n "$matches" ]; then
            found_any=1
            file_found=1
            match_count=$(echo "$matches" | wc -l)
            echo ""
            echo -e "  ${badge} ${BOLD}${desc}${NC}  (${match_count} تطابق)"
            echo -e "${GREY}  ──────────────────────────────────────────${NC}"

            echo "$matches" | head -15 | while IFS= read -r line; do
                echo -e "  ${RED}▸${NC} $line"
            done

            if [ "$match_count" -gt 15 ]; then
                echo -e "  ${GREY}  ... و$((match_count - 15)) تطابق إضافي${NC}"
            fi

            TOTAL_FINDINGS=$((TOTAL_FINDINGS + match_count))
            finding_add "$sev" "$desc in $histfile"

            REPORT_LINES+="=== [$sev] $desc — $histfile ===
$matches

"
        fi
    done

    if [ "$file_found" -eq 0 ]; then
        echo -e "  ${GREEN}✅ لا أنماط مشبوهة في هذا الملف${NC}"
    fi
    echo ""
done

# ─── خلاصة نهائية ─────────────────────────────────────────
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}$(t for2_scanned_all)${NC}  (${#HISTFILES[@]} ملف)"

if [ "$found_any" -eq 1 ]; then
    echo -e "${RED}⚠️  إجمالي التطابقات المشبوهة: ${TOTAL_FINDINGS}${NC}"
fi

echo ""
print_executive_summary "$TOOL_TITLE"

[ "$found_any" -eq 1 ] && save_report "$REPORT_LINES" "bash_history_review.txt" "$TOOL_TITLE"
