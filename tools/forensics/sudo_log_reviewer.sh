#!/bin/bash
# =====================================================
#  Sudo Log Reviewer — مراجع سجل أوامر sudo
#  يحلل: الأوامر المنفّذة بـ sudo، المستخدمين الأكثر
#  استخداماً، محاولات sudo الفاشلة، أوامر خطيرة
#  (rm -rf / chmod / passwd / visudo / useradd)،
#  استخدام sudo خارج أوقات العمل، تسلسل أوامر مشبوه
# =====================================================
finding_reset

TOOL_TITLE="$(t for5_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

LOGFILE=$(find_auth_log) || exit 1
echo -e "${GREY}  المصدر: $LOGFILE${NC}"
echo ""

REPORT=""

# ─── 1. آخر 50 أمر sudo ──────────────────────────────────────
echo -e "${YELLOW}$(t for5_last30) (آخر 50 أمر)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
sudo_cmds=$(grep "sudo:" "$LOGFILE" 2>/dev/null | grep "COMMAND=" | tail -50)
if [ -n "$sudo_cmds" ]; then
    # أوامر خطيرة
    DANGEROUS_PATTERNS='COMMAND=.*\brm\s+-rf|COMMAND=.*\bchmod\s+777\|COMMAND=.*\bpasswd\s|COMMAND=.*\bvisudo\b|COMMAND=.*\buseradd\b|COMMAND=.*\buserdel\b|COMMAND=.*\bchpasswd\b|COMMAND=.*\biptables\s+-F|COMMAND=.*\bnc\s|COMMAND=.*\bcurl.*\|.*sh|COMMAND=.*\bwget.*\|.*sh'

    echo "$sudo_cmds" | while IFS= read -r line; do
        if echo "$line" | grep -qiE "$DANGEROUS_PATTERNS"; then
            echo -e "  ${RED}🔴 [DANGEROUS] $line${NC}"
            finding_add high "Dangerous sudo command: $line"
        else
            echo "  $line"
        fi
    done
else
    echo -e "  ${GREEN}لا توجد أوامر sudo مسجّلة${NC}"
fi

REPORT+="=== Last 50 sudo commands ===
$sudo_cmds

"

# ─── 2. إحصاء الاستخدام لكل مستخدم ─────────────────────────
echo ""
echo -e "${YELLOW}$(t for5_usage_per_user)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
user_stats=$(grep "sudo:" "$LOGFILE" 2>/dev/null | grep "COMMAND=" | \
    grep -oE 'sudo:\s+[A-Za-z0-9_.-]+' | awk '{print $2}' | \
    sort | uniq -c | sort -rn | head -15)
if [ -n "$user_stats" ]; then
    echo "$user_stats" | while IFS= read -r stat; do
        count=$(echo "$stat" | awk '{print $1}')
        user=$(echo "$stat" | awk '{print $2}')
        if [ "$count" -ge 100 ]; then
            echo -e "  ${ORANGE}  ⚡ $count sudo commands — $user${NC}"
            finding_add medium "High sudo usage by $user: $count commands"
        else
            echo "     $count  $user"
        fi
    done
else
    echo -e "  ${GREY}لا توجد بيانات${NC}"
fi

REPORT+="=== Sudo Usage Per User ===
$user_stats

"

# ─── 3. محاولات sudo الفاشلة ─────────────────────────────────
echo ""
echo -e "${RED}$(t for5_failed_attempts)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
failed_sudo=$(grep -iE "sudo:.*authentication failure|sudo:.*not in the sudoers|sudo:.*incorrect password" \
    "$LOGFILE" 2>/dev/null | tail -30)
if [ -n "$failed_sudo" ]; then
    fail_count=$(echo "$failed_sudo" | wc -l)
    echo -e "  ${RED}$fail_count محاولة فاشلة:${NC}"
    echo "$failed_sudo" | while IFS= read -r line; do
        echo -e "  ${RED}▸ $line${NC}"
    done
    finding_add high "Failed sudo attempts: $fail_count occurrences"
else
    echo -e "  ${GREEN}لا توجد محاولات sudo فاشلة${NC}"
fi

REPORT+="=== Failed Sudo Attempts ===
${failed_sudo:-None}

"

# ─── 4. أوامر sudo خارج أوقات العمل ────────────────────────
echo ""
echo -e "${YELLOW}◉ أوامر sudo في أوقات غير عادية (23:00 - 06:00)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
offhours=$(grep "sudo:" "$LOGFILE" 2>/dev/null | grep "COMMAND=" | \
    grep -E '\s(23|00|01|02|03|04|05|06):' | tail -20)
if [ -n "$offhours" ]; then
    echo -e "  ${ORANGE}⚠️  أوامر sudo ليلية مشبوهة:${NC}"
    echo "$offhours" | while IFS= read -r line; do
        echo -e "  ${ORANGE}🌙 $line${NC}"
    done
    finding_add medium "Sudo commands during off-hours: $(echo "$offhours" | wc -l) occurrences"
else
    echo -e "  ${GREEN}لا توجد أوامر sudo ليلية${NC}"
fi

REPORT+="=== Off-hours Sudo ===
${offhours:-None}

"

# ─── 5. أوامر sudo خطيرة بالتفصيل ──────────────────────────
echo ""
echo -e "${YELLOW}◉ أوامر sudo الخطيرة (الكل)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

declare -A DANGEROUS_CMDS
DANGEROUS_CMDS["rm -rf"]="Dangerous deletion"
DANGEROUS_CMDS["chmod 777\|chmod 0777\|chmod a+s"]="Dangerous permissions"
DANGEROUS_CMDS["passwd\b"]="Password change"
DANGEROUS_CMDS["visudo\b"]="Sudoers modification"
DANGEROUS_CMDS["useradd\|adduser"]="User creation"
DANGEROUS_CMDS["userdel\|deluser"]="User deletion"
DANGEROUS_CMDS["iptables -F\|ufw disable"]="Firewall disabled"
DANGEROUS_CMDS["dd if=\|dd of="]="Disk write (dd)"
DANGEROUS_CMDS["mkfs\|fdisk\|parted"]="Disk formatting"

all_dangerous_found=""
for pattern in "${!DANGEROUS_CMDS[@]}"; do
    desc="${DANGEROUS_CMDS[$pattern]}"
    matches=$(grep "sudo:" "$LOGFILE" 2>/dev/null | grep "COMMAND=" | \
        grep -iE "$pattern" | tail -10)
    if [ -n "$matches" ]; then
        echo -e "  ${RED}[${desc}] ← $pattern${NC}"
        echo "$matches" | head -5 | while IFS= read -r m; do
            echo -e "  ${RED}  ▸ $m${NC}"
        done
        finding_add high "Dangerous sudo: $desc"
        all_dangerous_found+="=== $desc ===
$matches

"
    fi
done

[ -z "$all_dangerous_found" ] && echo -e "  ${GREEN}لا توجد أوامر sudo خطيرة${NC}"

REPORT+="=== Dangerous Sudo Commands ===
$all_dangerous_found
"

# ─── 6. تصدير تقرير ─────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

if [ -n "$sudo_cmds" ] || [ -n "$failed_sudo" ]; then
    save_report "$(tf for5_report_title_date "$(date)")

Source: $LOGFILE

$REPORT" "sudo_log_review.txt" "$TOOL_TITLE"
fi
