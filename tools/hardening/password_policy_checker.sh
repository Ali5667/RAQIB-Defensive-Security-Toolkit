#!/bin/bash
# =====================================================
#  Password Policy Checker — مدقق سياسة كلمات المرور
#  يفحص: login.defs، PAM configuration، /etc/shadow،
#  حسابات بدون كلمة سر، حسابات قديمة، حسابات مقفلة،
#  تاريخ انتهاء كلمات المرور، strength policy
# =====================================================
finding_reset

TOOL_TITLE="$(t har4_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

# ─── 1. /etc/login.defs ───────────────────────────────────────
FILE="/etc/login.defs"
echo -e "${BOLD}${YELLOW}◉ إعدادات $(t har4_from_file "$FILE")${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

check_defs() {
    local key="$1" recommended="$2" op="${3:-eq}" sev="${4:-medium}" desc="$5"
    local val
    val=$(grep -E "^${key}\s+" "$FILE" 2>/dev/null | awk '{print $2}')
    local not_specified="$(t har4_not_specified)"

    if [ -f "$FILE" ]; then
        if [ -z "$val" ]; then
            echo -e "  ${YELLOW}[?] $key = $not_specified  (recommended: $recommended)  — $desc${NC}"
            finding_add low "$key not set in login.defs"
        else
            local ok=0
            case "$op" in
                le) [[ "$val" =~ ^[0-9]+$ && "$recommended" =~ ^[0-9]+$ ]] && \
                     [ "$val" -le "$recommended" ] && ok=1 ;;
                ge) [[ "$val" =~ ^[0-9]+$ && "$recommended" =~ ^[0-9]+$ ]] && \
                     [ "$val" -ge "$recommended" ] && ok=1 ;;
                eq) [ "$val" = "$recommended" ] && ok=1 ;;
            esac
            if [ "$ok" -eq 1 ]; then
                echo -e "  ${GREEN}[✓] $key = $val${NC}  — $desc"
            else
                echo -e "  ${ORANGE}[!] $key = $val  (recommended: ${op}${recommended})  — $desc${NC}"
                finding_add "$sev" "login.defs: $key=$val (recommended: $recommended)"
            fi
        fi
        REPORT+="  $key = ${val:-$not_specified}\n"
    fi
}

if [ -f "$FILE" ]; then
    check_defs "PASS_MAX_DAYS"  "90"  "le" "medium" "أقصى عمر كلمة المرور (يوم)"
    check_defs "PASS_MIN_DAYS"  "1"   "ge" "low"    "أقل مدة قبل تغيير كلمة المرور"
    check_defs "PASS_MIN_LEN"   "12"  "ge" "medium" "أقل طول لكلمة المرور"
    check_defs "PASS_WARN_AGE"  "14"  "ge" "low"    "تحذير قبل انتهاء كلمة المرور (يوم)"
    check_defs "UID_MIN"        "1000" "eq" "low"   "أقل UID للمستخدمين العاديين"
    check_defs "UMASK"          "027"  "eq" "medium" "umask الافتراضي (027 أو 022)"
    check_defs "ENCRYPT_METHOD" "SHA512" "eq" "high" "خوارزمية تشفير كلمات المرور"
else
    echo -e "  ${RED}$(tf har4_file_missing "$FILE")${NC}"
    finding_add medium "login.defs missing"
fi

# ─── 2. PAM Configuration ────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ إعدادات PAM (سياسة جودة كلمات المرور)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

PAM_FILE=""
for pf in /etc/pam.d/common-password /etc/pam.d/system-auth \
          /etc/pam.d/password-auth /etc/security/pwquality.conf; do
    [ -f "$pf" ] && PAM_FILE="$pf" && break
done

if [ -n "$PAM_FILE" ]; then
    echo -e "  ${GREY}الملف: $PAM_FILE${NC}"

    # pam_pwquality / pam_cracklib
    pam_quality=$(grep -iE "pam_pwquality|pam_cracklib" "$PAM_FILE" 2>/dev/null)
    if [ -n "$pam_quality" ]; then
        echo -e "  ${GREEN}[✓] تم العثور على policy جودة كلمة المرور:${NC}"
        echo "    $pam_quality"

        # استخرج معاملات الجودة
        for param in "minlen" "minclass" "ucredit" "lcredit" "dcredit" "ocredit" "retry"; do
            val=$(echo "$pam_quality" | grep -oE "${param}=[0-9-]+" | head -1)
            [ -n "$val" ] && echo -e "    ${CYAN}$val${NC}"
        done
    else
        echo -e "  ${RED}[✗] لا توجد policy لجودة كلمة المرور (pam_pwquality/pam_cracklib)${NC}"
        finding_add high "No password quality policy (pam_pwquality/pam_cracklib) in PAM"
    fi

    # pam_faillock / pam_tally2 (قفل الحساب)
    faillock=$(grep -iE "pam_faillock|pam_tally2" "$PAM_FILE" 2>/dev/null)
    if [ -n "$faillock" ]; then
        echo -e "  ${GREEN}[✓] قفل الحساب عند المحاولات الفاشلة مُفعّل${NC}"
    else
        echo -e "  ${ORANGE}[!] لا يوجد قفل حساب (pam_faillock) — يسمح بـ brute force${NC}"
        finding_add medium "No account lockout policy (pam_faillock) configured"
    fi

    # pam_pwhistory
    history=$(grep -i "pam_pwhistory" "$PAM_FILE" 2>/dev/null)
    if [ -n "$history" ]; then
        echo -e "  ${GREEN}[✓] تاريخ كلمات المرور محفوظ (منع إعادة الاستخدام)${NC}"
    else
        echo -e "  ${YELLOW}[?] pam_pwhistory غير مُفعّل — كلمة المرور القديمة يمكن إعادة استخدامها${NC}"
    fi
else
    echo -e "  ${YELLOW}$(t har4_pam_not_found)${NC}"
    finding_add medium "PAM configuration not found"
fi

REPORT+="PAM: ${PAM_FILE:-not found}\n"

# ─── 3. حسابات بدون كلمة سر ──────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t har4_no_pw_accounts)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if [ -r /etc/shadow ]; then
    no_pw=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") && $3>=1000 {print $1, "— no/empty password"}' \
        /etc/shadow 2>/dev/null)
    if [ -n "$no_pw" ]; then
        echo -e "  ${RED}⚠️  حسابات بدون كلمة سر:${NC}"
        while IFS= read -r line; do
            echo -e "  ${RED}  🔴 $line${NC}"
            finding_add critical "Account without password: $line"
        done <<< "$no_pw"
    else
        echo -e "  ${GREEN}جميع الحسابات لديها كلمة سر${NC}"
    fi

    # حسابات بكلمة سر منتهية الصلاحية
    echo ""
    echo -e "${YELLOW}  ◉ كلمات مرور منتهية الصلاحية:${NC}"
    expired=$(awk -F: '{
        if ($3 == "" || $3 == 0) next
        days_since = int(systime() / 86400)
        if ($5 != "" && $5 != 0) {
            max_days = int($5)
            last_change = int($3)
            if (days_since - last_change > max_days) {
                print $1, "— expired", days_since - last_change - max_days, "days ago"
            }
        }
    }' /etc/shadow 2>/dev/null | head -20)

    if [ -n "$expired" ]; then
        echo -e "  ${ORANGE}كلمات مرور منتهية:${NC}"
        while IFS= read -r el; do
            echo -e "  ${ORANGE}  ⚠️  $el${NC}"
            finding_add medium "Expired password: $el"
        done <<< "$expired"
    else
        echo -e "  ${GREEN}لا توجد كلمات مرور منتهية الصلاحية${NC}"
    fi

    # حسابات مقفلة
    echo ""
    echo -e "${YELLOW}  ◉ الحسابات المقفلة (!) — للمراجعة:${NC}"
    locked=$(awk -F: '$2 ~ /^!/ && $1 != "root" {print $1}' /etc/shadow 2>/dev/null | head -10)
    if [ -n "$locked" ]; then
        echo "$locked" | while IFS= read -r lu; do
            echo -e "  ${GREY}  🔒 $lu (مقفل — مقصود؟)${NC}"
        done
    else
        echo -e "  ${GREEN}لا توجد حسابات مقفلة غير root${NC}"
    fi
else
    echo -e "  $(t c_needs_root)"
fi

# ─── 4. حسابات بدون كلمة سر في /etc/passwd ───────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ حسابات بكلمة سر في /etc/passwd (خطر قديم)${NC}"
shadow_in_passwd=$(awk -F: '$2 != "x" && $2 != "*" && $2 != "" && $2 != "!" {print $1, "— password in /etc/passwd!"}' \
    /etc/passwd 2>/dev/null)
if [ -n "$shadow_in_passwd" ]; then
    echo -e "  ${RED}⚠️  ${shadow_in_passwd}${NC}"
    finding_add critical "Password stored in /etc/passwd (not shadowed)"
else
    echo -e "  ${GREEN}جميع كلمات المرور في shadow${NC}"
fi

# ─── 5. مستخدمو UID=0 (root إضافيون) ──────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ حسابات بـ UID=0 (صلاحية root)${NC}"
uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
uid0_count=$(echo "$uid0" | wc -l)
if [ "$uid0_count" -gt 1 ]; then
    echo -e "  ${RED}⚠️  $uid0_count حساب بـ UID=0:${NC}"
    echo "$uid0" | while IFS= read -r u; do
        [ "$u" = "root" ] && echo -e "  ${GREEN}  $u (شرعي)${NC}" || \
            { echo -e "  ${RED}  🔴 $u (غير شرعي!)${NC}"; finding_add critical "Non-root account with UID=0: $u"; }
    done
else
    echo -e "  ${GREEN}حساب root واحد فقط بـ UID=0${NC}"
fi

# ─── 6. ملخص ─────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Password Policy Audit — $(date)

login.defs: ${FILE:-not found}
$REPORT

Expired: ${expired:-None}
No-password accounts: ${no_pw:-None}
UID=0 accounts: $uid0" "password_policy_check.txt" "$TOOL_TITLE"
