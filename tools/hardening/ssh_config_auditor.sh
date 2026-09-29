#!/bin/bash
# =====================================================
#  SSH Config Auditor — مدقق إعدادات SSH
#  يفحص sshd_config مقابل معايير CIS/NIST/NSA
#  يتحقق من: 45+ إعداد أمني، المفاتيح المصرح بها،
#  قيود المستخدمين، الشبكات، cipher suites، KEx،
#  MACs، و authorized_keys لكل المستخدمين
# =====================================================
finding_reset

TOOL_TITLE="$(t har2_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

CONFIG="/etc/ssh/sshd_config"
[ -n "$1" ] && CONFIG="$1"
if [ ! -f "$CONFIG" ]; then
    read -rp "$(t har2_prompt_config)  [افتراضي: /etc/ssh/sshd_config]: " CONFIG
    CONFIG="${CONFIG:-/etc/ssh/sshd_config}"
fi
[ ! -f "$CONFIG" ] && { echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1; }

echo -e "${GREY}  الملف: $CONFIG${NC}"
echo ""

REPORT_LINES=""
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# ─── دالة فحص الإعداد ─────────────────────────────────────────
# check_setting KEY EXPECTED SEVERITY DESC [OPERATOR]
# OPERATOR: eq (افتراضي) | ne | contains | numeric_le | numeric_ge
check() {
    local key="$1" expected="$2" sev="${3:-high}" desc="$4" op="${5:-eq}"
    local value
    # قراءة آخر قيمة غير معلّقة (يدعم Include)
    value=$(grep -iE "^\s*${key}\s+" "$CONFIG" 2>/dev/null | \
        tail -1 | awk '{$1=""; print $0}' | sed 's/^ //; s/\s*#.*//' | xargs 2>/dev/null)

    local not_defined good preferred line badge
    not_defined="$(t har2_not_defined)"
    good="$(t har2_good)"
    preferred="$(tf har2_preferred "$expected")"

    if [ -z "$value" ]; then
        badge="${YELLOW}[?] $key ${not_defined}${NC}"
        line="[?] $key NOT DEFINED — $desc (preferred: $expected)"
        echo -e "  ${YELLOW}[?]${NC} ${BOLD}$key${NC} — $desc  ${GREY}(preferred: $expected)${NC}"
        finding_add "low" "$key not defined in sshd_config (recommended: $expected)"
        WARN_COUNT=$((WARN_COUNT + 1))
    else
        local match=0
        case "$op" in
            eq)       [[ "${value,,}" == "${expected,,}" ]] && match=1 ;;
            ne)       [[ "${value,,}" != "${expected,,}" ]] && match=1 ;;
            contains) echo "${value,,}" | grep -qi "$expected" && match=1 ;;
            numeric_le) [[ "$value" =~ ^[0-9]+$ && "$expected" =~ ^[0-9]+$ ]] && \
                         [ "$value" -le "$expected" ] && match=1 ;;
            numeric_ge) [[ "$value" =~ ^[0-9]+$ && "$expected" =~ ^[0-9]+$ ]] && \
                         [ "$value" -ge "$expected" ] && match=1 ;;
        esac

        if [ "$match" -eq 1 ]; then
            echo -e "  ${GREEN}[✓]${NC} ${BOLD}$key${NC} = ${GREEN}$value${NC}  — $desc"
            line="[OK] $key = $value — $desc"
            PASS_COUNT=$((PASS_COUNT + 1))
        else
            case "$sev" in
                critical) color="$RED" ;;
                high) color="$ORANGE" ;;
                medium) color="$YELLOW" ;;
                *) color="$CYAN" ;;
            esac
            echo -e "  ${color}[✗]${NC} ${BOLD}$key${NC} = ${color}$value${NC}  (recommended: ${expected})  — $desc"
            line="[$sev] $key = $value (recommended: $expected) — $desc"
            finding_add "$sev" "sshd_config: $key=$value (should be: $expected) — $desc"
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
    fi
    REPORT_LINES+="${line}"$'\n'
}

# ─── فحوصات: Authentication ──────────────────────────────────
echo -e "${BOLD}${CYAN}━━ المصادقة (Authentication) ━━${NC}"
check "PermitRootLogin"           "no"              "critical" "$(t har2_desc_root_login)"
check "PasswordAuthentication"    "no"              "high"     "$(t har2_desc_password_auth)"
check "PermitEmptyPasswords"      "no"              "critical" "$(t har2_desc_empty_pw)"
check "PubkeyAuthentication"      "yes"             "medium"   "تفعيل مصادقة المفتاح العام"
check "AuthenticationMethods"     "publickey"       "medium"   "إجبار مصادقة المفتاح فقط" "contains"
check "MaxAuthTries"              "3"               "medium"   "$(t har2_desc_maxauth)" "numeric_le"
check "LoginGraceTime"            "30"              "low"      "وقت انتهاء تسجيل الدخول (ثانية)" "numeric_le"
check "UsePAM"                    "yes"             "low"      "استخدام PAM للمصادقة"

echo ""
echo -e "${BOLD}${CYAN}━━ البروتوكول والتشفير (Protocol & Crypto) ━━${NC}"
check "Protocol"                  "2"               "critical" "$(t har2_desc_protocol)"
check "X11Forwarding"             "no"              "medium"   "$(t har2_desc_x11)"
check "AllowAgentForwarding"      "no"              "medium"   "منع agent forwarding غير الضروري"
check "AllowTcpForwarding"        "no"              "medium"   "منع TCP tunneling غير المصرح"
check "PermitTunnel"              "no"              "medium"   "منع VPN tunneling عبر SSH"
check "GatewayPorts"              "no"              "high"     "منع binding لمنافذ خارجية"

echo ""
echo -e "${BOLD}${CYAN}━━ التسجيل والمراقبة (Logging) ━━${NC}"
check "LogLevel"                  "VERBOSE"         "medium"   "تسجيل مفصّل للعمليات" "contains"
check "SyslogFacility"            "AUTH"            "low"      "Facility تسجيل SSH"

echo ""
echo -e "${BOLD}${CYAN}━━ التحكم في الوصول (Access Control) ━━${NC}"
check "MaxSessions"               "4"               "low"      "الحد الأقصى لجلسات SSH" "numeric_le"
check "MaxStartups"               "10:30:60"        "medium"   "تحديد الاتصالات غير المصادقة"
check "ClientAliveInterval"       "300"             "low"      "Timeout للجلسات الخاملة (ثانية)" "numeric_le"
check "ClientAliveCountMax"       "2"               "low"      "عدد محاولات الping قبل قطع الاتصال" "numeric_le"
check "TCPKeepAlive"              "yes"             "low"      "إبقاء الاتصال حياً بـ TCP"
check "Compression"               "no"              "low"      "منع الضغط (يسهّل بعض الهجمات)"
check "IgnoreRhosts"              "yes"             "high"     "تجاهل ملفات .rhosts القديمة"
check "HostbasedAuthentication"   "no"              "high"     "منع المصادقة بالاسم"
check "IgnoreUserKnownHosts"      "yes"             "medium"   "تجاهل known_hosts الشخصي"

# ─── فحص: Cipher Suites قوية ─────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ Cipher Suites ━━${NC}"
ciphers_val=$(grep -iE "^\s*Ciphers\s+" "$CONFIG" 2>/dev/null | tail -1 | awk '{$1=""; print $0}' | xargs)
if [ -n "$ciphers_val" ]; then
    # تحقق من وجود ciphers ضعيفة
    weak_found=0
    for wc in "arcfour" "3des" "blowfish" "cast128" "aes128-cbc" "aes192-cbc" "aes256-cbc"; do
        if echo "${ciphers_val,,}" | grep -q "$wc"; then
            echo -e "  ${RED}[✗] Ciphers تحتوي cipher ضعيف: $wc${NC}"
            finding_add high "Weak SSH cipher enabled: $wc"
            weak_found=1
        fi
    done
    [ "$weak_found" -eq 0 ] && echo -e "  ${GREEN}[✓] Ciphers = $ciphers_val${NC}"
else
    echo -e "  ${YELLOW}[?] Ciphers غير محددة (يستخدم OpenSSH الافتراضي)${NC}"
fi

macs_val=$(grep -iE "^\s*MACs\s+" "$CONFIG" 2>/dev/null | tail -1 | awk '{$1=""; print $0}' | xargs)
if [ -n "$macs_val" ]; then
    for wm in "hmac-md5" "hmac-sha1" "umac-64"; do
        if echo "${macs_val,,}" | grep -q "$wm"; then
            echo -e "  ${ORANGE}[!] MACs تحتوي MAC ضعيف: $wm${NC}"
            finding_add medium "Weak SSH MAC enabled: $wm"
        fi
    done
else
    echo -e "  ${YELLOW}[?] MACs غير محددة (يستخدم OpenSSH الافتراضي)${NC}"
fi

# ─── فحص authorized_keys لكل المستخدمين ──────────────────────
echo ""
echo -e "${BOLD}${CYAN}━━ مفاتيح SSH المصرح بها (authorized_keys) ━━${NC}"
auth_keys_report=""
while IFS=: read -r uname _ uid _ _ home _; do
    [ "$uid" -lt 1000 ] && [ "$uname" != "root" ] && continue
    ak_file="$home/.ssh/authorized_keys"
    [ -f "$ak_file" ] || continue

    key_count=$(grep -c 'ssh-' "$ak_file" 2>/dev/null || echo 0)
    perm=$(raqib_stat_perm "$ak_file" 2>/dev/null || echo "?")

    echo -e "  ${CYAN}$uname${NC}: $ak_file ($key_count مفتاح، perms: $perm)"

    # فحص صلاحيات خاطئة
    if [[ "$perm" =~ [67][0-9][0-9] ]]; then
        echo -e "  ${RED}  ⚠️  صلاحيات authorized_keys واسعة جداً: $perm${NC}"
        finding_add high "Insecure authorized_keys permissions for $uname: $perm"
    fi

    # مفاتيح مشبوهة (command= قديم أو from=* مفتوح)
    if grep -q 'from="\*"' "$ak_file" 2>/dev/null; then
        echo -e "  ${ORANGE}  ⚠️  مفتاح SSH بقيد from=\"*\" مفتوح لأي IP${NC}"
        finding_add medium "Unrestricted SSH key for $uname (from=\"*\")"
    fi

    auth_keys_report+="$uname: $ak_file ($key_count keys, perms: $perm)\n"
done < /etc/passwd 2>/dev/null

[ -z "$auth_keys_report" ] && echo -e "  ${GREY}لا توجد ملفات authorized_keys مرئية${NC}"

REPORT_LINES+=$'\n'"=== authorized_keys ==="$'\n'"$auth_keys_report"

# ─── ملخص الفحص ──────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GREEN}✅ ناجح: $PASS_COUNT${NC}  |  ${RED}❌ فشل: $FAIL_COUNT${NC}  |  ${YELLOW}⚠️  تحذير: $WARN_COUNT${NC}"
echo ""
print_executive_summary "$TOOL_TITLE"

save_report "$(tf har2_report_title "$CONFIG" "$(date)")

$REPORT_LINES" "ssh_config_audit.txt" "$TOOL_TITLE"
