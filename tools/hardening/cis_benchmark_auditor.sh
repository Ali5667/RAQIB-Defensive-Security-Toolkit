#!/bin/bash
# =====================================================
#  RAQIB CIS Benchmark Auditor + Auto-Remediation
#  تقييم امتثال النظام لمعايير CIS Benchmarks
#  مع إمكانية المعالجة التلقائية والتراجع (Rollback)
#
#  المعايير المدعومة:
#    - CIS Level 1: إعدادات أساسية (يجب تطبيقها)
#    - CIS Level 2: إعدادات متقدمة (اختيارية)
#
#  الآلية:
#    1) يفحص كل معيار ويعطيه PASS أو FAIL
#    2) يحسب درجة الامتثال المئوية
#    3) يعرض خيار المعالجة التلقائية مع Backup
#    4) يحفظ نقطة استعادة (Rollback) قبل أي تغيير
#
#  بدون تبعيات — يستخدم أدوات POSIX الأساسية فقط.
# =====================================================
finding_reset

TOOL_TITLE="$(t hd9_title 2>/dev/null || echo 'CIS Benchmark Auditor')"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

BACKUP_DIR="${SCRIPT_DIR:-.}/state/cis_backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR" 2>/dev/null

REPORT=""
TOTAL_CHECKS=0
PASSED=0
FAILED=0
REMEDIATED=0
RESULTS=()

# ─── دوال المساعدة ──────────────────────────────────────────────

check_result() {
    local id="$1" level="$2" title="$3" result="$4" detail="$5"
    ((TOTAL_CHECKS++))
    local badge
    if [ "$result" = "PASS" ]; then
        badge="${GREEN}[PASS]${NC}"
        ((PASSED++))
    else
        badge="${RED}[FAIL]${NC}"
        ((FAILED++))
        finding_add medium 2>/dev/null
    fi
    printf "  %b %-6s L%s  %s\n" "$badge" "$id" "$level" "$title"
    [ -n "$detail" ] && echo -e "    ${GREY}$detail${NC}"
    RESULTS+=("$id|$level|$title|$result|$detail")
    REPORT="${REPORT}[$result] $id (L$level) $title\n"
    [ -n "$detail" ] && REPORT="${REPORT}  $detail\n"
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        local dest="$BACKUP_DIR/$(echo "$file" | tr '/' '_')"
        cp -a "$file" "$dest" 2>/dev/null
    fi
}

# ─── CIS Level 1 Checks ─────────────────────────────────────────

echo -e "${YELLOW}═══ CIS Level 1 — Essential Security Settings ═══${NC}"
echo ""

# 1.1 - Filesystem: /tmp separate partition
if mount | grep -q ' /tmp '; then
    check_result "1.1.1" "1" "/tmp is a separate partition" "PASS"
else
    check_result "1.1.1" "1" "/tmp is a separate partition" "FAIL" "/tmp is not on a separate partition"
fi

# 1.2 - /tmp noexec
if mount | grep ' /tmp ' | grep -q 'noexec'; then
    check_result "1.1.2" "1" "/tmp mounted with noexec" "PASS"
else
    check_result "1.1.2" "1" "/tmp mounted with noexec" "FAIL" "noexec not set on /tmp"
fi

# 2.1 - SSH: PermitRootLogin
if [ -f /etc/ssh/sshd_config ]; then
    local_val=$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ "$local_val" = "no" ]; then
        check_result "5.2.1" "1" "SSH: PermitRootLogin disabled" "PASS"
    else
        check_result "5.2.1" "1" "SSH: PermitRootLogin disabled" "FAIL" "Current: ${local_val:-not set}"
    fi
else
    check_result "5.2.1" "1" "SSH: PermitRootLogin disabled" "FAIL" "sshd_config not found"
fi

# 2.2 - SSH: Protocol 2
if [ -f /etc/ssh/sshd_config ]; then
    if ! grep -qi 'Protocol.*1' /etc/ssh/sshd_config 2>/dev/null; then
        check_result "5.2.2" "1" "SSH: Protocol 2 only" "PASS"
    else
        check_result "5.2.2" "1" "SSH: Protocol 2 only" "FAIL" "Protocol 1 is enabled"
    fi
fi

# 2.3 - SSH: MaxAuthTries
if [ -f /etc/ssh/sshd_config ]; then
    local max_auth
    max_auth=$(grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [ -n "$max_auth" ] && [ "$max_auth" -le 4 ] 2>/dev/null; then
        check_result "5.2.3" "1" "SSH: MaxAuthTries <= 4" "PASS" "MaxAuthTries=$max_auth"
    else
        check_result "5.2.3" "1" "SSH: MaxAuthTries <= 4" "FAIL" "Current: ${max_auth:-6 (default)}"
    fi
fi

# 2.4 - SSH: PermitEmptyPasswords
if [ -f /etc/ssh/sshd_config ]; then
    if grep -qi '^PermitEmptyPasswords.*no' /etc/ssh/sshd_config 2>/dev/null || \
       ! grep -qi '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null; then
        check_result "5.2.4" "1" "SSH: Empty passwords disabled" "PASS"
    else
        check_result "5.2.4" "1" "SSH: Empty passwords disabled" "FAIL"
    fi
fi

# 3.1 - Password: Minimum length
if [ -f /etc/login.defs ]; then
    local min_len
    min_len=$(grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$min_len" ] && [ "$min_len" -ge 14 ] 2>/dev/null; then
        check_result "5.4.1" "1" "Password minimum length >= 14" "PASS" "PASS_MIN_LEN=$min_len"
    else
        check_result "5.4.1" "1" "Password minimum length >= 14" "FAIL" "Current: ${min_len:-5 (default)}"
    fi
fi

# 3.2 - Password: Max days
if [ -f /etc/login.defs ]; then
    local max_days
    max_days=$(grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [ -n "$max_days" ] && [ "$max_days" -le 365 ] 2>/dev/null; then
        check_result "5.4.2" "1" "Password max age <= 365 days" "PASS" "PASS_MAX_DAYS=$max_days"
    else
        check_result "5.4.2" "1" "Password max age <= 365 days" "FAIL" "Current: ${max_days:-99999}"
    fi
fi

# 4.1 - Firewall enabled
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi 'active'; then
    check_result "3.5.1" "1" "Firewall is active" "PASS" "ufw is active"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi 'running'; then
    check_result "3.5.1" "1" "Firewall is active" "PASS" "firewalld is running"
elif iptables -L -n 2>/dev/null | grep -qE 'ACCEPT|DROP|REJECT' | head -1; then
    check_result "3.5.1" "1" "Firewall is active" "PASS" "iptables has rules"
else
    check_result "3.5.1" "1" "Firewall is active" "FAIL" "No active firewall detected"
fi

# 5.1 - No world-writable files in system dirs
local world_writable
world_writable=$(find /usr /bin /sbin -xdev -perm -002 -type f 2>/dev/null | head -5)
if [ -z "$world_writable" ]; then
    check_result "6.1.1" "1" "No world-writable system files" "PASS"
else
    check_result "6.1.1" "1" "No world-writable system files" "FAIL" "Found: $(echo "$world_writable" | head -3)"
fi

# 5.2 - No unowned files
local unowned
unowned=$(find /usr /bin /sbin -xdev -nouser -o -nogroup 2>/dev/null | head -5)
if [ -z "$unowned" ]; then
    check_result "6.1.2" "1" "No unowned system files" "PASS"
else
    check_result "6.1.2" "1" "No unowned system files" "FAIL" "Found: $(echo "$unowned" | head -3)"
fi

# 6.1 - /etc/passwd permissions
if [ -f /etc/passwd ]; then
    local pp
    pp=$(stat -c '%a' /etc/passwd 2>/dev/null || stat -f '%Lp' /etc/passwd 2>/dev/null)
    if [ "$pp" = "644" ]; then
        check_result "6.2.1" "1" "/etc/passwd permissions = 644" "PASS"
    else
        check_result "6.2.1" "1" "/etc/passwd permissions = 644" "FAIL" "Current: $pp"
    fi
fi

# 6.2 - /etc/shadow permissions
if [ -f /etc/shadow ]; then
    local sp
    sp=$(stat -c '%a' /etc/shadow 2>/dev/null || stat -f '%Lp' /etc/shadow 2>/dev/null)
    if [ "$sp" = "640" ] || [ "$sp" = "600" ] || [ "$sp" = "000" ]; then
        check_result "6.2.2" "1" "/etc/shadow permissions restricted" "PASS" "Permissions: $sp"
    else
        check_result "6.2.2" "1" "/etc/shadow permissions restricted" "FAIL" "Current: $sp"
    fi
fi

# 7.1 - Core dumps disabled
if grep -qs '^\*.*hard.*core.*0' /etc/security/limits.conf 2>/dev/null || \
   sysctl fs.suid_dumpable 2>/dev/null | grep -q '= 0'; then
    check_result "1.5.1" "1" "Core dumps disabled" "PASS"
else
    check_result "1.5.1" "1" "Core dumps disabled" "FAIL"
fi

# 7.2 - ASLR enabled
if [ "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" = "2" ]; then
    check_result "1.5.2" "1" "ASLR enabled (randomize_va_space=2)" "PASS"
else
    check_result "1.5.2" "1" "ASLR enabled (randomize_va_space=2)" "FAIL"
fi

echo ""
echo -e "${YELLOW}═══ CIS Level 2 — Advanced Security Settings ═══${NC}"
echo ""

# L2: 8.1 - Auditd running
if systemctl is-active auditd >/dev/null 2>&1 || [ -f /var/log/audit/audit.log ]; then
    check_result "4.1.1" "2" "Audit daemon is running" "PASS"
else
    check_result "4.1.1" "2" "Audit daemon is running" "FAIL" "auditd not active"
fi

# L2: 8.2 - USB storage disabled
if lsmod 2>/dev/null | grep -q usb_storage; then
    check_result "1.1.9" "2" "USB storage module not loaded" "FAIL" "usb_storage is loaded"
else
    check_result "1.1.9" "2" "USB storage module not loaded" "PASS"
fi

# L2: 8.3 - IP forwarding disabled
if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "0" ]; then
    check_result "3.1.1" "2" "IP forwarding disabled" "PASS"
else
    check_result "3.1.1" "2" "IP forwarding disabled" "FAIL" "ip_forward=1"
fi

# L2: 8.4 - ICMP redirects disabled
if [ "$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)" = "0" ]; then
    check_result "3.2.1" "2" "ICMP redirects disabled" "PASS"
else
    check_result "3.2.1" "2" "ICMP redirects disabled" "FAIL"
fi

# L2: 8.5 - TCP SYN cookies enabled
if [ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = "1" ]; then
    check_result "3.2.2" "2" "TCP SYN cookies enabled" "PASS"
else
    check_result "3.2.2" "2" "TCP SYN cookies enabled" "FAIL"
fi

# ═══════════════════════════════════════════════════════════════════
# النتائج والدرجة المئوية
# ═══════════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"

local score=0
[ "$TOTAL_CHECKS" -gt 0 ] && score=$(( (PASSED * 100) / TOTAL_CHECKS ))

local score_color
if [ "$score" -ge 80 ]; then score_color="$GREEN"
elif [ "$score" -ge 60 ]; then score_color="$YELLOW"
else score_color="$RED"
fi

echo -e "  ${BOLD}CIS Compliance Score:${NC} ${score_color}${score}%${NC} ($PASSED/$TOTAL_CHECKS passed)"
echo -e "  ${GREEN}Passed:${NC} $PASSED  ${RED}Failed:${NC} $FAILED"

local grade
if [ "$score" -ge 90 ]; then grade="A"
elif [ "$score" -ge 80 ]; then grade="B"
elif [ "$score" -ge 70 ]; then grade="C"
elif [ "$score" -ge 60 ]; then grade="D"
else grade="F"
fi
echo -e "  ${BOLD}Grade:${NC} ${score_color}${grade}${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"

REPORT="${REPORT}\n=== CIS Compliance Score: ${score}% (${PASSED}/${TOTAL_CHECKS}) Grade: ${grade} ===\n"

# ═══════════════════════════════════════════════════════════════════
# Auto-Remediation
# ═══════════════════════════════════════════════════════════════════
if [ "$FAILED" -gt 0 ]; then
    echo ""
    read -rp "  $(t hd9_auto_fix 2>/dev/null || echo 'Auto-fix failed checks? (backup will be created) [y/N]: ')" fix_ans

    if [ "$fix_ans" = "y" ]; then
        echo ""
        echo -e "  ${CYAN}Creating backup in: $BACKUP_DIR${NC}"

        for result_line in "${RESULTS[@]}"; do
            IFS='|' read -r rid rlevel rtitle rstatus rdetail <<< "$result_line"
            [ "$rstatus" = "PASS" ] && continue

            case "$rid" in
                5.2.1)
                    backup_file /etc/ssh/sshd_config
                    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null
                    grep -q '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || \
                        echo "PermitRootLogin no" >> /etc/ssh/sshd_config
                    echo -e "  ${GREEN}✓ Fixed: PermitRootLogin no${NC}"
                    ((REMEDIATED++))
                    ;;
                5.2.3)
                    backup_file /etc/ssh/sshd_config
                    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config 2>/dev/null
                    grep -q '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null || \
                        echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
                    echo -e "  ${GREEN}✓ Fixed: MaxAuthTries 4${NC}"
                    ((REMEDIATED++))
                    ;;
                5.4.1)
                    backup_file /etc/login.defs
                    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN\t14/' /etc/login.defs 2>/dev/null
                    echo -e "  ${GREEN}✓ Fixed: PASS_MIN_LEN 14${NC}"
                    ((REMEDIATED++))
                    ;;
                5.4.2)
                    backup_file /etc/login.defs
                    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' /etc/login.defs 2>/dev/null
                    echo -e "  ${GREEN}✓ Fixed: PASS_MAX_DAYS 365${NC}"
                    ((REMEDIATED++))
                    ;;
                1.5.2)
                    sysctl -w kernel.randomize_va_space=2 >/dev/null 2>&1
                    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-raqib-cis.conf 2>/dev/null
                    echo -e "  ${GREEN}✓ Fixed: ASLR enabled${NC}"
                    ((REMEDIATED++))
                    ;;
                3.2.1)
                    sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1
                    echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/99-raqib-cis.conf 2>/dev/null
                    echo -e "  ${GREEN}✓ Fixed: ICMP redirects disabled${NC}"
                    ((REMEDIATED++))
                    ;;
                3.2.2)
                    sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1
                    echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/99-raqib-cis.conf 2>/dev/null
                    echo -e "  ${GREEN}✓ Fixed: SYN cookies enabled${NC}"
                    ((REMEDIATED++))
                    ;;
            esac
        done

        echo ""
        echo -e "  ${GREEN}Remediated: $REMEDIATED checks${NC}"
        echo -e "  ${CYAN}Backups saved to: $BACKUP_DIR${NC}"
        echo -e "  ${YELLOW}To rollback: cp $BACKUP_DIR/* / (restore manually)${NC}"

        REPORT="${REPORT}\nAuto-remediated: $REMEDIATED checks\nBackups: $BACKUP_DIR\n"
    fi
fi

echo ""
if [ -n "$REPORT" ]; then
    save_report "$(echo -e "$REPORT")" "raqib_cis_audit_$(date +%Y%m%d_%H%M%S).txt" "$TOOL_TITLE" 2>/dev/null
fi
pause 2>/dev/null || read -rp "Press Enter to continue..."
