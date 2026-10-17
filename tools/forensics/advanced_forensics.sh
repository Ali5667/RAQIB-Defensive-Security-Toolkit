#!/bin/bash
# =====================================================
#  RAQIB Forensics Suite — أدوات التحقيقات الرقمية المتقدمة
#  3 أدوات جديدة في ملف واحد:
#
#  1) Live Memory Carving — فحص ذاكرة العمليات المشبوهة
#     يقرأ /proc/[PID]/maps و /proc/[PID]/mem لاستخلاص
#     سلاسل نصية مشبوهة (URLs, IPs, shell commands, keys)
#
#  2) Auditd Process Lineage — تتبع مسار العمليات
#     يبني شجرة العمليات من سجلات audit لمعرفة من أطلق
#     العملية الضارة بالتسلسل (Process Tree Reconstruction)
#
#  3) System Binary Integrity — فحص سلامة الأوامر النظامية
#     يقارن بصمات الأدوات الأساسية (ls, ps, netstat...)
#     مع حزم النظام الأصلية (debsums / rpm -V)
#
#  بدون تبعيات خارجية — يستخدم /proc + أدوات POSIX فقط.
# =====================================================
finding_reset

TOOL_TITLE="$(t fr7_title 2>/dev/null || echo 'Advanced Forensics Suite')"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

# ═══════════════════════════════════════════════════════════════════
# 1) Live Memory Carving
# ═══════════════════════════════════════════════════════════════════
memory_carve() {
    echo -e "${YELLOW}◉ Live Memory Carving — فحص ذاكرة العمليات${NC}"
    echo ""

    if [ ! -d /proc/1 ]; then
        echo -e "${RED}  /proc not available — Linux only${NC}"
        return 1
    fi

    # أنماط مشبوهة نبحث عنها بالذاكرة
    local SUSPICIOUS_PATTERNS='(/dev/tcp/|nc\s+-e|mkfifo|reverse.shell|bash\s+-i|python.*pty\.spawn|curl.*\|.*sh|wget.*\|.*sh|base64\s+-d|eval\s*\(|exec\s*\(|/etc/shadow|/etc/passwd|ssh-rsa\s+AAAA|BEGIN\s+(RSA|PRIVATE|CERTIFICATE)|stratum\+tcp|xmrig|monero|coinhive|c2server|beacon|implant|meterpreter|cobalt)'

    local total_suspicious=0
    local pids_checked=0

    # جمع العمليات المشبوهة أولاً (ليست root/kernel)
    echo -e "  ${GREY}Scanning process memory regions...${NC}"
    echo ""

    for pid_dir in /proc/[0-9]*/; do
        local pid="${pid_dir#/proc/}"
        pid="${pid%/}"

        # تجاهل PID 1 وعمليات النواة
        [ "$pid" = "1" ] && continue
        [ -f "/proc/$pid/maps" ] || continue

        local cmdline
        cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
        [ -z "$cmdline" ] && continue  # kernel thread

        ((pids_checked++))

        # قراءة المناطق القابلة للقراءة من الذاكرة
        local found_in_pid=0
        local findings=""

        while IFS= read -r map_line; do
            # نحلل سطر maps: address perms offset dev inode pathname
            local addr_range perms
            addr_range=$(echo "$map_line" | awk '{print $1}')
            perms=$(echo "$map_line" | awk '{print $2}')

            # نركز على المناطق القابلة للقراءة والكتابة (heap, stack, anon)
            [[ "$perms" == *r* ]] || continue

            local start_hex end_hex
            start_hex="0x${addr_range%-*}"
            end_hex="0x${addr_range#*-}"

            # نقرأ جزء محدود من الذاكرة (أول 64KB) لتفادي البطء
            local start_dec end_dec read_size
            start_dec=$((start_hex))
            end_dec=$((end_hex))
            read_size=$((end_dec - start_dec))
            [ "$read_size" -gt 65536 ] && read_size=65536
            [ "$read_size" -le 0 ] && continue

            # استخلاص السلاسل النصية من المنطقة
            local strings_found
            strings_found=$(dd if="/proc/$pid/mem" bs=1 skip="$start_dec" \
                           count="$read_size" 2>/dev/null | \
                           strings -n 6 2>/dev/null | \
                           grep -iE "$SUSPICIOUS_PATTERNS" 2>/dev/null | head -5)

            if [ -n "$strings_found" ]; then
                ((found_in_pid++))
                findings="${findings}${strings_found}\n"
            fi

        done < <(head -50 "/proc/$pid/maps" 2>/dev/null)

        if [ "$found_in_pid" -gt 0 ]; then
            ((total_suspicious++))

            local exe_path
            exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")

            # تحديد الخطورة
            local sev badge
            if echo -e "$findings" | grep -qiE 'meterpreter|cobalt|beacon|c2server|implant'; then
                sev="critical"; badge="${RED}[CRITICAL]${NC}"
            elif echo -e "$findings" | grep -qiE '/dev/tcp|reverse.shell|nc\s+-e|mkfifo'; then
                sev="high"; badge="${ORANGE}[HIGH]${NC}"
            elif echo -e "$findings" | grep -qiE 'BEGIN.*PRIVATE|ssh-rsa|/etc/shadow'; then
                sev="high"; badge="${ORANGE}[HIGH]${NC}"
            else
                sev="medium"; badge="${YELLOW}[MEDIUM]${NC}"
            fi

            echo -e "  $badge PID=$pid  CMD=$(echo "$cmdline" | cut -c1-60)"
            echo -e "    ${GREY}EXE: $exe_path${NC}"
            echo -e "$findings" | while IFS= read -r line; do
                [ -n "$line" ] && echo -e "    ${RED}→ $line${NC}"
            done
            echo ""
            finding_add "$sev" 2>/dev/null

            REPORT="${REPORT}[${sev^^}] PID=$pid CMD=$(echo "$cmdline" | cut -c1-80)\n"
            REPORT="${REPORT}  EXE: $exe_path\n"
            REPORT="${REPORT}$(echo -e "$findings" | head -5 | sed 's/^/  → /')\n\n"

            # استشارة محرك الاستخبارات لو متوفر
            local ips_in_mem
            ips_in_mem=$(echo -e "$findings" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
            for check_ip in $ips_in_mem; do
                raqib_intel_check_and_report "$check_ip" 2>/dev/null
            done
        fi

        # حد أقصى 200 عملية لتفادي البطء
        [ "$pids_checked" -ge 200 ] && break
    done

    echo -e "  ${GREY}Checked: $pids_checked processes | Suspicious: $total_suspicious${NC}"
}

# ═══════════════════════════════════════════════════════════════════
# 2) Auditd Process Lineage
# ═══════════════════════════════════════════════════════════════════
process_lineage() {
    echo -e "${YELLOW}◉ Process Lineage — تتبع مسار العمليات${NC}"
    echo ""

    local target_pid="$1"

    if [ -z "$target_pid" ]; then
        read -rp "  PID to trace (or 'recent' for recent suspicious): " target_pid
    fi

    if [ "$target_pid" = "recent" ]; then
        # البحث عن أحدث عمليات مشبوهة من سجلات audit
        echo -e "  ${GREY}Searching audit logs for recent executions...${NC}"
        echo ""

        local audit_log="/var/log/audit/audit.log"
        [ -f "$audit_log" ] || audit_log="/var/log/audit.log"

        if [ -f "$audit_log" ]; then
            echo -e "  ${CYAN}Recent EXECVE events:${NC}"
            grep -i 'type=EXECVE\|type=SYSCALL.*exe=' "$audit_log" 2>/dev/null | \
                tail -30 | while IFS= read -r line; do
                local ts pid exe
                ts=$(echo "$line" | grep -oE 'msg=audit\([0-9.]+' | grep -oE '[0-9.]+')
                pid=$(echo "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)
                exe=$(echo "$line" | grep -oE 'exe="[^"]*"' | cut -d'"' -f2)
                [ -n "$pid" ] && printf "    PID=%-8s EXE=%-40s\n" "$pid" "${exe:-?}"
            done
        else
            echo -e "  ${YELLOW}Audit log not found. Using /proc instead.${NC}"
        fi
        echo ""
        read -rp "  Enter PID to trace: " target_pid
    fi

    [ -z "$target_pid" ] && return

    echo ""
    echo -e "  ${CYAN}Process Tree for PID $target_pid:${NC}"
    echo -e "  ${GREY}──────────────────────────────────────${NC}"

    # بناء شجرة العمليات من /proc
    local current_pid="$target_pid"
    local depth=0
    local tree_lines=()

    while [ "$current_pid" != "0" ] && [ "$current_pid" != "1" ] && [ "$depth" -lt 20 ]; do
        if [ -d "/proc/$current_pid" ]; then
            local cmd ppid user start_time
            cmd=$(tr '\0' ' ' < "/proc/$current_pid/cmdline" 2>/dev/null | cut -c1-70)
            ppid=$(awk '/^PPid:/{print $2}' "/proc/$current_pid/status" 2>/dev/null)
            user=$(awk '/^Uid:/{print $2}' "/proc/$current_pid/status" 2>/dev/null)
            user=$(getent passwd "$user" 2>/dev/null | cut -d: -f1 || echo "$user")

            local exe_path
            exe_path=$(readlink -f "/proc/$current_pid/exe" 2>/dev/null || echo "?")

            local prefix=""
            for ((i=0; i<depth; i++)); do prefix="  │ $prefix"; done

            if [ "$depth" -eq 0 ]; then
                prefix="  ▶ "
            else
                prefix="  $(printf '│   %.0s' $(seq 1 $depth))├── "
            fi

            tree_lines+=("${prefix}PID=$current_pid  USER=$user  CMD=$cmd")
            tree_lines+=("${prefix}  EXE=$exe_path")

            # فحص هل العملية مشبوهة
            local suspicious=0
            if echo "$cmd" | grep -qiE 'nc\s|ncat|socat|/dev/tcp|python.*-c|perl.*-e|bash.*-i'; then
                tree_lines+=("${prefix}  ${RED}⚠ Suspicious command pattern${NC}")
                suspicious=1
            fi
            if echo "$exe_path" | grep -qE '^/tmp/|^/dev/shm/|^/var/tmp/'; then
                tree_lines+=("${prefix}  ${RED}⚠ Executable in temp directory${NC}")
                suspicious=1
            fi

            [ "$suspicious" -eq 1 ] && finding_add high 2>/dev/null

            current_pid="$ppid"
            ((depth++))
        else
            break
        fi
    done

    # طباعة من الأب للابن (عكس الترتيب)
    for ((i=${#tree_lines[@]}-1; i>=0; i--)); do
        echo -e "${tree_lines[$i]}"
    done

    # فحص العمليات الأبناء
    echo ""
    echo -e "  ${CYAN}Child processes of PID $target_pid:${NC}"
    local children
    children=$(find /proc -maxdepth 2 -name status 2>/dev/null | while read -r sf; do
        local cpid spid
        cpid=$(basename "$(dirname "$sf")")
        [[ "$cpid" =~ ^[0-9]+$ ]] || continue
        spid=$(awk '/^PPid:/{print $2}' "$sf" 2>/dev/null)
        [ "$spid" = "$target_pid" ] && echo "$cpid"
    done)

    if [ -n "$children" ]; then
        for child_pid in $children; do
            local child_cmd
            child_cmd=$(tr '\0' ' ' < "/proc/$child_pid/cmdline" 2>/dev/null | cut -c1-70)
            echo -e "    └── PID=$child_pid  CMD=$child_cmd"
        done
    else
        echo -e "    ${GREY}No child processes${NC}"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# 3) System Binary Integrity
# ═══════════════════════════════════════════════════════════════════
binary_integrity() {
    echo -e "${YELLOW}◉ System Binary Integrity Check — فحص سلامة الأوامر${NC}"
    echo ""

    # الأوامر الحرجة اللي نفحصها
    local CRITICAL_BINS=(
        /bin/ls /bin/ps /bin/netstat /bin/ss /bin/login /bin/su /bin/sudo
        /usr/bin/find /usr/bin/top /usr/bin/who /usr/bin/w /usr/bin/last
        /usr/bin/passwd /usr/bin/ssh /usr/bin/scp /usr/bin/curl /usr/bin/wget
        /usr/sbin/sshd /usr/sbin/cron /usr/sbin/iptables /usr/sbin/nft
        /bin/bash /bin/sh /usr/bin/python3 /usr/bin/perl
    )

    local total=0 verified=0 modified=0 missing=0 unpackaged=0

    echo -e "  ${GREY}Binary                          Status       Package${NC}"
    echo -e "  ${GREY}──────────────────────────────── ──────────── ──────────────${NC}"

    for bin_path in "${CRITICAL_BINS[@]}"; do
        ((total++))

        # تحقق من الوجود
        if [ ! -f "$bin_path" ]; then
            # ممكن يكون بمسار بديل
            local alt_path
            alt_path=$(command -v "$(basename "$bin_path")" 2>/dev/null)
            if [ -n "$alt_path" ] && [ -f "$alt_path" ]; then
                bin_path="$alt_path"
            else
                printf "  %-32s ${GREY}[MISSING]${NC}\n" "$bin_path"
                ((missing++))
                continue
            fi
        fi

        # فحص سلامة الحزمة
        local status pkg_name badge
        local mgr
        mgr=$(raqib_pkg_manager 2>/dev/null)

        case "$mgr" in
            apt)
                pkg_name=$(dpkg -S "$bin_path" 2>/dev/null | cut -d: -f1)
                if [ -n "$pkg_name" ]; then
                    # فحص debsums
                    if command -v debsums >/dev/null 2>&1; then
                        local check
                        check=$(debsums -c "$pkg_name" 2>/dev/null | grep -c "$bin_path")
                        if [ "$check" -gt 0 ]; then
                            status="MODIFIED"; badge="${RED}[MODIFIED]${NC}"
                            ((modified++))
                            finding_add high 2>/dev/null
                        else
                            status="OK"; badge="${GREEN}[OK]${NC}"
                            ((verified++))
                        fi
                    else
                        # بديل: مقارنة الهاش مع dpkg --verify
                        if dpkg --verify "$pkg_name" 2>/dev/null | grep -q "$bin_path"; then
                            status="MODIFIED"; badge="${RED}[MODIFIED]${NC}"
                            ((modified++))
                            finding_add high 2>/dev/null
                        else
                            status="OK"; badge="${GREEN}[OK]${NC}"
                            ((verified++))
                        fi
                    fi
                else
                    status="UNPACKAGED"; badge="${YELLOW}[UNPACKAGED]${NC}"
                    ((unpackaged++))
                    pkg_name="-"
                fi
                ;;
            dnf|yum|zypper)
                pkg_name=$(rpm -qf "$bin_path" 2>/dev/null)
                if [ -n "$pkg_name" ] && [ "$pkg_name" != "file $bin_path is not owned by any package" ]; then
                    local rpm_verify
                    rpm_verify=$(rpm -Vf "$bin_path" 2>/dev/null)
                    if [ -n "$rpm_verify" ] && echo "$rpm_verify" | grep -qE '^[S.][0-9M.][0-9.][0-9.][UG.][T.]'; then
                        status="MODIFIED"; badge="${RED}[MODIFIED]${NC}"
                        ((modified++))
                        finding_add high 2>/dev/null
                    else
                        status="OK"; badge="${GREEN}[OK]${NC}"
                        ((verified++))
                    fi
                else
                    status="UNPACKAGED"; badge="${YELLOW}[UNPACKAGED]${NC}"
                    ((unpackaged++))
                    pkg_name="-"
                fi
                ;;
            pacman)
                pkg_name=$(pacman -Qo "$bin_path" 2>/dev/null | awk '{print $(NF-1)}')
                if [ -n "$pkg_name" ]; then
                    # pacman -Qk يتحقق من تكامل الملفات
                    if pacman -Qk "$pkg_name" 2>&1 | grep -qi 'warning.*modified'; then
                        status="MODIFIED"; badge="${RED}[MODIFIED]${NC}"
                        ((modified++))
                    else
                        status="OK"; badge="${GREEN}[OK]${NC}"
                        ((verified++))
                    fi
                else
                    status="UNPACKAGED"; badge="${YELLOW}[UNPACKAGED]${NC}"
                    ((unpackaged++))
                    pkg_name="-"
                fi
                ;;
            apk)
                pkg_name=$(apk info --who-owns "$bin_path" 2>/dev/null | awk '{print $NF}')
                if [ -n "$pkg_name" ]; then
                    if apk verify "$pkg_name" 2>&1 | grep -qi 'FAIL'; then
                        status="MODIFIED"; badge="${RED}[MODIFIED]${NC}"
                        ((modified++))
                    else
                        status="OK"; badge="${GREEN}[OK]${NC}"
                        ((verified++))
                    fi
                else
                    status="UNPACKAGED"; badge="${YELLOW}[UNPACKAGED]${NC}"
                    ((unpackaged++))
                    pkg_name="-"
                fi
                ;;
            *)
                # بدون مدير حزم — نتحقق بالهاش فقط
                local hash
                hash=$(raqib_hash sha256 "$bin_path" 2>/dev/null || sha256sum "$bin_path" 2>/dev/null | awk '{print $1}')
                status="HASH-ONLY"; badge="${GREY}[HASH]${NC}"
                pkg_name="$hash"
                ((verified++))
                ;;
        esac

        # فحص إضافي: هل الملف SUID/SGID بشكل غير متوقع؟
        if [ -u "$bin_path" ]; then
            local expected_suid="su sudo passwd ping mount umount"
            local bname
            bname=$(basename "$bin_path")
            if ! echo "$expected_suid" | grep -qw "$bname"; then
                badge="${badge} ${RED}[UNEXPECTED SUID!]${NC}"
                finding_add critical 2>/dev/null
            fi
        fi

        printf "  %-32s %b  %s\n" "$bin_path" "$badge" "${pkg_name:-?}"
    done

    echo ""
    echo -e "  ${BOLD}Summary:${NC}"
    echo -e "    Total: $total | Verified: ${GREEN}$verified${NC} | Modified: ${RED}$modified${NC} | Missing: $missing | Unpackaged: $unpackaged"

    if [ "$modified" -gt 0 ]; then
        echo ""
        echo -e "  ${RED}⚠ $modified system binaries have been modified!${NC}"
        echo -e "  ${RED}  This may indicate a rootkit or tampering.${NC}"
        finding_add critical 2>/dev/null
    fi

    REPORT="${REPORT}=== System Binary Integrity ===\n"
    REPORT="${REPORT}Total: $total | Verified: $verified | Modified: $modified | Missing: $missing\n"
}

# ═══════════════════════════════════════════════════════════════════
# القائمة الرئيسية
# ═══════════════════════════════════════════════════════════════════
echo -e "  ${CYAN}1)${NC} 🧠 Live Memory Carving        — فحص ذاكرة العمليات"
echo -e "  ${CYAN}2)${NC} 🌳 Process Lineage Tracer     — تتبع مسار العمليات"
echo -e "  ${CYAN}3)${NC} 🔒 System Binary Integrity    — فحص سلامة الأوامر"
echo -e "  ${CYAN}4)${NC} 🔄 Run All                    — تشغيل الكل"
echo ""
read -rp "  اختر [1-4]: " choice

case "$choice" in
    1) memory_carve ;;
    2) process_lineage ;;
    3) binary_integrity ;;
    4) memory_carve; echo ""; process_lineage "recent"; echo ""; binary_integrity ;;
    *) echo -e "${RED}  Invalid choice${NC}" ;;
esac

echo ""
if [ -n "$REPORT" ]; then
    save_report "$(echo -e "$REPORT")" "raqib_forensics_$(date +%Y%m%d_%H%M%S).txt" "$TOOL_TITLE" 2>/dev/null
fi
pause 2>/dev/null || read -rp "Press Enter to continue..."
