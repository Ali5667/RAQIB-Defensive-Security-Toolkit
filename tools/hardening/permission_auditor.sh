#!/bin/bash
# =====================================================
#  Permission Auditor — مدقق الصلاحيات الشامل
#  يفحص: World-writable files/dirs، SUID/SGID binaries،
#  ملفات SSH مكشوفة، صلاحيات /etc الحساسة، cron jobs،
#  ملفات بدون مالك، صلاحيات .ssh directories،
#  مقارنة SUID/SGID مع قاعدة بيانات شرعية
# =====================================================
finding_reset

TOOL_TITLE="$(t har1_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

read -rp "$(t har1_prompt_dir)  [افتراضي: /]: " dir
dir="${dir:-/}"

if [ ! -d "$dir" ]; then
    echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1
fi

REPORT=""

# ─── قاعدة بيانات SUID شرعية ──────────────────────────────
# ملفات SUID معروفة ومتوقعة — أي شيء خارج هذه القائمة مشبوه
KNOWN_SUID=(
    "/bin/su" "/bin/ping" "/bin/ping6" "/bin/umount" "/bin/mount"
    "/usr/bin/sudo" "/usr/bin/passwd" "/usr/bin/gpasswd" "/usr/bin/newgrp"
    "/usr/bin/chfn" "/usr/bin/chsh" "/usr/bin/su" "/usr/bin/pkexec"
    "/usr/bin/ssh-agent" "/usr/bin/crontab" "/usr/bin/at"
    "/usr/lib/openssh/ssh-keysign" "/usr/sbin/unix_chkpwd"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    "/usr/lib/polkit-1/polkit-agent-helper-1"
    "/sbin/unix_chkpwd" "/usr/bin/sudo" "/usr/bin/wall"
    "/usr/bin/screen" "/bin/fusermount"
)

is_known_suid() {
    local file="$1"
    for known in "${KNOWN_SUID[@]}"; do
        [ "$file" = "$known" ] && return 0
    done
    return 1
}

# ─── 1. World-Writable Files (بدون sticky bit) ───────────────
echo -e "${BOLD}${YELLOW}$(t har1_s1) (قد يعدّلها أي مستخدم)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
run_with_spinner "  البحث... " -- bash -c "
find \"$dir\" -xdev -type f -perm -0002 2>/dev/null |
grep -vE '^/proc|^/sys|^/dev|^/run' | head -40 > /tmp/.raqib_ww_files
"
ww_files=$(cat /tmp/.raqib_ww_files 2>/dev/null)
rm -f /tmp/.raqib_ww_files

if [ -n "$ww_files" ]; then
    ww_count=$(echo "$ww_files" | wc -l)
    echo -e "  ${RED}$ww_count ملف world-writable:${NC}"
    echo "$ww_files" | while IFS= read -r f; do
        perm=$(raqib_stat_perm "$f" 2>/dev/null || echo "???")
        owner=$(stat -c '%U:%G' "$f" 2>/dev/null || stat -f '%Su:%Sg' "$f" 2>/dev/null || echo "?:?")
        echo -e "  ${RED}  ▸ $f  ${GREY}(perms: $perm, owner: $owner)${NC}"
        finding_add high "World-writable file: $f (perms: $perm)"
    done
else
    echo -e "  ${GREEN}لا توجد ملفات world-writable${NC}"
fi

REPORT+="$(t har1_s1)
${ww_files:-None}

"

# ─── 2. World-Writable Directories بدون Sticky Bit ───────────
echo ""
echo -e "${BOLD}${YELLOW}$(t har1_s4) (بدون sticky bit — خطر)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
ww_dirs=$(find "$dir" -xdev -type d -perm -0002 ! -perm -1000 \
    2>/dev/null | grep -vE '^/proc|^/sys|^/dev|^/run' | head -20)
if [ -n "$ww_dirs" ]; then
    ww_dir_count=$(echo "$ww_dirs" | wc -l)
    echo -e "  ${ORANGE}$ww_dir_count مجلد world-writable بدون sticky:${NC}"
    echo "$ww_dirs" | while IFS= read -r d; do
        perm=$(raqib_stat_perm "$d" 2>/dev/null || echo "???")
        echo -e "  ${ORANGE}  ▸ $d  ${GREY}(perms: $perm)${NC}"
        finding_add high "World-writable directory without sticky bit: $d"
    done
else
    echo -e "  ${GREEN}لا توجد مجلدات world-writable خطيرة${NC}"
fi

REPORT+="$(t har1_s4)
${ww_dirs:-None}

"

# ─── 3. SUID Binaries ─────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t har1_s2) — المقارنة مع القائمة الشرعية${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
run_with_spinner "  البحث عن SUID... " -- bash -c "
find \"$dir\" -xdev -type f -perm -4000 2>/dev/null |
grep -vE '^/proc|^/sys' | sort > /tmp/.raqib_suid
"
suid_files=$(cat /tmp/.raqib_suid 2>/dev/null)
rm -f /tmp/.raqib_suid

if [ -n "$suid_files" ]; then
    suid_count=$(echo "$suid_files" | wc -l)
    echo -e "  ${BOLD}$suid_count SUID binary:${NC}"
    echo "$suid_files" | while IFS= read -r f; do
        perm=$(raqib_stat_perm "$f" 2>/dev/null || echo "???")
        if is_known_suid "$f"; then
            echo -e "  ${GREEN}  ✓ $f  ${GREY}(perms: $perm — شرعي)${NC}"
        else
            echo -e "  ${RED}  ⚠️ [UNKNOWN SUID] $f  ${GREY}(perms: $perm)${NC}"
            finding_add critical "Unknown SUID binary (not in whitelist): $f"
        fi
    done
else
    echo -e "  ${GREEN}لا توجد SUID binaries${NC}"
fi

REPORT+="$(t har1_s2)
${suid_files:-None}

"

# ─── 4. SGID Binaries ─────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}$(t har1_s3)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
sgid_files=$(find "$dir" -xdev -type f -perm -2000 \
    2>/dev/null | grep -vE '^/proc|^/sys' | head -30)
if [ -n "$sgid_files" ]; then
    echo "$sgid_files" | while IFS= read -r f; do
        perm=$(raqib_stat_perm "$f" 2>/dev/null || echo "???")
        echo -e "  ${YELLOW}  ▸ $f  ${GREY}(perms: $perm)${NC}"
        finding_add medium "SGID binary: $f"
    done
else
    echo -e "  ${GREEN}لا توجد SGID binaries${NC}"
fi

REPORT+="$(t har1_s3)
${sgid_files:-None}

"

# ─── 5. ملفات بدون مالك (orphan files) ───────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ ملفات بدون مالك (Orphan Files) — دليل محتمل على اختراق${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
run_with_spinner "  البحث... " -- bash -c "
find \"$dir\" -xdev \( -nouser -o -nogroup \) 2>/dev/null |
grep -vE '^/proc|^/sys|^/dev' | head -30 > /tmp/.raqib_orphan
"
orphan_files=$(cat /tmp/.raqib_orphan 2>/dev/null)
rm -f /tmp/.raqib_orphan

if [ -n "$orphan_files" ]; then
    orphan_count=$(echo "$orphan_files" | wc -l)
    echo -e "  ${ORANGE}$orphan_count ملف/مجلد بدون مالك:${NC}"
    echo "$orphan_files" | while IFS= read -r f; do
        echo -e "  ${ORANGE}  ▸ $f${NC}"
        finding_add medium "Orphan file (no owner/group): $f"
    done
else
    echo -e "  ${GREEN}لا توجد ملفات بدون مالك${NC}"
fi

REPORT+="Orphan Files:
${orphan_files:-None}

"

# ─── 6. ملفات .ssh وصلاحياتها ────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ فحص صلاحيات مجلدات وملفات .ssh${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

ssh_report=""
for home_dir in /root /home/*; do
    ssh_dir="$home_dir/.ssh"
    [ -d "$ssh_dir" ] || continue

    ssh_perm=$(raqib_stat_perm "$ssh_dir" 2>/dev/null || echo "?")
    user=$(basename "$home_dir")

    # مجلد .ssh يجب أن يكون 700
    if [ "$ssh_perm" != "700" ] && [ "$ssh_perm" != "0700" ]; then
        echo -e "  ${RED}[HIGH] .ssh لـ $user بصلاحية $ssh_perm (يجب 700)${NC}"
        finding_add high ".ssh directory too permissive for $user: $ssh_perm (should be 700)"
    else
        echo -e "  ${GREEN}[✓] .ssh لـ $user — $ssh_perm${NC}"
    fi

    # authorized_keys يجب أن يكون 600
    ak="$ssh_dir/authorized_keys"
    if [ -f "$ak" ]; then
        ak_perm=$(raqib_stat_perm "$ak" 2>/dev/null || echo "?")
        if [ "$ak_perm" != "600" ] && [ "$ak_perm" != "0600" ]; then
            echo -e "  ${ORANGE}  [MEDIUM] authorized_keys لـ $user: $ak_perm (يجب 600)${NC}"
            finding_add medium "Insecure authorized_keys for $user: $ak_perm"
        fi
    fi

    # private keys
    for key in "$ssh_dir"/{id_rsa,id_ed25519,id_ecdsa}; do
        if [ -f "$key" ]; then
            key_perm=$(raqib_stat_perm "$key" 2>/dev/null || echo "?")
            if [ "$key_perm" != "600" ] && [ "$key_perm" != "0600" ]; then
                echo -e "  ${RED}  [HIGH] مفتاح خاص مكشوف: $(basename "$key") للمستخدم $user — $key_perm${NC}"
                finding_add high "Private SSH key too permissive for $user: $key_perm"
            fi
        fi
    done
    ssh_report+="$user: $ssh_dir ($ssh_perm)\n"
done

[ -z "$ssh_report" ] && echo -e "  ${GREY}لا توجد مجلدات .ssh${NC}"

REPORT+="SSH Directories:
$(echo -e "$ssh_report")
"

# ─── 7. ملخص ─────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$(tf har1_report_title "$dir" "$(date)")

$REPORT" "permission_audit_${dir//\//_}.txt" "$TOOL_TITLE"
