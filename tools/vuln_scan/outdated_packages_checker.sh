#!/bin/bash
# =====================================================
#  Outdated Packages Checker — فاحص الحزم المنتهية
#  يدعم: apt/yum/dnf/pacman/zypper/apk/snap/flatpak
#  يحلل: حزم أمنية حرجة، kernel updates، pip/npm/gem،
#  CVE حزم معروفة، تاريخ آخر تحديث، auto-update status
# =====================================================
finding_reset

TOOL_TITLE="$(t vul2_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""
TOTAL_UPGRADABLE=0

# ─── كشف مدير الحزم ──────────────────────────────────────────
echo -e "${BOLD}${YELLOW}◉ نظام التشغيل ومدير الحزم${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

# معلومات النظام
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo -e "  ${CYAN}OS:${NC} ${PRETTY_NAME:-$NAME $VERSION}"
else
    echo -e "  ${CYAN}OS:${NC} $(uname -s) $(uname -r)"
fi

# Kernel
echo -e "  ${CYAN}Kernel:${NC} $(uname -r)"
echo ""

# ─── 1. System Packages ──────────────────────────────────────
echo -e "${BOLD}${YELLOW}◉ حزم النظام القابلة للتحديث${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

PKG_MGR="none"

if command -v apt >/dev/null 2>&1; then
    PKG_MGR="apt"
    echo -e "  ${CYAN}مدير الحزم: APT (Debian/Ubuntu)${NC}"
    echo ""

    upgradable=$(run_with_spinner "$(t vul2_updating) " -- \
        bash -c "apt list --upgradable 2>/dev/null | grep -v '^Listing'")

    if [ -n "$upgradable" ]; then
        count=$(printf '%s\n' "$upgradable" | grep -c '\S')
        TOTAL_UPGRADABLE=$((TOTAL_UPGRADABLE + count))

        # فصل الحزم الأمنية
        security_pkgs=$(echo "$upgradable" | grep -i "security" | head -20)
        sec_count=$(echo "$security_pkgs" | grep -c '\S' 2>/dev/null || echo 0)

        echo -e "  ${BOLD}$count حزمة قابلة للتحديث${NC}"
        if [ "$sec_count" -gt 0 ]; then
            echo -e "  ${RED}  🔴 $sec_count حزمة أمنية حرجة:${NC}"
            echo "$security_pkgs" | while IFS= read -r sp; do
                echo -e "  ${RED}    ▸ $sp${NC}"
            done
            finding_add critical "$sec_count critical security packages need updating"
        fi

        # الباقي
        echo ""
        echo "$upgradable" | grep -vi "security" | head -20
        [ "$count" -gt 20 ] && echo -e "  ${GREY}  ... و$((count - 20)) حزمة إضافية${NC}"

        if [ "$count" -gt 50 ]; then
            finding_add high "System significantly outdated: $count packages need updating"
        elif [ "$count" -gt 20 ]; then
            finding_add high "Many outdated packages: $count"
        elif [ "$count" -gt 0 ]; then
            finding_add medium "Some packages outdated: $count"
        fi
    else
        echo -e "  ${GREEN}جميع الحزم محدّثة ✅${NC}"
    fi

    # تاريخ آخر تحديث
    last_update=$(stat -c '%Y' /var/cache/apt/pkgcache.bin 2>/dev/null)
    if [ -n "$last_update" ]; then
        now=$(date +%s)
        days_ago=$(( (now - last_update) / 86400 ))
        echo -e "  ${GREY}آخر apt update: قبل $days_ago يوم${NC}"
        [ "$days_ago" -gt 30 ] && {
            echo -e "  ${ORANGE}⚠️  لم يتم تحديث قاعدة الحزم منذ $days_ago يوم!${NC}"
            finding_add medium "Package database not updated in $days_ago days"
        }
    fi

    # Auto-update status
    echo ""
    if dpkg -l | grep -q "unattended-upgrades" 2>/dev/null; then
        echo -e "  ${GREEN}[✓] التحديثات التلقائية مُفعّلة (unattended-upgrades)${NC}"
    else
        echo -e "  ${YELLOW}[!] التحديثات التلقائية غير مُفعّلة${NC}"
        echo -e "  ${GREY}    sudo apt install unattended-upgrades${NC}"
        finding_add low "Automatic security updates not enabled"
    fi

elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
    echo -e "  ${CYAN}مدير الحزم: YUM (RHEL/CentOS)${NC}"
    yum_out=$(run_with_spinner "$(t vul2_updating) " -- bash -c "yum check-update 2>/dev/null")
    rc=$?
    echo "$yum_out" | head -30
    [ "$rc" = "100" ] && finding_add medium "YUM reports available updates"

    # Security updates
    sec_updates=$(yum check-update --security 2>/dev/null | grep -c '\S' || echo 0)
    [ "$sec_updates" -gt 0 ] && finding_add high "$sec_updates security updates available (yum)"

elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
    echo -e "  ${CYAN}مدير الحزم: DNF (Fedora/RHEL 8+)${NC}"
    dnf_out=$(run_with_spinner "$(t vul2_updating) " -- bash -c "dnf check-update 2>/dev/null")
    rc=$?
    echo "$dnf_out" | head -30
    [ "$rc" = "100" ] && finding_add medium "DNF reports available updates"

elif command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"
    echo -e "  ${CYAN}مدير الحزم: Pacman (Arch Linux)${NC}"
    pacman_out=$(run_with_spinner "$(t vul2_updating) " -- \
        bash -c "pacman -Sy >/dev/null 2>&1; pacman -Qu 2>/dev/null")
    echo "$pacman_out" | head -30
    count=$(printf '%s\n' "$pacman_out" | grep -c '\S')
    TOTAL_UPGRADABLE=$((TOTAL_UPGRADABLE + count))
    if [ "$count" -gt 20 ]; then
        finding_add high "Pacman: $count outdated packages"
    elif [ "$count" -gt 0 ]; then
        finding_add medium "Pacman: $count outdated packages"
    fi

elif command -v zypper >/dev/null 2>&1; then
    PKG_MGR="zypper"
    echo -e "  ${CYAN}مدير الحزم: Zypper (openSUSE)${NC}"
    zypper_out=$(run_with_spinner "$(t vul2_updating) " -- bash -c "zypper -q list-updates 2>/dev/null")
    echo "$zypper_out" | head -30
    count=$(printf '%s\n' "$zypper_out" | grep -c '\S')
    [ "$count" -gt 0 ] && finding_add medium "Zypper: $count updates available"

elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"
    echo -e "  ${CYAN}مدير الحزم: APK (Alpine Linux)${NC}"
    apk_out=$(run_with_spinner "$(t vul2_updating) " -- \
        bash -c "apk update >/dev/null 2>&1; apk version -l '<' 2>/dev/null")
    echo "$apk_out" | head -30
    count=$(printf '%s\n' "$apk_out" | grep -c '\S')
    [ "$count" -gt 0 ] && finding_add medium "APK: $count outdated packages"
fi

echo -e "${GREEN}$(tf vul2_upgradable_count "$TOTAL_UPGRADABLE")${NC}"
REPORT+="System Packages: $TOTAL_UPGRADABLE outdated ($PKG_MGR)\n"

# ─── 2. Kernel Update ────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ فحص تحديث Kernel${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
current_kernel=$(uname -r)
echo -e "  Kernel الحالي: ${CYAN}$current_kernel${NC}"

if [ "$PKG_MGR" = "apt" ]; then
    latest_kernel=$(apt list --upgradable 2>/dev/null | grep "linux-image" | head -1)
    if [ -n "$latest_kernel" ]; then
        echo -e "  ${ORANGE}⚠️  تحديث Kernel متوفر: $latest_kernel${NC}"
        finding_add high "Kernel update available"
    else
        echo -e "  ${GREEN}  Kernel محدّث ✅${NC}"
    fi
fi

# ─── 3. Python pip ────────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ $(t vul2_pip_outdated)${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if command -v pip3 >/dev/null 2>&1; then
    pip_outdated=$(run_with_spinner "  فحص pip... " -- pip3 list --outdated --format=columns 2>/dev/null)
    if [ -n "$pip_outdated" ]; then
        pip_count=$(echo "$pip_outdated" | tail -n +3 | grep -c '\S' 2>/dev/null || echo 0)
        echo -e "  ${YELLOW}$pip_count حزمة Python قديمة:${NC}"
        echo "$pip_outdated" | head -15
        [ "$pip_count" -gt 15 ] && echo -e "  ${GREY}  ... و$((pip_count - 15)) حزمة إضافية${NC}"
        finding_add low "pip: $pip_count outdated Python packages"
    else
        echo -e "  ${GREEN}جميع حزم pip محدّثة ✅${NC}"
    fi
elif command -v pip >/dev/null 2>&1; then
    pip_outdated=$(pip list --outdated --format=columns 2>/dev/null | head -15)
    [ -n "$pip_outdated" ] && { echo "$pip_outdated"; finding_add low "pip outdated packages found"; }
else
    echo -e "  ${GREY}pip3 غير متوفر${NC}"
fi

# ─── 4. npm (Node.js) ────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ Node.js npm — حزم عالمية قديمة${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if command -v npm >/dev/null 2>&1; then
    npm_outdated=$(npm outdated -g 2>/dev/null)
    if [ -n "$npm_outdated" ]; then
        npm_count=$(echo "$npm_outdated" | grep -c '\S')
        echo -e "  ${YELLOW}$npm_count حزمة npm عالمية قديمة:${NC}"
        echo "$npm_outdated" | head -10
        finding_add low "npm: $npm_count outdated global packages"
    else
        echo -e "  ${GREEN}جميع حزم npm العالمية محدّثة ✅${NC}"
    fi

    # npm audit
    echo ""
    echo -e "  ${YELLOW}◉ npm audit (ثغرات معروفة بالمشروع الحالي):${NC}"
    if [ -f "package.json" ]; then
        audit=$(npm audit --json 2>/dev/null | grep -oE '"(critical|high|moderate|low)":[0-9]+' | head -5)
        if [ -n "$audit" ]; then
            echo "  $audit"
        else
            echo -e "  ${GREEN}لا توجد ثغرات معروفة${NC}"
        fi
    else
        echo -e "  ${GREY}لا يوجد package.json بالدليل الحالي${NC}"
    fi
else
    echo -e "  ${GREY}npm غير متوفر${NC}"
fi

# ─── 5. Snap/Flatpak ─────────────────────────────────────────
echo ""
echo -e "${BOLD}${YELLOW}◉ Snap/Flatpak Updates${NC}"
echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"

if command -v snap >/dev/null 2>&1; then
    snap_refresh=$(snap refresh --list 2>/dev/null)
    if [ -n "$snap_refresh" ]; then
        echo -e "  ${YELLOW}Snap تحديثات متوفرة:${NC}"
        echo "$snap_refresh" | head -10
        finding_add low "Snap packages have updates available"
    else
        echo -e "  ${GREEN}Snap محدّث ✅${NC}"
    fi
else
    echo -e "  ${GREY}Snap غير متوفر${NC}"
fi

if command -v flatpak >/dev/null 2>&1; then
    flatpak_update=$(flatpak update --appstream 2>/dev/null; flatpak remote-ls --updates 2>/dev/null)
    if [ -n "$flatpak_update" ]; then
        echo -e "  ${YELLOW}Flatpak تحديثات:${NC}"
        echo "$flatpak_update" | head -10
    else
        echo -e "  ${GREEN}Flatpak محدّث ✅${NC}"
    fi
fi

# ─── 6. ملخص ─────────────────────────────────────────────────
echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "Outdated Packages Audit — $(date)
OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || uname -s)
Kernel: $(uname -r)
Package Manager: $PKG_MGR
System packages outdated: $TOTAL_UPGRADABLE

$REPORT" "outdated_packages.txt" "$TOOL_TITLE"
