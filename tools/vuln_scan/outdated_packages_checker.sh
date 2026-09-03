#!/bin/bash
finding_reset
echo -e "${CYAN}$(t vul2_title)${NC}"

if command -v apt >/dev/null 2>&1; then
    upgradable=$(run_with_spinner "$(t vul2_updating) " -- bash -c "apt list --upgradable 2>/dev/null | grep -v '^Listing'")
    echo -e "${YELLOW}$(t vul2_updating)${NC}"
    echo "$upgradable"
    count=$(printf '%s\n' "$upgradable" | grep -c '\S')
    echo -e "${GREEN}$(tf vul2_upgradable_count "$count")${NC}"
    if [ "$count" -gt 20 ]; then
        finding_add high
    elif [ "$count" -gt 0 ]; then
        finding_add medium
    fi
elif command -v yum >/dev/null 2>&1; then
    yum_out=$(run_with_spinner "$(t vul2_updating) " -- bash -c "yum check-update 2>/dev/null")
    rc=$?
    echo -e "${YELLOW}$(t vul2_updating)${NC}"
    echo "$yum_out"
    [ "$rc" = "100" ] && finding_add medium
elif command -v dnf >/dev/null 2>&1; then
    dnf_out=$(run_with_spinner "$(t vul2_updating) " -- bash -c "dnf check-update 2>/dev/null")
    rc=$?
    echo -e "${YELLOW}$(t vul2_updating)${NC}"
    echo "$dnf_out"
    [ "$rc" = "100" ] && finding_add medium
elif command -v pacman >/dev/null 2>&1; then
    echo -e "${YELLOW}$(t vul2_updating)${NC}"
    pacman_out=$(run_with_spinner "$(t vul2_updating) " -- bash -c "pacman -Sy >/dev/null 2>&1; pacman -Qu 2>/dev/null")
    echo "$pacman_out"
    count=$(printf '%s\n' "$pacman_out" | grep -c '\S')
    if [ "$count" -gt 20 ]; then
        finding_add high
    elif [ "$count" -gt 0 ]; then
        finding_add medium
    fi
elif command -v zypper >/dev/null 2>&1; then
    zypper_out=$(run_with_spinner "$(t vul2_updating) " -- bash -c "zypper -q list-updates 2>/dev/null")
    echo -e "${YELLOW}$(t vul2_updating)${NC}"
    echo "$zypper_out"
    count=$(printf '%s\n' "$zypper_out" | grep -c '\S')
    [ "$count" -gt 0 ] && finding_add medium
elif command -v apk >/dev/null 2>&1; then
    apk_out=$(run_with_spinner "$(t vul2_updating) " -- bash -c "apk update >/dev/null 2>&1; apk version -l '<' 2>/dev/null")
    echo -e "${YELLOW}$(t vul2_updating)${NC}"
    echo "$apk_out"
    count=$(printf '%s\n' "$apk_out" | grep -c '\S')
    [ "$count" -gt 0 ] && finding_add medium
fi

echo ""
if command -v pip3 >/dev/null 2>&1; then
    echo -e "${YELLOW}$(t vul2_pip_outdated)${NC}"
    pip_outdated=$(run_with_spinner "$(t vul2_pip_outdated) " -- pip3 list --outdated 2>/dev/null)
    echo "$pip_outdated"
    [ -n "$pip_outdated" ] && finding_add low
fi

print_executive_summary "$(t vul2_title)"
