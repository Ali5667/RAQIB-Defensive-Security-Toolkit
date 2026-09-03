#!/bin/bash
# =====================================================
#  RAQIB (رقيب) - Defensive Security Toolkit
#  Author : Ali Alnuaimi
#  GitHub : https://github.com/Ali5667
#  Twitter: @ali_cys45
# =====================================================
# كل أداة هنا مكتوبة بالكامل من الصفر وتشتغل بشكل
# مستقل — لا تعتمد على تحميل أدوات خارجية معروفة.
# =====================================================

# RAQIB يعتمد على associative arrays (Bash 4+) لملف الترجمة، فما تشتغل بشكل
# صحيح (وبدون رسالة خطأ واضحة) على Bash 3.x — وهو الإصدار الافتراضي بـ macOS.
# هذا الفحص يوقف التشغيل برسالة واضحة بدل انهيار غامض لاحقاً.
if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "RAQIB requires Bash 4 or newer (found: ${BASH_VERSION:-unknown})." >&2
    echo "RAQIB يتطلب Bash 4 أو أحدث (النسخة الحالية: ${BASH_VERSION:-غير معروفة})." >&2
    echo "  - macOS: brew install bash   ثم شغّل الأداة بـ:  /opt/homebrew/bin/bash raqib.sh" >&2
    echo "  - Linux: bash --version يفترض يطلع 4+ افتراضياً؛ لو أقدم حدّث الحزمة bash." >&2
    exit 1
fi

VERSION="2.0"
LAST_UPDATED="2026-09-02"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
TOOLS_DIR="$SCRIPT_DIR/tools"
export SCRIPT_DIR TOOLS_DIR

GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
ORANGE=$'\033[38;5;208m'
CRIMSON=$'\033[1;31m'
WHITE=$'\033[1;37m'
GREY=$'\033[1;30m'
BOLD=$'\033[1m'
NC=$'\033[0m'
export GREEN CYAN YELLOW RED ORANGE CRIMSON WHITE GREY BOLD NC

type_line() {
    local text="$1"; local delay="${2:-0.01}"
    for (( i=0; i<${#text}; i++ )); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    printf "\n"
}
export -f type_line

# reveal_logo: يطبع ملف الشعار سطر سطر بتأخير بسيط، يعطي تأثير مسح/رادار
# ينزل من فوق لتحت بدل ما يطلع الشعار كامل دفعة وحدة.
reveal_logo() {
    local file="$1"
    local delay="${2:-0.018}"
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf "%s\n" "$line"
        sleep "$delay"
    done < "$file"
}
export -f reveal_logo

# radar_scan: يطبع الشعار خافت (رمادي) أول شي، وبعدين يرجع المؤشر لفوق
# ويمسح خط ساطع (سماوي) ينزل سطر سطر فوق نفس الشعار، وأخيرًا يثبته أبيض عادي.
# تأثير رادار حقيقي بحركة مؤشر (ANSI) مو بس ظهور تدريجي.
radar_scan() {
    local file="$1"
    local delay="${2:-0.02}"
    local total
    total=$(wc -l < "$file")

    # الممر الأول: الشعار خافت رمادي بالكامل
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf "%s%s%s\n" "$GREY" "$line" "$NC"
    done < "$file"

    # رجّع المؤشر لأول سطر بالشعار
    printf "\033[%dA" "$total"

    # الممر الثاني: خط المسح الساطع ينزل سطر سطر
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf "%s%s%s\n" "$CYAN" "$line" "$NC"
        sleep "$delay"
    done < "$file"

    # رجّع المؤشر وثبّت الشعار بلونه النهائي (أبيض)
    printf "\033[%dA" "$total"
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf "%s%s%s\n" "$WHITE" "$line" "$NC"
    done < "$file"
}
export -f radar_scan

show_eagle_intro() {
    clear
    if (( RANDOM % 2 == 0 )); then
        radar_scan "$SCRIPT_DIR/assets/eagle_logo.txt"
    else
        radar_scan "$SCRIPT_DIR/assets/eagle_logo_2.txt"
    fi
    sleep 0.5
    print_banner_info
    sleep 0.6
}
export -f show_eagle_intro

# print_banner_info: يطبع اسم RAQIB وسطر الوصف/الإصدار وتاريخ الإنشاء ومعلومات المؤلف.
# مستخدمة من show_eagle_intro (مرة وحدة بالبداية) ومن show_banner (كل رجعة للقائمة الرئيسية).
print_banner_info() {
    echo -e "${GREEN}"
    cat << "EOF"
  ____      _    ___ ___ ____
 |  _ \    / \  / _ \_ _| __ )
 | |_) |  / _ \| | | | ||  _ \
 |  _ <  / ___ \ |_| | || |_) |
 |_| \_\/_/   \_\__\_\___|____/

EOF
    echo -e "${NC}"
    type_line "  RAQIB (رقيب) — $(t subtitle) v${VERSION}" 0.006
    type_line "  Rapid Audit & Quick Incident-response Bash-toolkit" 0.004
    type_line "  $(tf banner_created "$(get_created_date)")" 0.001
    type_line "  ------------------------------------------------------------" 0.001
    type_line "  [+] Author  : Ali Alnuaimi" 0.012
    type_line "  [+] GitHub  : https://github.com/Ali5667" 0.012
    type_line "  [+] Twitter : @ali_cys45" 0.012
    type_line "  ------------------------------------------------------------" 0.001
    echo ""
}
export -f print_banner_info

show_banner() {
    clear
    print_banner_info
}
export -f show_banner

pause() {
    echo ""
    read -rp "$(echo -e ${YELLOW}"$(t press_enter)"${NC})"
}
export -f pause

source "$MODULES_DIR/lang.sh"
load_lang

source "$MODULES_DIR/monitoring.sh"
source "$MODULES_DIR/logs.sh"
source "$MODULES_DIR/ids_ips.sh"
source "$MODULES_DIR/malware.sh"
source "$MODULES_DIR/forensics.sh"
source "$MODULES_DIR/hardening.sh"
source "$MODULES_DIR/vuln_scan.sh"

show_known_limitations() {
    show_banner
    echo -e "${BOLD}${ORANGE}$(t limitations_title)${NC}"
    echo ""
    local i
    for i in 1 2 3 4 5 6; do
        echo -e "  ${YELLOW}-${NC} $(t "limitations_item${i}")"
        echo ""
    done
    pause
}
export -f show_known_limitations

# يقارن رقمين إصدار بصيغة X.Y — يرجع 0 (صح) لو $1 أحدث من $2
_raqib_version_gt() {
    local a="$1" b="$2"
    local a_major a_minor b_major b_minor
    a_major="${a%%.*}"; a_minor="${a#*.}"; [ "$a_minor" = "$a" ] && a_minor=0
    b_major="${b%%.*}"; b_minor="${b#*.}"; [ "$b_minor" = "$b" ] && b_minor=0
    [[ "$a_major" =~ ^[0-9]+$ ]] || return 1
    [[ "$a_minor" =~ ^[0-9]+$ ]] || a_minor=0
    [[ "$b_major" =~ ^[0-9]+$ ]] || return 1
    [[ "$b_minor" =~ ^[0-9]+$ ]] || b_minor=0
    if [ "$a_major" -gt "$b_major" ]; then return 0; fi
    if [ "$a_major" -eq "$b_major" ] && [ "$a_minor" -gt "$b_minor" ]; then return 0; fi
    return 1
}

check_for_updates() {
    show_banner
    echo -e "${CYAN}$(t upd_title)${NC}"
    echo -e "${GREY}$(tf upd_current_version "$VERSION")${NC}"
    echo ""

    local src_file="$SCRIPT_DIR/update_source.txt"
    if [ ! -f "$src_file" ]; then
        echo -e "${YELLOW}$(t upd_disabled)${NC}"
        pause
        return
    fi

    local url enabled found=0
    while IFS='|' read -r url enabled; do
        [ -z "$url" ] && continue
        case "$url" in \#*) continue ;; esac
        [ "$enabled" != "1" ] && continue
        found=1
        break
    done < "$src_file"

    if [ "$found" -ne 1 ]; then
        echo -e "${YELLOW}$(t upd_disabled)${NC}"
        pause
        return
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}$(t hrc_no_curl)${NC}"
        pause
        return
    fi

    local tmp remote_version remote_link
    tmp="$(mktemp)"
    if ! run_with_spinner "$(t upd_checking) " -- curl -sL -m 15 -o "$tmp" "$url" 2>/dev/null || [ ! -s "$tmp" ]; then
        echo -e "${RED}$(t upd_fetch_failed)${NC}"
        rm -f "$tmp"
        pause
        return
    fi

    remote_version="$(sed -n '1p' "$tmp" | tr -d '[:space:]')"
    remote_link="$(sed -n '2p' "$tmp" | tr -d '\r')"
    rm -f "$tmp"

    if [ -z "$remote_version" ]; then
        echo -e "${RED}$(t upd_fetch_failed)${NC}"
        pause
        return
    fi

    if ! [[ "$remote_version" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        echo -e "${RED}$(t upd_fetch_failed)${NC}"
        pause
        return
    fi

    if _raqib_version_gt "$remote_version" "$VERSION"; then
        echo -e "${GREEN}$(tf upd_available "$remote_version")${NC}"
        [ -n "$remote_link" ] && echo -e "  ${CYAN}${remote_link}${NC}"
    else
        echo -e "${GREEN}$(t upd_up_to_date)${NC}"
    fi
    pause
}
export -f check_for_updates

main_menu() {
    while true; do
        show_banner
        echo -e "${BOLD}$(t menu_prompt)${NC}"
        echo ""
        echo -e "  ${CYAN}1)${NC} $(t cat1)"
        echo -e "  ${CYAN}2)${NC} $(t cat2)"
        echo -e "  ${CYAN}3)${NC} $(t cat3)"
        echo -e "  ${CYAN}4)${NC} $(t cat4)"
        echo -e "  ${CYAN}5)${NC} $(t cat5)"
        echo -e "  ${CYAN}6)${NC} $(t cat6)"
        echo -e "  ${CYAN}7)${NC} $(t cat7)"
        echo -e "  ${CYAN}8)${NC} $(t history_menu_option)"
        echo -e "  ${CYAN}9)${NC} $(t lang_menu_option)"
        echo -e "  ${CYAN}10)${NC} $(t limitations_menu_option)"
        echo -e "  ${CYAN}11)${NC} $(t update_menu_option)"
        echo -e "  ${RED}0)${NC} $(t exit_label)"
        echo ""
        read -rp "  $(t choice_label)" choice
        case $choice in
            1) menu_monitoring ;;
            2) menu_logs ;;
            3) menu_ids_ips ;;
            4) menu_malware ;;
            5) menu_forensics ;;
            6) menu_hardening ;;
            7) menu_vuln_scan ;;
            8) view_scan_history ;;
            9) menu_language ;;
            10) show_known_limitations ;;
            11) check_for_updates ;;
            0) echo -e "${GREEN}$(t goodbye)${NC}"; exit 0 ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1 ;;
        esac
    done
}

show_eagle_intro
main_menu
