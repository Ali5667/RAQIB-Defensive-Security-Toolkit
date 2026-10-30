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
    echo "  - Windows (Git Bash): bash raqib.sh  أو شغّل raqib.bat مباشرة" >&2
    echo "  - Windows (WSL2)    : wsl --install ثم شغّله من لينكس داخل WSL" >&2
    echo "  - macOS: brew install bash   ثم شغّل الأداة بـ:  /opt/homebrew/bin/bash raqib.sh" >&2
    echo "  - Linux: bash --version يفترض يطلع 4+ افتراضياً؛ لو أقدم حدّث الحزمة bash." >&2
    exit 1
fi

VERSION="2.2"
CREATED_DATE="2026-09-01"
LAST_UPDATED="2026-10-14"

# فرض ترميز UTF-8 بغض النظر عن إعدادات النظام — يمنع تقطيع الأحرف العربية
# (كل حرف عربي = عدة بايتات) إلى بايتات منفردة تظهر كرموز مكسّرة/مخربطة،
# خصوصاً بدالة type_line اللي تطبع النص حرف حرف.
if locale -a 2>/dev/null | grep -qi "^C\.utf8$\|^C\.UTF-8$"; then
    export LC_ALL=C.UTF-8
elif locale -a 2>/dev/null | grep -qi "^en_US\.utf8$\|^en_US\.UTF-8$"; then
    export LC_ALL=en_US.UTF-8
fi
export LANG="${LC_ALL:-$LANG}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
TOOLS_DIR="$SCRIPT_DIR/tools"
export SCRIPT_DIR MODULES_DIR TOOLS_DIR VERSION CREATED_DATE LAST_UPDATED

# تحميل وحدات الترجمة والوظائف الأساسية مبكراً لتكون متوفرة في البانر وكل الدوال
source "$MODULES_DIR/common.sh"
source "$MODULES_DIR/lang.sh"
source "$MODULES_DIR/auto_translate.sh"
raqib_load_translation_caches
load_lang

# طبقة الأنظمة متعددة المنصات — تُزرع هنا أيضاً لضمان الرصيد عند تشغيل raqib.sh مباشرة
source "$MODULES_DIR/platform.sh" 2>/dev/null || true

# RAQIB_OS_LABEL — تسمية منصة لطيفة للبانر
raqib_os_label() {
    case "${RAQIB_OS:-unknown}" in
        linux)  echo "Linux" ;;
        wsl)    echo "Windows (WSL2 · ${WSL_DISTRO_NAME:-WSL})" ;;
        darwin) echo "macOS ($(uname -m 2>/dev/null || echo arm))" ;;
        msys)   echo "Windows (Git Bash)" ;;
        cygwin) echo "Windows (Cygwin)" ;;
        *)      echo "Unknown (${OSTYPE:-n/a})" ;;
    esac
}
export -f raqib_os_label

GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
ORANGE=$'\033[38;5;208m'
CRIMSON=$'\033[1;31m'
WHITE=$'\033[1;37m'
GREY=$'\033[1;30m'
BOLD=$'\033[1m'
PURPLE=$'\033[38;5;141m'
NC=$'\033[0m'
export GREEN CYAN YELLOW RED ORANGE CRIMSON WHITE GREY BOLD PURPLE NC

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
    # تشغيل صوت النسر بالخلفية بدون تعطيل الرسوم التفاعلية (يدعم macOS وLinux وWindows/WSL)
    local sound_file="$SCRIPT_DIR/assets/eagle_cry_real.wav"
    if [ -f "$sound_file" ]; then
        if declare -F raqib_play_sound >/dev/null 2>&1; then
            raqib_play_sound "$sound_file"
        elif [ -f "$MODULES_DIR/common.sh" ]; then
            source "$MODULES_DIR/common.sh" 2>/dev/null || true
            declare -F raqib_play_sound >/dev/null 2>&1 && raqib_play_sound "$sound_file"
        fi
    fi
    if (( RANDOM % 2 == 0 )); then
        radar_scan "$SCRIPT_DIR/assets/eagle_logo.txt"
    else
        radar_scan "$SCRIPT_DIR/assets/eagle_logo_2.txt"
    fi
    sleep 1.2
}
export -f show_eagle_intro

# raqib_hijri_date -> يطبع التاريخ الهجري الحالي (يوم/شهر بالاسم/سنة) حسب اللغة المختارة
# باستخدام خوارزمية تحويل جدول-يوليوسي قياسية بدون إنترنت أو مكتبات خارجية.
raqib_hijri_date() {
    local lang="${1:-${LANG_CODE:-ar}}"
    local py_cmd=""
    if python3 -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
        py_cmd="python3"
    elif python -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
        py_cmd="python"
    elif py -3 -c "import sys; sys.exit(0)" >/dev/null 2>&1; then
        py_cmd="py -3"
    else
        echo "—"
        return
    fi

    $py_cmd - "$lang" << 'PYEOF'
import sys, datetime

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

lang = sys.argv[1].lower() if len(sys.argv) > 1 and sys.argv[1] else "ar"

HIJRI_MONTHS = {
    'ar': ['محرم','صفر','ربيع الأول','ربيع الآخر','جمادى الأولى','جمادى الآخرة','رجب','شعبان','رمضان','شوال','ذو القعدة','ذو الحجة'],
    'en': ['Muharram','Safar','Rabi\' al-Awwal','Rabi\' al-Thani','Jumada al-Ula','Jumada al-Akhirah','Rajab','Sha\'ban','Ramadan','Shawwal','Dhu al-Qi\'dah','Dhu al-Hijjah'],
    'fr': ['Mouharram','Safar','Rabi\' al-awwal','Rabi\' ath-thani','Joumada al-oula','Joumada ath-thaniya','Rajab','Cha\'bane','Ramadan','Chawwal','Dhou al-qi\'da','Dhou al-hijja'],
    'es': ['Muharram','Safar','Rabi\' al-Awwal','Rabi\' al-Thani','Yumada al-Wla','Yumada al-Ajira','Rayab','Sha\'ban','Ramadán','Shawwal','Du al-Qa\'da','Du al-Hiyya'],
    'de': ['Muharram','Safar','Rabi\' al-Awwal','Rabi\' ath-Thani','Dschumada l-ula','Dschumada l-achira','Radschab','Scha\'ban','Ramadan','Schawwal','Dhu l-qa\'da','Dhu l-Hiddscha'],
    'tr': ['Muharrem','Safer','Rebiülevvel','Rebiülahir','Cemaziyelevvel','Cemaziyelahir','Recep','Şaban','Ramazan','Şevval','Zilkade','Zilhicce'],
    'fa': ['محرم','صفر','ربیع‌الاول','ربیع‌الثانی','جمادی‌الاول','جمادی‌الثانی','رجب','شعبان','رمضان','شوال','ذی‌القعده','ذی‌الحجه'],
    'ru': ['Мухаррам','Сафар','Раби аль-авваль','Раби ас-сани','Джумада аль-уля','Джумада аль-ахира','Раджаб','Шаабан','Рамадан','Шавваль','Зу-ль-каада','Зу-ль-хиджа'],
    'ku': ['مۆحەڕەم','سەفەر','ڕەبیعولئەووەڵ','ڕەبیعولئاخیر','جومادەلئوولا','جومادەلئاخیرە','ڕەجەب','شەعبان','ڕەمەزان','شەووال','زولقەعدە','زولحیججە'],
    'zh': ['穆哈兰姆月','色法尔月','赖比尔·敖外鲁月','赖比尔·阿色尼月','主马达·敖外鲁月','主马达·阿色尼月','热哲卜月','舍尔邦月','赖买丹月','闪瓦鲁月','都尔喀尔德月','都尔黑哲月'],
    'ur': ['محرم','صفر','ربیع الاول','ربیع الثانی','جمادی الاول','جمادی الثانی','رجب','شعبان','رمضان','شوال','ذوالقعدہ','ذوالحجہ'],
    'pt': ['Muharram','Safar','Rabi al-Awwal','Rabi al-Thani','Jumada al-Awwal','Jumada al-Thani','Rajab','Sha\'ban','Ramadan','Shawwal','Dhu al-Qi\'dah','Dhu al-Hijjah'],
    'id': ['Muharram','Safar','Rabi\'ul Awal','Rabi\'ul Akhir','Jumadil Awal','Jumadil Akhir','Rajab','Sya\'ban','Ramadan','Syawal','Zulkaidah','Zulhijah'],
    'it': ['Muharram','Safar','Rabi\' al-Awwal','Rabi\' al-Thani','Jumada al-Ula','Jumada al-Akhira','Rajab','Sha\'ban','Ramadan','Shawwal','Dhu al-Qi\'da','Dhu al-Hijja'],
    'ja': ['ムハッラム','サファル','ラビー・ウル＝アウワル','ラビー・ウス＝サーニー','ジュマーダー・ル＝ウーラー','ジュマーダー・ス＝サーニー','ラジャブ','シャアバーン','ラマダーン','シャウワール','ズー・ル＝カイダ','ズー・ル＝ヒッジャ'],
    'hi': ['मुहर्रम','सफ़र','रबी उल-अव्वल','रबी उस-सानी','जुमादा अल-अव्वल','जुमादा अल-सानी','रजब','शाबान','रमज़ान','शव्वाल','ज़ुल-क़ादा','ज़ुल-हिज्जा'],
    'nl': ['Moeharram','Safar','Rabi\' al-awwal','Rabi\' al-thani','Djoemada al-awwal','Djoemada al-thani','Radjab','Sja\'ban','Ramadan','Sjawwal','Dhoe al-qi\'da','Dhoe al-hidjdja'],
    'ko': ['무하람','사파르','라비 알아우왈','라비 알사니','주마다 알아우왈','주마다 알사니','라잡','샤아반','라마단','샤왈','두 알카아다','두 알히자'],
    'pl': ['Muharram','Safar','Rabi al-Awwal','Rabi al-Thani','Dżumada al-Ula','Dżumada al-Achira','Radżab','Szaban','Ramadan','Szawwal','Zu al-Kada','Zu al-Hidżdża'],
    'uk': ['Мухаррам','Сафар','Рабі аль-авваль','Рабі ас-сані','Джумада аль-уля','Джумада аль-ахіра','Раджаб','Шаабан','Рамадан','Шавваль','Зуль-каада','Зуль-хіджжа'],
}

def greg_to_jdn(y, m, d):
    a = (14 - m)//12
    y2 = y + 4800 - a
    m2 = m + 12*a - 3
    return d + (153*m2+2)//5 + 365*y2 + y2//4 - y2//100 + y2//400 - 32045

def jdn_to_hijri(jdn):
    l = jdn - 1948440 + 10632
    n = (l-1)//10631
    l = l - 10631*n + 354
    j = ((10985-l)//5316)*((50*l)//17719) + (l//5670)*((43*l)//15238)
    l = l - ((30-j)//15)*((17719*j)//50) - (j//16)*((15238*j)//43) + 29
    hm = (24*l)//709
    hd = l - (709*hm)//24
    hy = 30*n + j - 30
    return hy, hm, hd

now = datetime.date.today()
jdn = greg_to_jdn(now.year, now.month, now.day)
hy, hm, hd = jdn_to_hijri(jdn)

months = HIJRI_MONTHS.get(lang, HIJRI_MONTHS['ar'])
m_name = months[hm - 1]
if lang == 'ar':
    out = f"{hd} {m_name} {hy}هـ"
elif lang == 'ur':
    out = f"{hd} {m_name} {hy} ھ"
elif lang == 'fa':
    out = f"{hd} {m_name} {hy} ق"
elif lang == 'ku':
    out = f"{hd}ی {m_name}ی {hy}ک"
elif lang == 'tr':
    out = f"{hd} {m_name} {hy} H"
elif lang in ('zh', 'ja'):
    out = f"{m_name}{hd}日, {hy}年"
elif lang == 'ko':
    out = f"{hy}년 {m_name} {hd}일"
elif lang in ('es', 'pt'):
    out = f"{hd} de {m_name} de {hy} AH"
elif lang == 'de':
    out = f"{hd}. {m_name} {hy} d.H."
elif lang == 'ru':
    out = f"{hd} {m_name} {hy} г.х."
elif lang == 'uk':
    out = f"{hd} {m_name} {hy} р.х."
elif lang == 'hi':
    out = f"{hd} {m_name} {hy} हिजरी"
elif lang == 'id':
    out = f"{hd} {m_name} {hy} H"
elif lang == 'it':
    out = f"{hd} {m_name} {hy} d.E."
elif lang == 'nl':
    out = f"{hd} {m_name} {hy} n.H."
else:
    out = f"{hd} {m_name} {hy} AH"

print(out)
PYEOF
}
export -f raqib_hijri_date


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
    echo -e "  ${BOLD}${CYAN}RAQIB (رقيب) — $(t subtitle) v${VERSION}${NC}"
    echo -e "  Rapid Audit & Quick Incident-response Bash-toolkit"

    local cur_time greg_dt hijri_dt created_fmt updated_fmt
    cur_time="$(date '+%H:%M:%S')"
    greg_dt="$(raqib_gregorian_date "${LANG_CODE:-ar}")"
    hijri_dt="$(raqib_hijri_date "${LANG_CODE:-ar}" 2>/dev/null || echo '—')"
    created_fmt="$(raqib_gregorian_date "${LANG_CODE:-ar}" "${CREATED_DATE:-2026-09-01}")"
    updated_fmt="$(raqib_gregorian_date "${LANG_CODE:-ar}" "${LAST_UPDATED:-2026-10-14}")"

    echo -e "  📅 ${greg_dt}   |   ⏰ ${cur_time}   |   🕌 ${hijri_dt}"
    echo -e "  ${GREY}--------------------------------------------------------------------------------${NC}"

    local op_name="${RAQIB_OPERATOR:-Operator Active}"
    local op_role="${RAQIB_OPERATOR_ROLE:-Senior}"
    op_role="$(tr '[:lower:]' '[:upper:]' <<< "${op_role:0:1}")${op_role:1}"
    local siem_state="Active"
    [ ! -s "${RAQIB_EVENTS_FILE:-.raqib_events.jsonl}" ] && siem_state="Standby"

    printf "  ${YELLOW}[+] Author  :${NC} %-30s ${YELLOW}[+] Created :${NC} %s\n" "Ali Alnuaimi (@Ali5667)" "$created_fmt"
    printf "  ${YELLOW}[+] GitHub  :${NC} %-30s ${YELLOW}[+] Updated :${NC} %s (v${VERSION})\n" "https://github.com/Ali5667" "$updated_fmt"
    printf "  ${YELLOW}[+] Twitter :${NC} %-30s ${YELLOW}[+] Session :${NC} ${GREEN}%s (%s)${NC}\n" "@ali_cys45" "$op_name" "$op_role"
    printf "  ${YELLOW}[+] SIEM    :${NC} %s\n" ".raqib_events.jsonl (${siem_state})"
    printf "  ${YELLOW}[+] Platform:${NC} %s\n" "$(raqib_os_label 2>/dev/null || echo "${RAQIB_OS:-Linux}")"
    echo -e "  ${GREY}--------------------------------------------------------------------------------${NC}"
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

# show_live_clock -> شاشة تفاعلية كاملة للساعة الحية ورادار الوقت والدفاع
show_live_clock() {
    local key=""
    local greg_dt hijri_dt created_fmt updated_fmt
    local cur_time host_str uptime_str
    local op_name="${RAQIB_OPERATOR:-Operator Active}"
    local op_role="${RAQIB_OPERATOR_ROLE:-Senior}"
    local siem_file="${RAQIB_EVENTS_FILE:-.raqib_events.jsonl}"
    local siem_count=0

    # إخفاء المؤشر أثناء عرض شاشة الساعة الحية
    printf "\033[?25l"
    trap 'printf "\033[?25h"' RETURN INT TERM

    # حساب التواريخ الثابتة واسم المضيف مرة واحدة في البداية لمنع استهلاك المعالج والوميض
    greg_dt="$(raqib_gregorian_date "${LANG_CODE:-ar}")"
    hijri_dt="$(raqib_hijri_date "${LANG_CODE:-ar}" 2>/dev/null || echo '—')"
    created_fmt="$(raqib_gregorian_date "${LANG_CODE:-ar}" "${CREATED_DATE:-2026-09-01}")"
    updated_fmt="$(raqib_gregorian_date "${LANG_CODE:-ar}" "${LAST_UPDATED:-2026-10-14}")"
    host_str="$(hostname 2>/dev/null || echo "$HOSTNAME")"

    clear
    while true; do
        cur_time="$(date '+%H:%M:%S')"
        uptime_str="$(uptime 2>/dev/null | sed 's/^[ \t]*//' || echo "Active")"
        if [ -s "$siem_file" ]; then
            siem_count="$(wc -l < "$siem_file" 2>/dev/null || echo 0)"
        else
            siem_count=0
        fi

        # إعادة المؤشر لأعلى الشاشة بدون مسح كامل لمنع الوميض
        printf "\033[H"
        echo -e "${GREEN}"
        cat << "EOF"
  ____      _    ___ ___ ____    _     _____     _______ 
 |  _ \    / \  / _ \_ _| __ )  | |   |_ _\ \   / / ____|
 | |_) |  / _ \| | | | ||  _ \  | |    | | \ \ / /|  _|  
 |  _ <  / ___ \ |_| | || |_) | | |___ | |  \ V / | |___ 
 |_| \_\/_/   \_\__\_\___|____/  |_____|___|  \_/  |_____|
EOF
        echo -e "${NC}"
        echo -e "  ${BOLD}${CYAN}RAQIB (رقيب) — $(t live_clock_title)${NC}"
        echo -e "  ${GREY}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""

        # رسم الوقت الرقمي بالساعة والدقيقة والثانية بنمط 7-Segment أنيق
        local r0="" r1="" r2=""
        for (( i=0; i<${#cur_time}; i++ )); do
            local ch="${cur_time:$i:1}"
            case "$ch" in
                0) r0+=" _  "; r1+="| | "; r2+="|_| " ;;
                1) r0+="    "; r1+="  | "; r2+="  | " ;;
                2) r0+=" _  "; r1+=" _| "; r2+="|_  " ;;
                3) r0+=" _  "; r1+=" _| "; r2+=" _| " ;;
                4) r0+="    "; r1+="|_| "; r2+="  | " ;;
                5) r0+=" _  "; r1+="|_  "; r2+=" _| " ;;
                6) r0+=" _  "; r1+="|_  "; r2+="|_| " ;;
                7) r0+=" _  "; r1+="  | "; r2+="  | " ;;
                8) r0+=" _  "; r1+="|_| "; r2+="|_| " ;;
                9) r0+=" _  "; r1+="|_| "; r2+=" _| " ;;
                :) r0+="   "; r1+=" ● "; r2+=" ● " ;;
                *) r0+="   "; r1+="   "; r2+="   " ;;
            esac
        done

        echo -e "         ${BOLD}${YELLOW}${r0}${NC}"
        echo -e "         ${BOLD}${YELLOW}${r1}${NC}"
        echo -e "         ${BOLD}${YELLOW}${r2}${NC}"
        echo -e "                  ${CYAN}● LIVE UTC+LOCAL TICKING ●${NC}"
        echo ""
        echo -e "  ${GREY}────────────────────────────────────────────────────────────────────────────────${NC}"
        echo -e "  📅 ${WHITE}$(t lc_gregorian):${NC}  ${GREEN}${greg_dt}${NC}"
        echo -e "  🕌 ${WHITE}$(t lc_hijri):${NC}      ${GREEN}${hijri_dt}${NC}"
        echo -e "  🚀 ${WHITE}$(t lc_created):${NC}    ${CYAN}${created_fmt}${NC}"
        echo -e "  🔄 ${WHITE}$(t lc_updated):${NC}    ${CYAN}${updated_fmt}${NC}  ${GREY}(v${VERSION})${NC}"
        echo -e "  ${GREY}────────────────────────────────────────────────────────────────────────────────${NC}"
        echo -e "  👤 ${YELLOW}[+] Operator:${NC}  ${op_name} (${op_role})"
        echo -e "  💻 ${YELLOW}[+] Host:${NC}      ${host_str}"
        echo -e "  📊 ${YELLOW}[+] SIEM Logs:${NC} ${siem_count} events recorded"
        echo -e "  ⏱️  ${YELLOW}[+] System:${NC}    ${uptime_str}"
        echo -e "  ${GREY}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo -e "  ${YELLOW}$(t lc_press_exit)${NC}      "

        if IFS= read -r -s -n 1 -t 1 key 2>/dev/null; then
            break
        fi
    done
    printf "\033[?25h"
    clear
}
export -f show_live_clock

source "$MODULES_DIR/monitoring.sh"
source "$MODULES_DIR/logs.sh"
source "$MODULES_DIR/ids_ips.sh"
source "$MODULES_DIR/malware.sh"
source "$MODULES_DIR/forensics.sh"
source "$MODULES_DIR/hardening.sh"
source "$MODULES_DIR/vuln_scan.sh"
source "$TOOLS_DIR/ctf/ctf_menu.sh" 2>/dev/null || true

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
    if command -v python3 >/dev/null 2>&1 && [ -f "$MODULES_DIR/raqib_updater.py" ]; then
        python3 "$MODULES_DIR/raqib_updater.py"
        pause
        return
    fi

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
        echo -e "${BOLD}Choose a defensive category / اختر الفئة الأمنية للدفاع:${NC}"
        echo ""
        if [ "${LANG_CODE:-ar}" = "ar" ]; then
            echo -e "  ${CYAN} 1)${NC} 🛰️  مراقبة الشبكة                     ${CYAN}(12 tools - PortScan, ARP, SIEM, Collector)${NC}"
            echo -e "  ${CYAN} 2)${NC} 📋  تحليل السجلات                     ${CYAN}(5 tools  - SSH Brute, Keyword, Timeline, Web)${NC}"
            echo -e "  ${CYAN} 3)${NC} 🚨  كشف التسلل والتهديدات             ${CYAN}(6 tools  - FIM, Cron Auditor, IP Blocker)${NC}"
            echo -e "  ${CYAN} 4)${NC} 🦠  تحليل الملفات المشبوهة            ${CYAN}(13 tools - YARA-Lite, Threat Intel, Rootkit)${NC}"
            echo -e "  ${CYAN} 5)${NC} 🔍  الطب الشرعي الرقمي                ${CYAN}(6 tools  - Email Header, Sudo, History)${NC}"
            echo -e "  ${CYAN} 6)${NC} 🛡️  تقوية الأنظمة                     ${CYAN}(8 tools  - Permissions, SSH, Encrypted Reports)${NC}"
            echo -e "  ${CYAN} 7)${NC} 🎯  فحص الثغرات والصلاحيات            ${CYAN}(5 tools  - Port CVEs, Outdated Pkgs, SSL)${NC}"
            echo -e "  ${CYAN} 8)${NC} 🏴  وضع التحديات (CTF / Wargames)     ${PURPLE}(22 tools - Crypto, Stego, Forensics, Web, Binary)${NC}"
            echo -e "  ${CYAN} 9)${NC} 📜  سجل الفحوصات الأخيرة              ${GREY}(Last 10 generated audit reports)${NC}"
            echo -e "  ${CYAN}10)${NC} 🌐  تغيير اللغة                       ${GREY}(20 fully supported languages)${NC}"
            echo -e "  ${CYAN}11)${NC} ⚠️  حدود معروفة بالأداة               ${GREY}(Transparency & technical boundaries)${NC}"
            echo -e "  ${CYAN}12)${NC} 🔄  التحقق من التحديثات               ${GREY}(Passive GitHub release check)${NC}"
            echo -e "  ${CYAN}13)${NC} ⏰  الساعة الحية ورادار الوقت            ${GREEN}(Live Digital Clock, Dates & Uptime)${NC}"
            echo -e "  ${RED} 0)${NC} 🚪  خروج                              ${RED}(Clean session shutdown)${NC}"
        else
            echo -e "  ${CYAN} 1)${NC} 🛰️  Network Monitoring               ${CYAN}(12 tools - PortScan, ARP, SIEM, Collector)${NC}"
            echo -e "  ${CYAN} 2)${NC} 📋  Log Analysis                      ${CYAN}(5 tools  - SSH Brute, Keyword, Timeline, Web)${NC}"
            echo -e "  ${CYAN} 3)${NC} 🚨  Intrusion & Threat Detection      ${CYAN}(6 tools  - FIM, Cron Auditor, IP Blocker)${NC}"
            echo -e "  ${CYAN} 4)${NC} 🦠  Suspicious File Analysis          ${CYAN}(13 tools - YARA-Lite, Threat Intel, Rootkit)${NC}"
            echo -e "  ${CYAN} 5)${NC} 🔍  Digital Forensics                 ${CYAN}(6 tools  - Email Header, Sudo, History)${NC}"
            echo -e "  ${CYAN} 6)${NC} 🛡️  System Hardening                  ${CYAN}(8 tools  - Permissions, SSH, Encrypted Reports)${NC}"
            echo -e "  ${CYAN} 7)${NC} 🎯  Vulnerability & Permission Scan   ${CYAN}(5 tools  - Port CVEs, Outdated Pkgs, SSL)${NC}"
            echo -e "  ${CYAN} 8)${NC} 🏴  CTF / Wargames Mode               ${PURPLE}(22 tools - Crypto, Stego, Forensics, Web, Binary)${NC}"
            echo -e "  ${CYAN} 9)${NC} 📜  View Scan History                 ${GREY}(Last 10 generated audit reports)${NC}"
            echo -e "  ${CYAN}10)${NC} 🌐  Change Language                   ${GREY}(20 fully supported languages)${NC}"
            echo -e "  ${CYAN}11)${NC} ⚠️  Known Limitations                 ${GREY}(Transparency & technical boundaries)${NC}"
            echo -e "  ${CYAN}12)${NC} 🔄  Check for Updates                 ${GREY}(Passive GitHub release check)${NC}"
            echo -e "  ${CYAN}13)${NC} ⏰  Live Defense Clock & Telemetry        ${GREEN}(Live Digital Clock, Dates & Uptime)${NC}"
            echo -e "  ${RED} 0)${NC} 🚪  Exit RAQIB                        ${RED}(Clean session shutdown)${NC}"
        fi
        echo ""
        local choice
        if [ "${LANG_CODE:-ar}" = "ar" ]; then
            read -rp "  ${BOLD}${YELLOW}اختر [0-13]: ${NC}" choice
        else
            read -rp "  ${BOLD}${YELLOW}Choice [0-13]: ${NC}" choice
        fi
        case "$choice" in
            1) menu_monitoring ;;
            2) menu_logs ;;
            3) menu_ids_ips ;;
            4) menu_malware ;;
            5) menu_forensics ;;
            6) menu_hardening ;;
            7) menu_vuln_scan ;;
            8) menu_ctf_main ;;
            9) view_scan_history ;;
            10) menu_language ;;
            11) show_known_limitations ;;
            12) check_for_updates ;;
            13|c|C|clock|time|ساعة) show_live_clock ;;
            0) echo -e "${GREEN}$(t goodbye)${NC}"; exit 0 ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1 ;;
        esac
    done
}

if [ -z "${BASH_SOURCE[0]}" ] || [ "${BASH_SOURCE[0]}" = "$0" ]; then
    # دعم الأوامر المباشرة من سطر الأوامر (Non-interactive CLI dispatch)
    if [ "$#" -gt 0 ]; then
        case "$1" in
            update)
                shift
                python3 "$RAQIB_INTEL_SCRIPT" update "$@"
                exit $?
                ;;
            lookup|search)
                shift
                python3 "$RAQIB_INTEL_SCRIPT" lookup "$@"
                exit $?
                ;;
            intel|intelligence)
                shift
                python3 "$RAQIB_INTEL_SCRIPT" "$@"
                exit $?
                ;;
            --help|-h)
                echo "Usage: ./raqib.sh [update|lookup|intel] [options]"
                echo "       ./raqib.sh update --source feodo|attack|all"
                echo "       ./raqib.sh lookup <IP>"
                echo "       ./raqib.sh                  (interactive UI)"
                exit 0
                ;;
        esac
    fi

    # لو أول مرة يشغل الأداة (ملف اللغة مو موجود)، طلع له قائمة اللغات
    if [ ! -f "$RAQIB_LANG_FILE" ]; then
        menu_language
    fi

    raqib_login_attempts=0
    until raqib_operator_login; do
        raqib_login_attempts=$((raqib_login_attempts + 1))
        if [ "$raqib_login_attempts" -ge 3 ]; then
            echo -e "${RED}$(t op_too_many_attempts)${NC}"
            exit 1
        fi
    done

    show_eagle_intro
    main_menu
fi

