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

if declare -F raqib_color_enabled >/dev/null 2>&1 && ! raqib_color_enabled; then
    GREEN="" CYAN="" YELLOW="" RED="" ORANGE="" CRIMSON=""
    WHITE="" GREY="" BOLD="" PURPLE="" NC=""
else
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
fi
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

# تسلسل إقلاع قصير تحت شعار النسر — يظهر في strong و cinematic فقط.
raqib_boot_sequence() {
    local level="none"
    if declare -F raqib_fx_level_cache >/dev/null 2>&1; then
        raqib_fx_level_cache
        level="${_RAQIB_FX_LEVEL:-none}"
    fi
    [ "$level" = "none" ] && return 0
    echo ""
    if [ "$level" = "cinematic" ] && declare -F fx_glitch_line >/dev/null 2>&1; then
        fx_glitch_line "RAQIB // DEFENSE GRID :: BOOT"
    else
        echo -e "  ${CYAN}RAQIB // DEFENSE GRID :: BOOT${NC}"
    fi
    local -a steps
    if [ "$level" = "cinematic" ]; then
        steps=(
            "core defense modules ............... armed"
            "YARA-lite + heuristic engines ...... online"
            "SIEM telemetry link ................ active"
            "operator session ................... authenticated"
        )
    else
        steps=(
            "defense modules .................... armed"
            "detection engines .................. online"
            "telemetry link .................... active"
        )
    fi
    local s
    for s in "${steps[@]}"; do
        printf "  %s[ OK ]%s %s%s%s\n" "$GREEN" "$NC" "$GREY" "$s" "$NC"
        raqib_fx_sleep 0.04
    done
}
export -f raqib_boot_sequence

show_eagle_intro() {
    raqib_clear
    # عند إطفاء المؤثرات (أو تشغيل غير تفاعلي) نتجاوز الأنترو كاملاً
    if declare -F raqib_fx_ok >/dev/null 2>&1 && ! raqib_fx_ok; then
        return 0
    fi
    # مطر Matrix خفيف قبل شعار النسر (cinematic فقط)
    if declare -F fx_matrix_rain >/dev/null 2>&1; then
        fx_matrix_rain 54 4
    fi
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
    if declare -F raqib_boot_sequence >/dev/null 2>&1; then
        raqib_boot_sequence
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


# ─────────────────────────────────────────────────────────────
#  الشعار الموحّد — كلمة RAQIB مبنية حرفاً حرفاً، وكل حرف بلون
#  مختلف (سماوي → أزرق → بنفسجي) مع أشرطة بيانات جانبية.
#  الوسيط الأول اختياري: رقم صف 0-5 لإبراز صف أثناء خط المسح.
#  يُستخدم بالبنر الرئيسي وشاشة الساعة الحية، مع بديل ASCII تلقائي
#  إذا كانت الطرفية ما تدعم UTF-8 (حتى ما ينكسر الشكل بأي بيئة).
# ─────────────────────────────────────────────────────────────
raqib_print_logo() {
    local highlight="${1:-}"
    local utf8=0
    case "${LC_ALL:-${LANG:-}}" in
        *UTF-8*|*utf-8*|*utf8*|*UTF8*) utf8=1 ;;
    esac
    if [ "$utf8" -ne 1 ]; then
        cat << 'EOF'
  ##   ____      _    ___ ___ ____   ##
  ##  |  _ \    / \  / _ \_ _| __ )  ##
  ##  | |_) |  / _ \| | | | ||  _ \  ##
  ##  |  _ <  / ___ \ |_| | || |_) | ##
  ##  |_| \_\/_/   \_\__\_\___|____/ ##
EOF
        return 0
    fi
    # كل حرف مقسّم لصفوف منفصلة بنفس عرضه، حتى نلوّن كل حرف لحاله
    # ونحافظ على المحاذاة العمودية تماماً.
    local -a gR gA gQ gI gB
    gR=( '██████╗ ' '██╔══██╗' '██████╔╝' '██╔══██╗' '██║  ██║' '╚═╝  ╚═╝' )
    gA=( ' █████╗ ' '██╔══██╗' '███████║' '██╔══██║' '██║  ██║' '╚═╝  ╚═╝' )
    gQ=( ' ██████╗ ' '██╔═══██╗' '██║   ██║' '██║▄▄ ██║' '╚██████╔╝' ' ╚══▀▀═╝ ' )
    gI=( '██╗' '██║' '██║' '██║' '██║' '╚═╝' )
    gB=( '██████╗ ' '██╔══██╗' '██████╔╝' '██╔══██╗' '██████╔╝' '╚═════╝ ' )

    local cR=$'\033[1;36m' cA=$'\033[38;5;51m' cQ=$'\033[38;5;75m'
    local cI=$'\033[38;5;105m' cB=$'\033[38;5;141m'
    local railL=$'\033[38;5;30m' railR=$'\033[38;5;37m' railHot=$'\033[1;36m'
    if declare -F raqib_color_enabled >/dev/null 2>&1 && ! raqib_color_enabled; then
        # خرج معاد توجيهه/NO_COLOR: نفس الشعار بدون أي أكواد تحكم
        local p
        for p in 0 1 2 3 4 5; do
            printf '  ░▒▓█  %s%s%s%s%s  █▓▒░\n' "${gR[$p]}" "${gA[$p]}" "${gQ[$p]}" "${gI[$p]}" "${gB[$p]}"
        done
        return 0
    fi
    local i row
    for i in 0 1 2 3 4 5; do
        if [ "$highlight" = "$i" ]; then
            row="${WHITE}${gR[$i]}${gA[$i]}${gQ[$i]}${gI[$i]}${gB[$i]}${NC}"
            printf '  %s░▒▓█%s  %s  %s█▓▒░%s\n' "$railHot" "$NC" "$row" "$railHot" "$NC"
        else
            # الحروف تتلاصق كما في خط ANSI Shadow الأصلي — كل حرف بلونه
            row="${cR}${gR[$i]}${NC}${cA}${gA[$i]}${NC}${cQ}${gQ[$i]}${NC}${cI}${gI[$i]}${NC}${cB}${gB[$i]}${NC}"
            printf '  %s░▒▓█%s  %s  %s█▓▒░%s\n' "$railL" "$NC" "$row" "$railR" "$NC"
        fi
    done
}
export -f raqib_print_logo

# شرائط زخرفية جاهزة (بدون spawn ولا حلقات وقت العرض)
_RAQIB_RULE11="▬▬▬▬▬▬▬▬▬▬▬"
_RAQIB_RULE12="▬▬▬▬▬▬▬▬▬▬▬▬"
_RAQIB_RULE24="────────────────────────"
_RAQIB_RULE25="─────────────────────────"

# تاج الشعار — إطار علوي بعرض 50 عموداً بالضبط، بتدرّج متماثل
raqib_logo_crown() {
    local utf8=0
    case "${LC_ALL:-${LANG:-}}" in
        *UTF-8*|*utf-8*|*utf8*|*UTF8*) utf8=1 ;;
    esac
    if [ "$utf8" -ne 1 ]; then
        printf '  +------------------------------------------------+\n'
        return 0
    fi
    local c1=$'\033[1;36m' c2=$'\033[38;5;75m' c3=$'\033[38;5;141m'
    if declare -F raqib_color_enabled >/dev/null 2>&1 && ! raqib_color_enabled; then
        c1="" c2="" c3=""
    fi
    printf '  %s◤%s%s%s%s%s%s%s%s%s%s◥%s\n' \
        "$c1" "$_RAQIB_RULE11" "$c2" "$_RAQIB_RULE12" "$WHITE" "◈" \
        "$c2" "$_RAQIB_RULE12" "$c3" "$_RAQIB_RULE12" "$NC"
}
export -f raqib_logo_crown

# قاعدة الشعار — مرآة التاج، بنفس العرض
raqib_logo_base() {
    local utf8=0
    case "${LC_ALL:-${LANG:-}}" in
        *UTF-8*|*utf-8*|*utf8*|*UTF8*) utf8=1 ;;
    esac
    if [ "$utf8" -ne 1 ]; then
        printf '  +------------------------------------------------+\n'
        return 0
    fi
    local c1=$'\033[1;36m' c2=$'\033[38;5;75m' c3=$'\033[38;5;141m'
    if declare -F raqib_color_enabled >/dev/null 2>&1 && ! raqib_color_enabled; then
        c1="" c2="" c3=""
    fi
    printf '  %s◣%s%s%s%s%s%s%s%s%s%s◢%s\n' \
        "$c3" "$_RAQIB_RULE11" "$c2" "$_RAQIB_RULE12" "$WHITE" "◈" \
        "$c2" "$_RAQIB_RULE12" "$c1" "$_RAQIB_RULE12" "$NC"
}
export -f raqib_logo_base

# فاصل رفيع بعرض 50 عموداً مع معيّن في الوسط
raqib_logo_rule() {
    local utf8=0
    case "${LC_ALL:-${LANG:-}}" in
        *UTF-8*|*utf-8*|*utf8*|*UTF8*) utf8=1 ;;
    esac
    if [ "$utf8" -ne 1 ]; then
        printf '  %s--------------------------------------------------%s\n' "$GREY" "$NC"
        return 0
    fi
    printf '  %s%s%s%s%s%s%s\n' "$GREY" "$_RAQIB_RULE24" "$CYAN" "◈" "$GREY" "$_RAQIB_RULE25" "$NC"
}
export -f raqib_logo_rule

# يحرّك صف إضاءة فوق الشعار (مسح رأسي) حسب مستوى المؤثرات:
# light: بدون حركة | strong: لقطتان | cinematic: مسح كامل.
raqib_logo_animated() {
    local level="strong"
    if declare -F raqib_fx_level_cache >/dev/null 2>&1; then
        raqib_fx_level_cache
        level="${_RAQIB_FX_LEVEL:-none}"
    fi
    if [ "$level" = "none" ] || [ "$level" = "light" ] || ! raqib_fx_utf8 2>/dev/null; then
        raqib_print_logo
        return 0
    fi
    local -a rows
    if [ "$level" = "cinematic" ]; then
        rows=(0 1 2 3 4 5)
    else
        rows=(2 4)
    fi
    raqib_print_logo "${rows[0]}"
    raqib_fx_sleep 0.05
    local i r
    for ((i = 1; i < ${#rows[@]}; i++)); do
        r="${rows[$i]}"
        printf '\033[6A\r'
        raqib_print_logo "$r"
        raqib_fx_sleep 0.05
    done
    printf '\033[6A\r'
    raqib_print_logo
}
export -f raqib_logo_animated

# مستخدمة من show_eagle_intro (مرة وحدة بالبداية) ومن show_banner (كل رجعة للقائمة الرئيسية).
print_banner_info() {
    # كاش عناوين البانر حسب اللغة — 9 استدعاءات مرة واحدة فقط لكل لغة
    if [ "${_RAQIB_BANNER_LBL_LANG:-}" != "${LANG_CODE:-ar}" ]; then
        _RAQIB_BANNER_LBL_LANG="${LANG_CODE:-ar}"
        if declare -F t >/dev/null 2>&1; then
            _RAQIB_L_PLATFORM="$(t lbl_platform)"
            _RAQIB_L_DATE="$(t lbl_date)"
            _RAQIB_L_HIJRI="$(t lbl_hijri)"
            _RAQIB_L_SIEM="$(t lbl_siem)"
            _RAQIB_L_OPERATOR="$(t lbl_operator)"
            _RAQIB_L_AUTHOR="$(t lbl_author)"
            _RAQIB_L_UPDATED="$(t lbl_updated)"
            _RAQIB_L_TAGLINE="$(t lbl_tagline)"
            _RAQIB_L_STATUS="$(t lbl_status)"
        fi
    fi
    local lbl_platform="${_RAQIB_L_PLATFORM:-Platform}" lbl_date="${_RAQIB_L_DATE:-Date}"
    local lbl_hijri="${_RAQIB_L_HIJRI:-Hijri}" lbl_siem="${_RAQIB_L_SIEM:-SIEM}"
    local lbl_operator="${_RAQIB_L_OPERATOR:-Operator}" lbl_author="${_RAQIB_L_AUTHOR:-Author}"
    local lbl_updated="${_RAQIB_L_UPDATED:-Updated}" lbl_tagline="${_RAQIB_L_TAGLINE:-Rapid Audit & Quick Incident-response Bash-toolkit}"
    local lbl_status="${_RAQIB_L_STATUS:-DEFENSE GRID ONLINE}"

    # التاج + الشعار (مسح رأسي) + القاعدة — إطار واحد متماسك
    if declare -F raqib_logo_crown >/dev/null 2>&1; then
        raqib_logo_crown
    fi
    if declare -F raqib_logo_animated >/dev/null 2>&1; then
        raqib_logo_animated
    else
        raqib_print_logo
    fi
    if declare -F raqib_logo_base >/dev/null 2>&1; then
        raqib_logo_base
    fi
    echo ""
    # زخارف سطر التوقيع: بديل ASCII إذا كانت الطرفية لا تدعم UTF-8
    local tag_l="◢◤" tag_r="◥◣" tag_sep="·" dotsep="·" utf8=0
    case "${LC_ALL:-${LANG:-}}" in
        *UTF-8*|*utf-8*|*utf8*|*UTF8*) utf8=1 ;;
        *) tag_l="<<"; tag_r=">>"; tag_sep="|"; dotsep="|" ;;
    esac
    echo -e "   ${PURPLE}${tag_l}${NC}  ${ORANGE}رقيب${NC} ${GREY}${tag_sep}${NC} ${BOLD}${WHITE}RAQIB${NC} ${GREY}${tag_sep}${NC} ${CYAN}$(t subtitle)${NC}  ${PURPLE}${tag_r}${NC}  ${GREY}v${VERSION}${NC}"
    echo -e "      ${GREY}${lbl_tagline}${NC}"

    local cur_time greg_dt hijri_dt updated_fmt
    # الوقت/التاريخ عبر printf المدمج في Bash 4.2+ (بدون spawn لأمر date).
    # على macOS (Bash 3.2) نرتد إلى date مرة واحدة فقط.
    local _now _today
    if [ "${BASH_VERSINFO[0]:-0}" -gt 4 ] || { [ "${BASH_VERSINFO[0]:-0}" -eq 4 ] && [ "${BASH_VERSINFO[1]:-0}" -ge 2 ]; }; then
        printf -v cur_time '%(%H:%M:%S)T' -1
        printf -v _today '%(%F)T' -1
    else
        _now="$(date '+%H:%M:%S|%F')"
        cur_time="${_now%%|*}"
        _today="${_now#*|}"
    fi
    # كاش تواريخ البانر: تتغير يومياً فقط، فنحسبها مرة واحدة لكل لغة/يوم.
    # يوفّر ~1.5 ثانية بكل رجوع للقائمة على Git Bash (حساب الهجري ببايثون).
    local _date_key="${LANG_CODE:-ar}:${_today}"
    if [ "${_RAQIB_BANNER_DATE_KEY:-}" = "$_date_key" ]; then
        greg_dt="${_RAQIB_BANNER_GREG:-}"
        hijri_dt="${_RAQIB_BANNER_HIJRI:-}"
        updated_fmt="${_RAQIB_BANNER_UPDATED:-}"
    else
        greg_dt="$(raqib_gregorian_date "${LANG_CODE:-ar}")"
        hijri_dt="$(raqib_hijri_date "${LANG_CODE:-ar}" 2>/dev/null || echo '—')"
        updated_fmt="$(raqib_gregorian_date "${LANG_CODE:-ar}" "${LAST_UPDATED:-2026-10-14}")"
        _RAQIB_BANNER_DATE_KEY="$_date_key"
        _RAQIB_BANNER_GREG="$greg_dt"
        _RAQIB_BANNER_HIJRI="$hijri_dt"
        _RAQIB_BANNER_UPDATED="$updated_fmt"
    fi

    local op_name="${RAQIB_OPERATOR:-Operator Active}"
    local op_role="${RAQIB_OPERATOR_ROLE:-Senior}"
    # بدون tr خارجي — أول حرف يبقى كما هو (القيمة الافتراضية Senior أصلاً)
    op_role="${op_role:0:1}${op_role:1}"
    local siem_file="${RAQIB_EVENTS_FILE:-.raqib_events.jsonl}"
    local siem_dot="○" siem_color="$GREY" siem_events=0
    [ "$utf8" -ne 1 ] && siem_dot="o"
    if [ -s "$siem_file" ]; then
        if [ "$utf8" -eq 1 ]; then siem_dot="●"; else siem_dot="*"; fi
        siem_color="$GREEN"
        siem_events="$(wc -l < "$siem_file" 2>/dev/null)"
        siem_events="${siem_events// /}"
        [ -z "$siem_events" ] && siem_events=0
    fi
    local os_label
    os_label="$(raqib_os_label 2>/dev/null || echo "${RAQIB_OS:-Linux}")"

    printf "  ${YELLOW}%s${NC}: %s  ${GREY}|${NC}  ${WHITE}%s${NC}\n" "$lbl_platform" "$os_label" "$cur_time"
    printf "  ${YELLOW}%s${NC}: %s\n" "$lbl_date" "$greg_dt"
    printf "  ${YELLOW}%s${NC}: %s\n" "$lbl_hijri" "$hijri_dt"
    printf "  ${YELLOW}%s${NC}: %s%s%s %s ${dotsep} %s\n" "$lbl_siem" "$siem_color" "$siem_dot" "$NC" "$siem_events" "${siem_file##*/}"
    printf "  ${YELLOW}%s${NC}: %s ${GREY}(%s)${NC}\n" "$lbl_operator" "$op_name" "$op_role"
    printf "  ${YELLOW}%s${NC}: %s\n" "$lbl_author" "Ali Alnuaimi (@Ali5667) ${dotsep} github.com/Ali5667 ${dotsep} x.com/ali_cys45"
    printf "  ${YELLOW}%s${NC}: ${GREEN}v${VERSION}${NC} ${dotsep} %s\n" "$lbl_updated" "$updated_fmt"
    if declare -F raqib_logo_rule >/dev/null 2>&1; then
        raqib_logo_rule
    else
        echo -e "  ${GREY}──────────────────────────────────────────────────${NC}"
    fi
    if declare -F fx_status_line >/dev/null 2>&1; then
        fx_status_line "${lbl_status} ${dotsep} ${os_label} ${dotsep} v${VERSION}"
    else
        echo -e "  ${GREEN}●${NC} ${GREY}${lbl_status}${NC}"
    fi
    echo ""
}
export -f print_banner_info

show_banner() {
    raqib_clear
    # خط مسح سريع فوق البنر — حركة بصرية خفيفة بكل انتقال بين القوائم
    if declare -F fx_scanline >/dev/null 2>&1; then
        fx_scanline 50
    fi
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

    raqib_clear
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
        raqib_print_logo
        echo ""
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
    raqib_clear
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
        # أسماء الفئات تتبع اللغة المختارة — تُحمّل مرة واحدة لكل لغة
        if [ "${_RAQIB_MAINMENU_LANG:-}" != "${LANG_CODE:-ar}" ]; then
            _RAQIB_MAINMENU_LANG="${LANG_CODE:-ar}"
            _RAQIB_MM_NAMES=(
                "$(t cat1)" "$(t cat2)" "$(t cat3)" "$(t cat4)"
                "$(t cat5)" "$(t cat6)" "$(t cat7)" "$(t cat8)"
                "$(t cat9)" "$(t cat10)" "$(t cat11)" "$(t cat12)"
                "$(t cat13)" "$(t menu_exit)"
            )
            _RAQIB_MM_PROMPT="$(t menu_prompt)"
            _RAQIB_MM_CHOICE="$(t menu_choice_range)"
        fi
        _RAQIB_MM_DESC=(
            "12 tools · PortScan, ARP, SIEM, Collector"
            "5 tools · SSH Brute, Keyword, Timeline, Web"
            "6 tools · FIM, Cron Auditor, IP Blocker"
            "13 tools · YARA-Lite, Threat Intel, Rootkit"
            "7 tools · Email Header, Advanced, Sudo, History"
            "9 tools · Permissions, SSH, Windows Defense"
            "6 tools · Port CVEs, Outdated Pkgs, Secrets"
            "23 tools · Crypto, Stego, Forensics, Web, Binary"
            "Last 10 generated audit reports"
            "20 fully supported languages"
            "Transparency & technical boundaries"
            "Passive GitHub release check"
            "Live Digital Clock, Dates & Uptime"
            "Clean session shutdown"
        )
        local sep="┃"
        case "${LC_ALL:-${LANG:-}}" in
            *UTF-8*|*utf-8*|*utf8*|*UTF8*) ;;
            *) sep="|" ;;
        esac
        printf '%s\n\n' "${BOLD}${_RAQIB_MM_PROMPT}${NC}" | fx_reveal_lines 0.05
        {
            local _i num color name_color desc_color
            for _i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13; do
                num=$((_i + 1))
                [ "$_i" -eq 13 ] && num=0
                color="$CYAN"; name_color="$WHITE"; desc_color="$GREY"
                [ "$_i" -eq 7 ] && color="$PURPLE"
                [ "$_i" -eq 12 ] && color="$GREEN"
                if [ "$_i" -eq 13 ]; then
                    color="$RED"; name_color="$RED"; desc_color="$RED"
                fi
                printf '  %s%2s)%s %s%s%s  %s%s%s %s%s%s\n' \
                    "$color" "$num" "$NC" \
                    "$BOLD$name_color" "${_RAQIB_MM_NAMES[$_i]}" "$NC" \
                    "$GREY" "$sep" "$NC" \
                    "$desc_color" "${_RAQIB_MM_DESC[$_i]}" "$NC"
            done
        } | fx_reveal_lines 0.05 7
        echo ""
        local choice
        read -rp "  ${BOLD}${YELLOW}${_RAQIB_MM_CHOICE}${NC}" choice
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

