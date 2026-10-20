#!/bin/bash
# ============================================================================
#  RAQIB - i18n / Language Core Module
#  Modular, lightweight multi-language loader (optimized for Kali Linux / low-spec OS)
#  Only the active language file is loaded into memory on-demand.
# ============================================================================

_LANG_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_LANG_ROOT_DIR="$(cd "$_LANG_MODULE_DIR/.." && pwd)"

RAQIB_LANG_FILE="${RAQIB_LANG_FILE:-$_LANG_ROOT_DIR/.raqib_lang}"
LANGUAGES_DIR="${LANGUAGES_DIR:-$_LANG_MODULE_DIR/languages}"

# Supported languages in menu order (20 languages)
LANG_CODES=(ar en fr es de tr fa ru ku zh ur pt id it ja hi nl ko pl uk)

# Lightweight language metadata (native names) for menu display without loading files
declare -g -A LANG_NAMES=(
    [ar]="العربية"
    [en]="English"
    [fr]="Français"
    [es]="Español"
    [de]="Deutsch"
    [tr]="Türkçe"
    [fa]="فارسی"
    [ru]="Русский"
    [ku]="کوردی"
    [zh]="中文"
    [ur]="اردو"
    [pt]="Português"
    [id]="Bahasa Indonesia"
    [it]="Italiano"
    [ja]="日本語"
    [hi]="हिन्दी"
    [nl]="Nederlands"
    [ko]="한국어"
    [pl]="Polski"
    [uk]="Українська"
)

_RAQIB_CURRENT_LOADED_LANG=""

# ----------------------------------------------------------------------------
# raqib_load_lang <lang_code>
# Dynamically loads a single language file into memory.
# Unsets previous language array to free memory and keep Kali OS footprint minimal.
# ----------------------------------------------------------------------------
raqib_load_lang() {
    local code="${1:-${LANG_CODE:-ar}}"

    # Validate against supported codes
    case " ${LANG_CODES[*]} " in
        *" $code "*) : ;;
        *) code="ar" ;;
    esac

    # If another language is already in memory, unset it to free memory
    if [ -n "$_RAQIB_CURRENT_LOADED_LANG" ] && [ "$_RAQIB_CURRENT_LOADED_LANG" != "$code" ]; then
        local old_upper
        old_upper="$(echo "$_RAQIB_CURRENT_LOADED_LANG" | tr '[:lower:]' '[:upper:]')"
        unset "STR_${old_upper}"
    fi

    # Locate language file
    local lang_file="$LANGUAGES_DIR/${code}.sh"
    if [ ! -f "$lang_file" ] && [ -f "$_LANG_ROOT_DIR/modules/languages/${code}.sh" ]; then
        lang_file="$_LANG_ROOT_DIR/modules/languages/${code}.sh"
    fi

    if [ -f "$lang_file" ]; then
        source "$lang_file"
        _RAQIB_CURRENT_LOADED_LANG="$code"
        LANG_CODE="$code"
        export _RAQIB_CURRENT_LOADED_LANG LANG_CODE
        return 0
    else
        echo "[-] Language file not found: $lang_file" >&2
        return 1
    fi
}
export -f raqib_load_lang

# ----------------------------------------------------------------------------
# load_lang: Load saved language preference (defaults to Arabic) and sources file
# ----------------------------------------------------------------------------
load_lang() {
    local saved_code=""
    if [ -f "$RAQIB_LANG_FILE" ]; then
        saved_code="$(tr -d '[:space:]' < "$RAQIB_LANG_FILE" 2>/dev/null)"
    fi
    case " ${LANG_CODES[*]} " in
        *" $saved_code "*) LANG_CODE="$saved_code" ;;
        *) LANG_CODE="ar" ;;
    esac
    raqib_load_lang "$LANG_CODE"
}
export -f load_lang

# ----------------------------------------------------------------------------
# save_lang: Persist user language preference to .raqib_lang
# ----------------------------------------------------------------------------
save_lang() {
    echo "$LANG_CODE" > "$RAQIB_LANG_FILE"
}
export -f save_lang

# ----------------------------------------------------------------------------
# t <key>: prints translated string for active LANG_CODE.
# Falls back to Arabic on-demand only if key is missing in active language.
# ----------------------------------------------------------------------------
t() {
    local key="$1"
    if [ -z "$_RAQIB_CURRENT_LOADED_LANG" ]; then
        load_lang
    fi

    local lc_upper
    lc_upper="$(echo "${LANG_CODE:-ar}" | tr '[:lower:]' '[:upper:]')"
    local -n arr="STR_${lc_upper}" 2>/dev/null
    local val="${arr[$key]}"

    # Fallback to Arabic if missing and active language is not Arabic
    if [ -z "$val" ] && [ "${LANG_CODE:-ar}" != "ar" ]; then
        if [ -z "${STR_AR[subtitle]}" ]; then
            local fb_file="$LANGUAGES_DIR/ar.sh"
            [ ! -f "$fb_file" ] && fb_file="$_LANG_ROOT_DIR/modules/languages/ar.sh"
            [ -f "$fb_file" ] && source "$fb_file"
        fi
        local -n fb="STR_AR" 2>/dev/null
        val="${fb[$key]}"
    fi

    printf '%s' "$val"
}
export -f t

# ----------------------------------------------------------------------------
# tf <key> <args...>: printf wrapper around t()
# ----------------------------------------------------------------------------
tf() {
    local key="$1"; shift
    local fmt
    fmt="$(t "$key")"
    printf -- "$fmt" "$@"
}
export -f tf

# ----------------------------------------------------------------------------
# menu_language: interactive language selection menu
# ----------------------------------------------------------------------------
menu_language() {
    while true; do
        show_banner
        echo -e "${BOLD}$(t lang_menu_title)${NC}"
        echo ""
        local i=1
        local code
        for code in "${LANG_CODES[@]}"; do
            local marker=""
            if [ "$code" = "$LANG_CODE" ]; then marker=" ${GREEN}✓${NC}"; fi
            local name="${LANG_NAMES[$code]:-$code}"
            echo -e "  ${CYAN}${i})${NC} ${name}${marker}"
            i=$((i + 1))
        done
        echo -e "  ${RED}0)${NC} $(t back)"
        echo ""
        read -rp "  $(t choice_label)" c
        if [ "$c" = "0" ]; then
            return
        elif [[ "$c" =~ ^[0-9]+$ ]] && [ "$c" -ge 1 ] && [ "$c" -le "${#LANG_CODES[@]}" ]; then
            local selected_code="${LANG_CODES[$((c-1))]}"
            LANG_CODE="$selected_code"
            save_lang
            raqib_load_lang "$LANG_CODE"
            echo -e "${GREEN}$(t lang_changed)${NC}"
            if [ "$LANG_CODE" != "ar" ] && [ "$LANG_CODE" != "en" ]; then
                if declare -F raqib_lang_completeness >/dev/null 2>&1; then
                    local completeness
                    completeness="$(raqib_lang_completeness "$LANG_CODE")"
                    local have="${completeness%/*}"
                    local total="${completeness#*/}"
                    if [ -n "$have" ] && [ -n "$total" ] && [ "$have" -lt "$total" ]; then
                        raqib_auto_translate_missing "$LANG_CODE"
                    fi
                fi
            fi
            sleep 1
            return
        else
            echo -e "${RED}$(t invalid_choice)${NC}"
            sleep 1
        fi
    done
}
export -f menu_language

# ============================================================================
#  Date Formatting Functions (Multilingual)
# ============================================================================

raqib_format_date() {
    local date_str="$1"
    local lc="${2:-${LANG_CODE:-ar}}"
    [ -z "$date_str" ] && date_str="$(date '+%Y-%m-%d')"
    
    local y="${date_str%%-*}"
    local rest="${date_str#*-}"
    local m="${rest%%-*}"
    local d="${rest#*-}"
    
    # Strip leading zeros for arithmetic
    m=$(( 10#$m ))
    d=$(( 10#$d ))
    
    local month_name=""
    case "$lc" in
        ar)
            case "$m" in
                1) month_name="يناير" ;; 2) month_name="فبراير" ;; 3) month_name="مارس" ;;
                4) month_name="أبريل" ;; 5) month_name="مايو" ;; 6) month_name="يونيو" ;;
                7) month_name="يوليو" ;; 8) month_name="أغسطس" ;; 9) month_name="سبتمبر" ;;
                10) month_name="أكتوبر" ;; 11) month_name="نوفمبر" ;; 12) month_name="ديسمبر" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        en)
            case "$m" in
                1) month_name="January" ;; 2) month_name="February" ;; 3) month_name="March" ;;
                4) month_name="April" ;; 5) month_name="May" ;; 6) month_name="June" ;;
                7) month_name="July" ;; 8) month_name="August" ;; 9) month_name="September" ;;
                10) month_name="October" ;; 11) month_name="November" ;; 12) month_name="December" ;;
            esac
            printf '%s' "${month_name} ${d}, ${y}"
            ;;
        fr)
            case "$m" in
                1) month_name="janvier" ;; 2) month_name="février" ;; 3) month_name="mars" ;;
                4) month_name="avril" ;; 5) month_name="mai" ;; 6) month_name="juin" ;;
                7) month_name="juillet" ;; 8) month_name="août" ;; 9) month_name="septembre" ;;
                10) month_name="octobre" ;; 11) month_name="novembre" ;; 12) month_name="décembre" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        es)
            case "$m" in
                1) month_name="enero" ;; 2) month_name="febrero" ;; 3) month_name="marzo" ;;
                4) month_name="abril" ;; 5) month_name="mayo" ;; 6) month_name="junio" ;;
                7) month_name="julio" ;; 8) month_name="agosto" ;; 9) month_name="septiembre" ;;
                10) month_name="octubre" ;; 11) month_name="noviembre" ;; 12) month_name="diciembre" ;;
            esac
            printf '%s' "${d} de ${month_name} de ${y}"
            ;;
        de)
            case "$m" in
                1) month_name="Januar" ;; 2) month_name="Februar" ;; 3) month_name="März" ;;
                4) month_name="April" ;; 5) month_name="Mai" ;; 6) month_name="Juni" ;;
                7) month_name="Juli" ;; 8) month_name="August" ;; 9) month_name="September" ;;
                10) month_name="Oktober" ;; 11) month_name="November" ;; 12) month_name="Dezember" ;;
            esac
            printf '%s' "${d}. ${month_name} ${y}"
            ;;
        tr)
            case "$m" in
                1) month_name="Ocak" ;; 2) month_name="Şubat" ;; 3) month_name="Mart" ;;
                4) month_name="Nisan" ;; 5) month_name="Mayıs" ;; 6) month_name="Haziran" ;;
                7) month_name="Temmuz" ;; 8) month_name="Ağustos" ;; 9) month_name="Eylül" ;;
                10) month_name="Ekim" ;; 11) month_name="Kasım" ;; 12) month_name="Aralık" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        fa)
            case "$m" in
                1) month_name="ژانویه" ;; 2) month_name="فوریه" ;; 3) month_name="مارس" ;;
                4) month_name="آوریل" ;; 5) month_name="مه" ;; 6) month_name="ژوئن" ;;
                7) month_name="ژوئیه" ;; 8) month_name="اوت" ;; 9) month_name="سپتامبر" ;;
                10) month_name="اکتبر" ;; 11) month_name="نوامبر" ;; 12) month_name="دسامبر" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        ru)
            case "$m" in
                1) month_name="января" ;; 2) month_name="февраля" ;; 3) month_name="марта" ;;
                4) month_name="апреля" ;; 5) month_name="мая" ;; 6) month_name="июня" ;;
                7) month_name="июля" ;; 8) month_name="августа" ;; 9) month_name="сентября" ;;
                10) month_name="октября" ;; 11) month_name="ноября" ;; 12) month_name="декабря" ;;
            esac
            printf '%s' "${d} ${month_name} ${y} г."
            ;;
        ku)
            case "$m" in
                1) month_name="کانوونی دووەم" ;; 2) month_name="شوبات" ;; 3) month_name="ئادار" ;;
                4) month_name="نیسان" ;; 5) month_name="ئایار" ;; 6) month_name="حوزەیران" ;;
                7) month_name="تەممووز" ;; 8) month_name="ئاب" ;; 9) month_name="ئەیلوول" ;;
                10) month_name="تشرینی یەکەم" ;; 11) month_name="تشرینی دووەم" ;; 12) month_name="کانوونی یەکەم" ;;
            esac
            printf '%s' "${d}ی ${month_name} ${y}"
            ;;
        zh|ja)
            case "$m" in
                1) month_name="1月" ;; 2) month_name="2月" ;; 3) month_name="3月" ;;
                4) month_name="4月" ;; 5) month_name="5月" ;; 6) month_name="6月" ;;
                7) month_name="7月" ;; 8) month_name="8月" ;; 9) month_name="9月" ;;
                10) month_name="10月" ;; 11) month_name="11月" ;; 12) month_name="12月" ;;
            esac
            printf '%s' "${y}年${month_name}${d}日"
            ;;
        ur)
            case "$m" in
                1) month_name="جنوری" ;; 2) month_name="فروری" ;; 3) month_name="مارچ" ;;
                4) month_name="اپریل" ;; 5) month_name="مئی" ;; 6) month_name="جون" ;;
                7) month_name="جولائی" ;; 8) month_name="اگست" ;; 9) month_name="ستمبر" ;;
                10) month_name="اکتوبر" ;; 11) month_name="نومبر" ;; 12) month_name="دسمبر" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        pt)
            case "$m" in
                1) month_name="janeiro" ;; 2) month_name="fevereiro" ;; 3) month_name="março" ;;
                4) month_name="abril" ;; 5) month_name="maio" ;; 6) month_name="junho" ;;
                7) month_name="julho" ;; 8) month_name="agosto" ;; 9) month_name="setembro" ;;
                10) month_name="outubro" ;; 11) month_name="novembro" ;; 12) month_name="dezembro" ;;
            esac
            printf '%s' "${d} de ${month_name} de ${y}"
            ;;
        id)
            case "$m" in
                1) month_name="Januari" ;; 2) month_name="Februari" ;; 3) month_name="Maret" ;;
                4) month_name="April" ;; 5) month_name="Mei" ;; 6) month_name="Juni" ;;
                7) month_name="Juli" ;; 8) month_name="Agustus" ;; 9) month_name="September" ;;
                10) month_name="Oktober" ;; 11) month_name="November" ;; 12) month_name="Desember" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        it)
            case "$m" in
                1) month_name="gennaio" ;; 2) month_name="febbraio" ;; 3) month_name="marzo" ;;
                4) month_name="aprile" ;; 5) month_name="maggio" ;; 6) month_name="giugno" ;;
                7) month_name="luglio" ;; 8) month_name="agosto" ;; 9) month_name="settembre" ;;
                10) month_name="ottobre" ;; 11) month_name="novembre" ;; 12) month_name="dicembre" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        hi)
            case "$m" in
                1) month_name="जनवरी" ;; 2) month_name="फ़रवरी" ;; 3) month_name="मार्च" ;;
                4) month_name="अप्रैल" ;; 5) month_name="मई" ;; 6) month_name="जून" ;;
                7) month_name="जुलाई" ;; 8) month_name="अगस्त" ;; 9) month_name="सितम्बर" ;;
                10) month_name="अक्टूबर" ;; 11) month_name="नवम्बर" ;; 12) month_name="दिसम्बर" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        nl)
            case "$m" in
                1) month_name="januari" ;; 2) month_name="februari" ;; 3) month_name="maart" ;;
                4) month_name="april" ;; 5) month_name="mei" ;; 6) month_name="juni" ;;
                7) month_name="juli" ;; 8) month_name="augustus" ;; 9) month_name="september" ;;
                10) month_name="oktober" ;; 11) month_name="november" ;; 12) month_name="december" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        ko)
            case "$m" in
                1) month_name="1월" ;; 2) month_name="2월" ;; 3) month_name="3월" ;;
                4) month_name="4월" ;; 5) month_name="5월" ;; 6) month_name="6월" ;;
                7) month_name="7월" ;; 8) month_name="8월" ;; 9) month_name="9월" ;;
                10) month_name="10월" ;; 11) month_name="11월" ;; 12) month_name="12월" ;;
            esac
            printf '%s' "${y}년 ${month_name} ${d}일"
            ;;
        pl)
            case "$m" in
                1) month_name="stycznia" ;; 2) month_name="lutego" ;; 3) month_name="marca" ;;
                4) month_name="kwietnia" ;; 5) month_name="maja" ;; 6) month_name="czerwca" ;;
                7) month_name="lipca" ;; 8) month_name="sierpnia" ;; 9) month_name="września" ;;
                10) month_name="października" ;; 11) month_name="listopada" ;; 12) month_name="grudnia" ;;
            esac
            printf '%s' "${d} ${month_name} ${y}"
            ;;
        uk)
            case "$m" in
                1) month_name="січня" ;; 2) month_name="лютого" ;; 3) month_name="березня" ;;
                4) month_name="квітня" ;; 5) month_name="травня" ;; 6) month_name="червня" ;;
                7) month_name="липня" ;; 8) month_name="серпня" ;; 9) month_name="вересня" ;;
                10) month_name="жовтня" ;; 11) month_name="листопада" ;; 12) month_name="грудня" ;;
            esac
            printf '%s' "${d} ${month_name} ${y} р."
            ;;
        *)
            printf '%s' "$date_str"
            ;;
    esac
}
export -f raqib_format_date

raqib_current_date() {
    raqib_format_date "$(date '+%Y-%m-%d')" "${1:-$LANG_CODE}"
}
export -f raqib_current_date

raqib_gregorian_date() {
    local lc="${1:-${LANG_CODE:-ar}}"
    local dt="${2:-}"
    if [ -n "$dt" ]; then
        raqib_format_date "$dt" "$lc"
    else
        raqib_format_date "$(date '+%Y-%m-%d')" "$lc"
    fi
}
export -f raqib_gregorian_date

raqib_current_datetime() {
    printf '%s  %s' "$(raqib_current_date "${1:-$LANG_CODE}")" "$(date '+%H:%M:%S')"
}
export -f raqib_current_datetime

get_created_date() {
    raqib_format_date "${CREATED_DATE:-2026-09-01}" "${1:-$LANG_CODE}"
}
export -f get_created_date

get_last_updated_date() {
    raqib_format_date "${LAST_UPDATED:-2026-10-14}" "${1:-$LANG_CODE}"
}
export -f get_last_updated_date

# Automatically initialize preferred language
load_lang
