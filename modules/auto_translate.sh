#!/bin/bash
# ============================================================================
# auto_translate.sh — إكمال النصوص الناقصة بأي لغة تلقائياً عبر خدمة ترجمة
# حية على الإنترنت (LibreTranslate)، اختياري بالكامل وبموافقة المستخدم.
#
# لماذا ملف منفصل: هذي الميزة الوحيدة بكل RAQIB اللي تحتاج إنترنت لغرض
# "الترجمة نفسها" (غير أدوات الأمن اللي أصلاً تتصل بالإنترنت لأغراضها
# الخاصة زي VirusTotal). فصلها يخلي واضح للمستخدم والمطور وين بالضبط
# تحصل اتصالات شبكة غير متوقعة.
#
# لا يوجد سيرفر ترجمة رسمي لـ RAQIB — يمكنك تغيير LT_API_URL أدناه لأي
# سيرفر LibreTranslate تثق فيه (عام أو تستضيفه بنفسك عبر Docker).
# ============================================================================

# رابط خدمة LibreTranslate. غيّره لسيرفر خاص بك عند الحاجة.
LT_API_URL="${LT_API_URL:-https://libretranslate.com/translate}"
LT_CACHE_DIR="$MODULES_DIR/lang_cache"

# raqib_lang_completeness <lang_code> -> يطبع "الموجود/الكلي"
raqib_lang_completeness() {
    local code="$1"
    local lc_upper
    lc_upper="$(echo "$code" | tr '[:lower:]' '[:upper:]')"
    local -n arr="STR_${lc_upper}" 2>/dev/null
    local -n en_arr="STR_EN"
    local total=${#en_arr[@]}
    local have=0
    local k
    for k in "${!en_arr[@]}"; do
        [ -n "${arr[$k]}" ] && ((have++))
    done
    echo "$have/$total"
}

# raqib_translate_one <text> <target_lang_code> -> يطبع النص المترجم أو فاضي عند الفشل
raqib_translate_one() {
    local text="$1"
    local target="$2"

    if command -v python3 >/dev/null 2>&1; then
        python3 - "$LT_API_URL" "$target" "$text" << 'PYEOF'
import sys, json, urllib.request, urllib.error

url, target, text = sys.argv[1], sys.argv[2], sys.argv[3]
payload = json.dumps({"q": text, "source": "en", "target": target, "format": "text"}).encode()
req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode())
        print(data.get("translatedText", ""))
except Exception:
    print("")
PYEOF
    else
        # بديل بسيط بدون python3 (أقل دقة بمعالجة JSON، يكفي لحالات بسيطة)
        local escaped
        escaped=$(printf '%s' "$text" | sed 's/\\/\\\\/g; s/"/\\"/g')
        curl -s -m 10 -X POST "$LT_API_URL" \
            -H "Content-Type: application/json" \
            -d "{\"q\":\"$escaped\",\"source\":\"en\",\"target\":\"$target\",\"format\":\"text\"}" \
            2>/dev/null | grep -oP '(?<="translatedText":")[^"]*'
    fi
}

# raqib_auto_translate_missing <lang_code> -> يترجم كل النصوص الناقصة بلغة معينة
# ويخزنها بملف كاش يُحمّل تلقائياً بالمرات القادمة.
raqib_auto_translate_missing() {
    local code="$1"
    local lc_upper
    lc_upper="$(echo "$code" | tr '[:lower:]' '[:upper:]')"
    local -n arr="STR_${lc_upper}" 2>/dev/null
    local -n en_arr="STR_EN"

    local missing_keys=()
    local k
    for k in "${!en_arr[@]}"; do
        [ -z "${arr[$k]}" ] && missing_keys+=("$k")
    done

    local missing_count=${#missing_keys[@]}
    if [ "$missing_count" -eq 0 ]; then
        echo -e "${GREEN}$(t at_already_complete)${NC}"
        return 0
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo -e "${RED}$(t at_needs_curl)${NC}"
        return 1
    fi

    echo -e "$(tf at_missing_count "$missing_count")"
    read -rp "$(t at_confirm_prompt)" ans
    [ "$ans" != "y" ] && [ "$ans" != "Y" ] && { echo -e "$(t at_cancelled)"; return 0; }

    mkdir -p "$LT_CACHE_DIR"
    local cache_file="$LT_CACHE_DIR/${code}.sh"
    local translated=0
    local failed=0

    echo -e "$(t at_translating)"
    for k in "${missing_keys[@]}"; do
        local src="${en_arr[$k]}"
        local out
        out="$(raqib_translate_one "$src" "$code")"
        if [ -n "$out" ]; then
            local esc="${out//\\/\\\\}"
            esc="${esc//\"/\\\"}"
            printf 'STR_%s[%s]="%s"\n' "$lc_upper" "$k" "$esc" >> "$cache_file"
            arr["$k"]="$out"
            ((translated++))
        else
            ((failed++))
        fi
    done

    echo -e "$(tf at_done "$translated" "$failed")"
    [ -f "$cache_file" ] && echo -e "$(tf at_cache_saved "$cache_file")"
}

# raqib_load_translation_caches -> تُستدعى مرة وحدة عند بدء تشغيل الأداة
# لتحميل أي ترجمات آلية سابقة محفوظة بالكاش فوق نتائج lang.sh الأصلية.
raqib_load_translation_caches() {
    [ -d "$LT_CACHE_DIR" ] || return 0
    local f
    for f in "$LT_CACHE_DIR"/*.sh; do
        [ -f "$f" ] && source "$f"
    done
}

export -f raqib_lang_completeness
export -f raqib_translate_one
export -f raqib_auto_translate_missing
export -f raqib_load_translation_caches
