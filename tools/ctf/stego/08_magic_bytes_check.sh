#!/bin/bash
# =============================================================
#  RAQIB CTF — Magic Bytes Checker
#  أداة #8: كشف نوع الملف الحقيقي وPolyglot files
#  اللغة: Bash محض — xxd/hexdump + file command + grep
#         لا حاجة لـ Python — shell مثالي هنا
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🪄 Magic Bytes Checker                           ║${NC}"
echo -e "${CYAN}║  اكشف النوع الحقيقي للملف + Polyglot detection  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  مسار الملف: " target_file
[ ! -f "$target_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }

filename="$(basename -- "$target_file")"
extension="${filename##*.}"
filesize="$(wc -c < "$target_file" 2>/dev/null)"

echo ""
echo -e "  ${YELLOW}الملف:${NC}      $filename"
echo -e "  ${YELLOW}الامتداد:${NC}   .$extension"
echo -e "  ${YELLOW}الحجم:${NC}      $filesize بايت"
echo ""

# ─── قراءة أول 16 بايت كـ hex ────────────────────────────────
if command -v xxd >/dev/null 2>&1; then
    magic_hex="$(xxd -l 16 -p -- "$target_file" 2>/dev/null | tr -d '\n' | tr '[:lower:]' '[:upper:]')"
elif command -v hexdump >/dev/null 2>&1; then
    magic_hex="$(hexdump -n 16 -e '16/1 "%02X"' -- "$target_file" 2>/dev/null)"
elif command -v od >/dev/null 2>&1; then
    magic_hex="$(od -A n -t x1 -N 16 -- "$target_file" 2>/dev/null | tr -d ' \n' | tr '[:lower:]' '[:upper:]')"
else
    magic_hex="UNAVAILABLE"
fi

echo -e "  ${BOLD}أول 16 بايت (hex):${NC}"
echo -e "  ${CYAN}$magic_hex${NC}"
echo ""

# ─── جدول Magic Bytes ────────────────────────────────────────
declare -A MAGIC_TYPES
MAGIC_TYPES=(
    ["FFD8FF"]="JPEG Image"
    ["89504E47"]="PNG Image"
    ["47494638"]="GIF Image (GIF87a/GIF89a)"
    ["424D"]="BMP Image"
    ["49492A00"]="TIFF Image (little-endian)"
    ["4D4D002A"]="TIFF Image (big-endian)"
    ["25504446"]="PDF Document"
    ["504B0304"]="ZIP / DOCX / XLSX / JAR / APK"
    ["504B0506"]="ZIP (empty)"
    ["1F8B"]="GZIP Compressed"
    ["425A68"]="BZIP2 Compressed"
    ["FD377A585A"]="XZ Compressed"
    ["526172211A07"]="RAR Archive"
    ["377ABCAF271C"]="7-Zip Archive"
    ["4D5A"]="Windows PE Executable (EXE/DLL)"
    ["7F454C46"]="ELF Binary (Linux executable)"
    ["CAFEBABE"]="Java Class / Mach-O (macOS binary)"
    ["FEEDFACE"]="Mach-O 32-bit"
    ["FEEDFACF"]="Mach-O 64-bit"
    ["D0CF11E0"]="Microsoft Office (old .doc/.xls)"
    ["52494646"]="RIFF (WAV / AVI)"
    ["000001BA"]="MPEG Video"
    ["000001B3"]="MPEG Video Stream"
    ["66747970"]="MP4 / M4V Video"
    ["494433"]="MP3 Audio (ID3 tag)"
    ["4F676753"]="OGG Audio"
    ["664C6143"]="FLAC Audio"
    ["3C3F786D6C"]="XML Document"
    ["3C21444F4354"]="HTML Document"
    ["7B0A"]="JSON"
    ["7B22"]="JSON"
    ["2321"]="Script (shebang #!)"
    ["EFBBBF"]="UTF-8 BOM Text"
    ["FFFE"]="UTF-16 LE Text"
    ["FEFF"]="UTF-16 BE Text"
    ["3026B2758E66CF"]="Windows Media (WMV/WMA)"
    ["53514C697465"]="SQLite Database"
    ["213C617263683E"]="Debian Package (.deb)"
)

detected_type=""
for magic in "${!MAGIC_TYPES[@]}"; do
    magic_len=${#magic}
    prefix="${magic_hex:0:$magic_len}"
    if [[ "$prefix" == "$magic" ]]; then
        detected_type="${MAGIC_TYPES[$magic]}"
        break
    fi
done

# ─── النتيجة من `file` command ───────────────────────────────
file_output=""
if command -v file >/dev/null 2>&1; then
    file_output="$(file --brief -- "$target_file" 2>/dev/null)"
fi

echo -e "  ${BOLD}نتيجة التحليل:${NC}"
echo "  ─────────────────────────────────"

if [ -n "$file_output" ]; then
    echo -e "  ${GREEN}[file command]${NC} $file_output"
fi

if [ -n "$detected_type" ]; then
    echo -e "  ${GREEN}[magic bytes]${NC}  $detected_type"
else
    echo -e "  ${YELLOW}[magic bytes]${NC}  لم يُتعرَّف على النوع من قاعدة البيانات المحلية"
fi

echo ""

# ─── كشف Extension Mismatch (الخطر الحقيقي في CTF) ──────────
echo -e "  ${BOLD}🎭 فحص Extension Spoofing:${NC}"
echo "  ─────────────────────────────────"

mismatch=false

# خريطة امتدادات vs magic bytes متوقعة
check_mismatch() {
    local ext="$1"
    local expected_magic="$2"
    local expected_type="$3"
    local prefix="${magic_hex:0:${#expected_magic}}"
    if [[ "${ext,,}" == "${1,,}" ]]; then
        if [[ "$prefix" != "$expected_magic" ]]; then
            echo -e "  ${RED}  ⚠️  MISMATCH! الامتداد .$ext لكن المحتوى ليس $expected_type${NC}"
            echo -e "  ${RED}     المحتوى الفعلي يبدأ بـ: ${magic_hex:0:8}...${NC}"
            mismatch=true
        fi
    fi
}

case "${extension,,}" in
    jpg|jpeg) check_mismatch "jpg" "FFD8FF" "JPEG" ;;
    png)      check_mismatch "png" "89504E47" "PNG" ;;
    gif)      check_mismatch "gif" "47494638" "GIF" ;;
    pdf)      check_mismatch "pdf" "25504446" "PDF" ;;
    zip)      check_mismatch "zip" "504B0304" "ZIP" ;;
    exe)      check_mismatch "exe" "4D5A" "PE EXE" ;;
    elf)      check_mismatch "elf" "7F454C46" "ELF" ;;
    mp3)      check_mismatch "mp3" "494433" "MP3" ;;
    wav)      check_mismatch "wav" "52494646" "RIFF/WAV" ;;
esac

if ! $mismatch; then
    if [ -n "$detected_type" ]; then
        echo -e "  ${GREEN}  ✅ الامتداد يتطابق مع المحتوى${NC}"
    else
        echo -e "  ${GREY}  — لا يمكن التحقق (نوع غير معروف في القاعدة)${NC}"
    fi
fi

echo ""

# ─── Polyglot Detection ──────────────────────────────────────
echo -e "  ${BOLD}🔀 فحص Polyglot (ملف بطبيعتين):${NC}"
echo "  ─────────────────────────────────"

polyglot_hints=()

# PHP في صورة (أشيع في CTF)
if grep -c '<?php' -- "$target_file" >/dev/null 2>&1; then
    php_count=$(grep -c '<?php' -- "$target_file" 2>/dev/null || echo 0)
    [ "$php_count" -gt 0 ] && polyglot_hints+=("⚠️  يحتوي على PHP code (<?php) — محتمل Webshell Polyglot")
fi

# HTML داخل ملف
if grep -qc '<html\|<script\|<body' -- "$target_file" 2>/dev/null; then
    polyglot_hints+=("⚠️  يحتوي HTML/JavaScript")
fi

# ZIP داخل ملف آخر
if strings -- "$target_file" 2>/dev/null | grep -q "PK" && [[ "${magic_hex:0:4}" != "504B" ]]; then
    polyglot_hints+=("💡 يحتوي على ZIP signature في المنتصف — جرب rename إلى .zip")
fi

# نص بعد EOF في صور
if [[ "${magic_hex:0:6}" =~ ^(FFD8FF|89504E|474946) ]]; then
    # إذا الملف صورة — فحص هل يوجد نص مخفي في الذيل
    trailing=$(tail -c 200 -- "$target_file" 2>/dev/null | strings 2>/dev/null | head -5)
    if [ -n "$trailing" ]; then
        polyglot_hints+=("💡 يوجد نص مقروء في نهاية الملف:")
        polyglot_hints+=("   $trailing")
    fi
fi

if [ ${#polyglot_hints[@]} -eq 0 ]; then
    echo -e "  ${GREEN}  ✅ لا مؤشرات واضحة على Polyglot${NC}"
else
    for hint in "${polyglot_hints[@]}"; do
        echo -e "  ${ORANGE}  $hint${NC}"
    done
fi

echo ""
echo -e "  ${YELLOW}💡 أدوات إضافية:${NC}"
echo -e "  ${GREY}  • strings \"$target_file\" | head -50${NC}"
echo -e "  ${GREY}  • binwalk \"$target_file\"  (لو مثبت)${NC}"
echo -e "  ${GREY}  • exiftool \"$target_file\" (لو مثبت)${NC}"
echo ""

pause
