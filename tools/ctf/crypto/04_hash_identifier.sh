#!/bin/bash
# =============================================================
#  RAQIB CTF — Hash Identifier
#  أداة #4: تحديد نوع الهاش
#  اللغة: Bash محض — regex + length checks كافية تماماً
#         لا حاجة لـ Python هنا
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  #️⃣  Hash Identifier                             ║${NC}"
echo -e "${CYAN}║  حدد نوع الهاش من طوله وتركيبه                  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  أدخل الهاش: " hash_input
hash_input="${hash_input// /}"   # إزالة المسافات
[ -z "$hash_input" ] && { echo -e "${RED}لا يوجد مدخل${NC}"; exit 1; }

len=${#hash_input}

echo ""
echo -e "  ${YELLOW}الهاش:${NC} $hash_input"
echo -e "  ${YELLOW}الطول:${NC} $len حرف"
echo ""

# ─── دالة مطابقة ─────────────────────────────────────────────
matches=()
add_match() { matches+=("$1"); }

# ─── Hex-only patterns ───────────────────────────────────────
is_hex=false
[[ "$hash_input" =~ ^[0-9a-fA-F]+$ ]] && is_hex=true

# ─── Prefix-based detection ──────────────────────────────────
case "$hash_input" in
    '$2y$'*|'$2b$'*|'$2a$'*)    add_match "bcrypt (Blowfish, 60 chars)" ;;
    '$1$'*)                       add_match "MD5crypt (Linux \$1\$)" ;;
    '$5$'*)                       add_match "SHA-256crypt (Linux \$5\$)" ;;
    '$6$'*)                       add_match "SHA-512crypt (Linux \$6\$)" ;;
    '$apr1$'*)                    add_match "APR1-MD5 (Apache)" ;;
    '$argon2'*)                   add_match "Argon2" ;;
    '$pbkdf2'*)                   add_match "PBKDF2" ;;
    'sha256:'*)                   add_match "SHA-256 (prefixed)" ;;
    'sha512:'*)                   add_match "SHA-512 (prefixed)" ;;
    'md5:'*)                      add_match "MD5 (prefixed)" ;;
esac

# ─── Length-based detection ──────────────────────────────────
if $is_hex; then
    case $len in
        8)   add_match "CRC-32" ;;
        16)  add_match "MySQL 3.x / Half MD5 / DES (old)" ;;
        32)  add_match "MD5 ⭐" ; add_match "NTLM" ; add_match "MD4" ; add_match "LM (part)" ;;
        40)  add_match "SHA-1 ⭐" ; add_match "RIPEMD-160" ; add_match "HAS-160" ;;
        48)  add_match "Tiger-192" ; add_match "SHA-1 (salted)" ;;
        56)  add_match "SHA-224" ; add_match "Haval-224" ;;
        64)  add_match "SHA-256 ⭐" ; add_match "RIPEMD-256" ; add_match "Blake2s-256" ;;
        80)  add_match "RIPEMD-320" ; add_match "Haval-320" ;;
        96)  add_match "SHA-384" ;;
        128) add_match "SHA-512 ⭐" ; add_match "Whirlpool" ; add_match "Blake2b-512" ;;
    esac
fi

# ─── Base64-like patterns ─────────────────────────────────────
if [[ "$hash_input" =~ ^[A-Za-z0-9+/]+=*$ ]]; then
    case $len in
        24) add_match "MD5 (Base64 encoded)" ;;
        28) add_match "SHA-1 (Base64 encoded)" ;;
        32) add_match "SHA-1 HMAC (Base64)" ;;
        44) add_match "SHA-256 (Base64 encoded) ⭐" ;;
        88) add_match "SHA-512 (Base64 encoded)" ;;
    esac
fi

# ─── UUID / GUID ─────────────────────────────────────────────
if [[ "$hash_input" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
    add_match "UUID / GUID"
fi

# ─── JWT ─────────────────────────────────────────────────────
if [[ "$hash_input" =~ ^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$ ]]; then
    add_match "JWT (JSON Web Token) — 3 parts base64url"
fi

# ─── NTLM / LM specific lengths ──────────────────────────────
if $is_hex && [ $len -eq 32 ]; then
    # NTLM هو MD4 لـ Unicode password
    echo -e "  ${GREY}  💡 تلميح: MD5 و NTLM كلاهما 32 hex — NTLM = MD4(UTF-16LE(password))${NC}"
fi

# ─── الإخراج ─────────────────────────────────────────────────
echo -e "  ${BOLD}الأنواع المحتملة:${NC}"
echo "  ─────────────────────────────────"

if [ ${#matches[@]} -eq 0 ]; then
    echo -e "  ${RED}  ⚠️  لم يُتعرَّف على النوع${NC}"
    echo -e "  ${GREY}     طول غير معتاد: $len — ربما hash مخصص أو مشفر${NC}"
else
    for match in "${matches[@]}"; do
        echo -e "  ${GREEN}  ✅ $match${NC}"
    done
fi

echo ""
echo -e "  ${YELLOW}📌 للـ Cracking:${NC}"
echo -e "  ${GREY}  • Hashcat: hashcat -m <mode> '$hash_input' wordlist.txt${NC}"
echo -e "  ${GREY}  • John:    echo '$hash_input' | john --stdin${NC}"
echo -e "  ${GREY}  • Online:  https://crackstation.net/${NC}"
echo -e "  ${GREY}  • Online:  https://hashes.com/en/decrypt/hash${NC}"
echo ""

pause
