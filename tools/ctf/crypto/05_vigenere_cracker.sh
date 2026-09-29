#!/bin/bash
# =============================================================
#  RAQIB CTF — Vigenère Cracker
#  أداة #5: كسر تشفير Vigenère باستخدام Kasiski + IC attack
#  يعمل بدون تبعيات خارجية — Python3 فقط
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🔑 Vigenère Cracker — Kasiski + IC Attack      ║${NC}"
echo -e "${CYAN}║  يكشف طول المفتاح ثم يستردّ المفتاح حرفاً حرفاً ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "  ${YELLOW}1)${NC} من ملف"
echo -e "  ${YELLOW}2)${NC} من نص مباشر"
read -rp "  اختر: " src_choice

if [ "$src_choice" = "1" ]; then
    read -rp "  مسار الملف: " input_file
    [ ! -f "$input_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }
    cipher_text="$(cat -- "$input_file")"
else
    read -rp "  أدخل النص المشفّر: " cipher_text
fi

[ -z "$cipher_text" ] && { echo -e "${RED}لا يوجد مدخل${NC}"; exit 1; }

echo ""
echo -e "${YELLOW}جارٍ التحليل...${NC}"
echo ""

python3 - "$cipher_text" <<'PYEOF'
import sys, re, collections, string

ciphertext = sys.argv[1]
# نظّف النص — احتفظ بالحروف الإنجليزية فقط (uppercase)
clean = re.sub(r'[^A-Za-z]', '', ciphertext).upper()

if len(clean) < 20:
    print("  ⚠️  النص قصير جداً للتحليل الإحصائي (أقل من 20 حرف).")
    sys.exit(0)

EN_FREQ = {
    'E':12.70,'T':9.06,'A':8.17,'O':7.51,'I':6.97,'N':6.75,'S':6.33,
    'H':6.09,'R':5.99,'D':4.25,'L':4.03,'C':2.78,'U':2.76,'M':2.41,
    'W':2.36,'F':2.23,'G':2.02,'Y':1.97,'P':1.93,'B':1.49,'V':0.98,
    'K':0.77,'J':0.15,'X':0.15,'Q':0.10,'Z':0.07
}

def index_of_coincidence(text):
    n = len(text)
    if n < 2:
        return 0
    freq = collections.Counter(text)
    return sum(f*(f-1) for f in freq.values()) / (n*(n-1))

def kasiski_test(text, min_len=3, max_len=5):
    """يجد تكرارات sequences ويحسب المسافات بينها"""
    distances = []
    for length in range(min_len, max_len+1):
        seqs = {}
        for i in range(len(text)-length):
            seq = text[i:i+length]
            if seq in seqs:
                seqs[seq].append(i)
            else:
                seqs[seq] = [i]
        for seq, positions in seqs.items():
            if len(positions) > 1:
                for j in range(1, len(positions)):
                    distances.append(positions[j] - positions[j-1])
    return distances

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def find_key_length(text, max_key=20):
    """يجمع Kasiski + IC لتقدير أفضل طول مفتاح"""
    distances = kasiski_test(text)
    gcd_counts = collections.Counter()
    for d in distances:
        for k in range(2, max_key+1):
            if d % k == 0:
                gcd_counts[k] += 1

    # IC test لكل طول
    ic_scores = {}
    for key_len in range(2, max_key+1):
        groups = [''.join(text[i::key_len]) for i in range(key_len)]
        avg_ic = sum(index_of_coincidence(g) for g in groups) / key_len
        ic_scores[key_len] = avg_ic  # أقرب لـ 0.065 = إنجليزي عادي

    # دمج النتيجتين
    combined = {}
    for k in range(2, max_key+1):
        kasiski_score = gcd_counts.get(k, 0)
        ic_score = ic_scores.get(k, 0)
        # IC الإنجليزي ≈ 0.065
        ic_closeness = 1 - abs(ic_score - 0.065) * 20
        combined[k] = kasiski_score * 0.4 + max(ic_closeness, 0) * 0.6

    return sorted(combined.items(), key=lambda x: -x[1])[:5]

def crack_key(text, key_len):
    """يستردّ المفتاح بـ frequency analysis على كل سلسلة جزئية"""
    key = []
    for i in range(key_len):
        group = text[i::key_len]
        freq = collections.Counter(group)
        # جرب كل إزاحة واختر الأقرب لتوزيع الإنجليزية
        best_shift, best_score = 0, -1
        for shift in range(26):
            score = 0
            for c, cnt in freq.items():
                plain_c = chr((ord(c) - shift) % 26 + ord('A'))
                score += cnt * EN_FREQ.get(plain_c, 0)
            if score > best_score:
                best_score, best_shift = score, shift
        key.append(chr(best_shift + ord('A')))
    return ''.join(key)

def decrypt_vigenere(cipher, key):
    result = []
    key_up = key.upper()
    ki = 0
    for c in cipher:
        if c.isalpha():
            shift = ord(key_up[ki % len(key_up)]) - ord('A')
            if c.isupper():
                result.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
            else:
                result.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

# ─── التحليل ───
print(f"  📊 طول النص (بعد التنظيف): {len(clean)} حرف")
print(f"  🎲 IC الكلي: {index_of_coincidence(clean):.4f}  (الإنجليزي المعتاد: 0.0650)")
print("")

candidates = find_key_length(clean)
print("  🔍 أفضل أطوال محتملة للمفتاح:")
for key_len, score in candidates:
    key = crack_key(clean, key_len)
    plain = decrypt_vigenere(clean[:50], key)
    print(f"    طول={key_len}  مفتاح={key}  →  {plain[:40]}...")
print("")

# استخدم أفضل مرشح
best_key_len = candidates[0][0]
best_key = crack_key(clean, best_key_len)
full_plain = decrypt_vigenere(ciphertext, best_key)

print(f"  ✅ المفتاح المُستردّ (طول {best_key_len}): {best_key}")
print("")
print("  📋 النص المفكوك:")
print("  " + "-"*50)
print("  " + full_plain[:500])
if len(full_plain) > 500:
    print(f"  ... (+{len(full_plain)-500} حرف)")
print("  " + "-"*50)

# البحث عن flags
import re as _re
flags = _re.findall(r'(?:flag|FLAG|CTF|ctf)\{[^}]+\}', full_plain)
if flags:
    print("")
    print(f"  🏴 FLAGS FOUND:")
    for f in flags:
        print(f"    {f}")
PYEOF

echo ""
read -rp "  هل تريد المحاولة بمفتاح يدوي؟ (y/n): " manual
if [ "$manual" = "y" ]; then
    read -rp "  أدخل المفتاح: " manual_key
    if [ -n "$manual_key" ]; then
        echo ""
        echo -e "${GREEN}  النص المفكوك بالمفتاح '${manual_key}':${NC}"
        python3 - "$cipher_text" "$manual_key" <<'PYEOF2'
import sys
cipher, key = sys.argv[1], sys.argv[2].upper()
result = []
ki = 0
for c in cipher:
    if c.isalpha():
        shift = ord(key[ki % len(key)]) - ord('A')
        if c.isupper():
            result.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
        else:
            result.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
        ki += 1
    else:
        result.append(c)
print('  ' + ''.join(result))
PYEOF2
    fi
fi
