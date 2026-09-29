#!/bin/bash
# =============================================================
#  RAQIB CTF — Frequency Analysis
#  أداة #2: تحليل تردد الأحرف — يساعد على كسر Substitution
#  و Caesar ciphers بالاعتماد على توزيع أحرف اللغة الإنجليزية
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  📊 Frequency Analysis                           ║${NC}"
echo -e "${CYAN}║  تحليل تردد الأحرف لكسر الشفرات البسيطة       ║${NC}"
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
    echo -e "  أدخل النص المشفر (CTRL+D للإنهاء):"
    cipher_text="$(cat)"
fi

[ -z "$cipher_text" ] && { echo -e "${RED}لا يوجد نص${NC}"; exit 1; }

python3 - "$cipher_text" <<'PYEOF'
import sys, re, collections, string

text = sys.argv[1]

# ─── English letter frequency (reference) ────────────────────
EN_FREQ = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# ─── Count letters in ciphertext ─────────────────────────────
letter_counts = collections.Counter(c.upper() for c in text if c.isalpha())
total = sum(letter_counts.values())

if total == 0:
    print("⚠️  لا يوجد أحرف في النص.")
    sys.exit(0)

sorted_letters = [l for l, _ in letter_counts.most_common()]

print("\n" + "═"*55)
print("  📊 توزيع الأحرف في النص المشفر:")
print("═"*55)

# رسم Bar chart نصي
for letter, count in letter_counts.most_common(26):
    pct = count / total * 100
    bar = "█" * int(pct * 1.5)
    print(f"  {letter} │{bar:<30} {count:4d} ({pct:.1f}%)")

# ─── الخريطة المقترحة (Substitution guess) ───────────────────
print("\n" + "─"*55)
print("  🗺️  الخريطة المقترحة (بناءً على تردد الإنجليزية):")
print("─"*55)
print("  مشفّر → واضح")
for i, cipher_char in enumerate(sorted_letters[:len(EN_FREQ)]):
    plain_char = EN_FREQ[i]
    print(f"    {cipher_char}  →  {plain_char}")

# ─── Caesar shift guess ───────────────────────────────────────
most_common = sorted_letters[0] if sorted_letters else None
if most_common:
    e_shift = (ord(most_common) - ord('E')) % 26
    t_shift = (ord(most_common) - ord('T')) % 26
    print("\n" + "─"*55)
    print("  💡 تخمين Caesar Shift:")
    print(f"     لو الأكثر تكراراً ({most_common}) = E  ← shift = {e_shift}")
    print(f"     لو الأكثر تكراراً ({most_common}) = T  ← shift = {t_shift}")

    # تطبيق الـ shifts المقترحة
    print("\n  تطبيق shift={}: ".format(e_shift), end="")
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c.upper()) - ord('A') - e_shift) % 26 + base))
        else:
            result.append(c)
    print(''.join(result)[:200])

# ─── Index of Coincidence ────────────────────────────────────
ic = sum(n * (n - 1) for n in letter_counts.values()) / (total * (total - 1)) if total > 1 else 0
print("\n" + "─"*55)
print(f"  📐 Index of Coincidence (IC) = {ic:.4f}")
if ic > 0.065:
    print("     → قريب من الإنجليزية (0.065) — على الأرجح Substitution أو Caesar")
elif ic > 0.045:
    print("     → IC متوسط — ربما Vigenère بـ key قصير")
else:
    print("     → IC منخفض — يشير لـ Vigenère بـ key طويل أو transposition")
print()
PYEOF

pause
