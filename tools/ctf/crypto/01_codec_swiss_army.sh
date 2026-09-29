#!/bin/bash
# =============================================================
#  RAQIB CTF — Codec Swiss Army Knife
#  أداة #1: تحليل تلقائي وفك تشفير متعدد
#  تدعم: Base64, Hex, ROT13, ROT47, XOR (brute), Caesar (brute),
#         URL encoding, Binary, Morse code
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🔐 Codec Swiss Army Knife                       ║${NC}"
echo -e "${CYAN}║  فك تشفير تلقائي — يجرب كل الأساليب الشائعة   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "  ${YELLOW}1)${NC} من ملف"
echo -e "  ${YELLOW}2)${NC} من نص مباشر"
read -rp "  اختر: " src_choice

if [ "$src_choice" = "1" ]; then
    read -rp "  مسار الملف: " input_file
    [ ! -f "$input_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }
    input_data="$(cat -- "$input_file")"
else
    read -rp "  أدخل النص المشفر: " input_data
fi

[ -z "$input_data" ] && { echo -e "${RED}لا يوجد مدخل${NC}"; exit 1; }

python3 - "$input_data" <<'PYEOF'
import sys, base64, binascii, urllib.parse, re, string

data = sys.argv[1].strip()

MORSE_TABLE = {
    '.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E', '..-.':'F',
    '--.':'G', '....':'H', '..':'I', '.---':'J', '-.-':'K', '.-..':'L',
    '--':'M', '-.':'N', '---':'O', '.--.':'P', '--.-':'Q', '.-.':'R',
    '...':'S', '-':'T', '..-':'U', '...-':'V', '.--':'W', '-..-':'X',
    '-.--':'Y', '--..':'Z', '-----':'0', '.----':'1', '..---':'2',
    '...--':'3', '....-':'4', '.....':'5', '-....':'6', '--...':'7',
    '---..':'8', '----.':'9',
}

results = []
found_flags = []

FLAG_PATTERNS = [
    r'picoCTF\{[^}]+\}',
    r'[Ff][Ll][Aa][Gg]\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'[A-Z0-9_]+\{[^}]+\}',
]

def check_flag(text, method):
    for pat in FLAG_PATTERNS:
        for m in re.finditer(pat, text):
            found_flags.append((method, m.group()))

def try_decode(name, text):
    check_flag(text, name)
    results.append((name, text[:200] + ("..." if len(text) > 200 else "")))

# ─── Base64 ───────────────────────────────────────────────────
try:
    padded = data + '=' * (-len(data) % 4)
    decoded = base64.b64decode(padded, validate=True).decode('utf-8', errors='replace')
    try_decode("Base64 → UTF-8", decoded)
except Exception:
    pass

# ─── Base64 (URL-safe) ───────────────────────────────────────
try:
    padded = data.replace('-','+').replace('_','/') + '=' * (-len(data) % 4)
    decoded = base64.b64decode(padded).decode('utf-8', errors='replace')
    try_decode("Base64 URL-safe", decoded)
except Exception:
    pass

# ─── Hex ─────────────────────────────────────────────────────
try:
    clean_hex = data.replace(' ','').replace('0x','').replace('\\x','')
    if re.match(r'^[0-9a-fA-F]+$', clean_hex) and len(clean_hex) % 2 == 0:
        decoded = bytes.fromhex(clean_hex).decode('utf-8', errors='replace')
        try_decode("Hex → UTF-8", decoded)
except Exception:
    pass

# ─── ROT13 ───────────────────────────────────────────────────
rot13 = data.translate(str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
try_decode("ROT13", rot13)

# ─── ROT47 ───────────────────────────────────────────────────
rot47 = ''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in data)
try_decode("ROT47", rot47)

# ─── URL Decode ──────────────────────────────────────────────
try:
    url_dec = urllib.parse.unquote(data)
    if url_dec != data:
        try_decode("URL Decode", url_dec)
except Exception:
    pass

# ─── Binary ──────────────────────────────────────────────────
try:
    clean_bin = data.replace(' ','').replace('\n','')
    if re.match(r'^[01]+$', clean_bin) and len(clean_bin) % 8 == 0:
        chars = [chr(int(clean_bin[i:i+8], 2)) for i in range(0, len(clean_bin), 8)]
        decoded = ''.join(chars)
        try_decode("Binary → ASCII", decoded)
except Exception:
    pass

# ─── Morse ───────────────────────────────────────────────────
try:
    if re.match(r'^[\.\-\s/]+$', data):
        words = data.split('/')
        decoded_words = []
        for word in words:
            chars = word.strip().split()
            decoded_words.append(''.join(MORSE_TABLE.get(c, '?') for c in chars))
        morse_out = ' '.join(decoded_words)
        try_decode("Morse Code", morse_out)
except Exception:
    pass

# ─── Caesar Brute Force ──────────────────────────────────────
letters = [c for c in data if c.isalpha()]
if letters:
    for shift in range(1, 26):
        shifted = []
        for c in data:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shifted.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                shifted.append(c)
        candidate = ''.join(shifted)
        # فقط نُضيف Caesar لو كُشف flag أو بدا نص إنجليزي معقول
        if any(re.search(p, candidate) for p in FLAG_PATTERNS):
            try_decode(f"Caesar +{shift}", candidate)

# ─── XOR single-byte brute ───────────────────────────────────
try:
    raw_bytes = None
    try:
        clean_hex = data.replace(' ','').replace('0x','').replace('\\x','')
        if re.match(r'^[0-9a-fA-F]+$', clean_hex) and len(clean_hex) % 2 == 0:
            raw_bytes = bytes.fromhex(clean_hex)
    except Exception:
        pass
    if raw_bytes is None:
        raw_bytes = data.encode('latin-1', errors='replace')
    for key in range(1, 256):
        xored = bytes([b ^ key for b in raw_bytes])
        try:
            candidate = xored.decode('utf-8', errors='strict')
            if any(re.search(p, candidate) for p in FLAG_PATTERNS):
                try_decode(f"XOR key=0x{key:02x}", candidate)
        except Exception:
            pass
except Exception:
    pass

# ─── الإخراج ─────────────────────────────────────────────────
print("\n" + "═"*55)
print("  🏴 FLAGS FOUND:" if found_flags else "  ⚠️  لم يُعثر على flag بصيغة معروفة")
print("═"*55)
for method, flag in found_flags:
    print(f"  ✅ [{method}]  {flag}")

print("\n" + "─"*55)
print("  📋 نتائج فك التشفير:")
print("─"*55)
seen = set()
for method, text in results:
    key = text.strip()[:80]
    if key in seen:
        continue
    seen.add(key)
    printable = sum(1 for c in text if c.isprintable())
    ratio = printable / max(len(text), 1)
    if ratio > 0.7:  # فقط نتائج تبدو نصاً حقيقياً
        print(f"\n  [{method}]")
        print(f"  {text[:300]}")

if not results:
    print("  لا توجد نتائج قابلة للقراءة.")
print()
PYEOF

pause
