#!/bin/bash
# =============================================================
#  RAQIB CTF — LSB Extractor
#  أداة #6: استخراج بيانات مخفية بطريقة LSB من PNG/BMP
#  يعمل بدون تبعيات خارجية إن أمكن — Python3 + Pillow اختياري
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🖼️  LSB Extractor — Least Significant Bit      ║${NC}"
echo -e "${CYAN}║  استخراج بيانات مخفية من PNG/BMP بطريقة LSB    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  مسار الصورة (PNG/BMP): " img_file
[ ! -f "$img_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }

echo ""
echo -e "  ${YELLOW}1)${NC} استخراج LSB (البت الأقل أهمية) من كل القنوات RGB"
echo -e "  ${YELLOW}2)${NC} استخراج من قناة محددة (R أو G أو B أو A)"
echo -e "  ${YELLOW}3)${NC} تجربة أنماط شائعة (CTF brute)"
echo -e "  ${YELLOW}4)${NC} طباعة بيانات الصورة الخام (strings + magic)"
read -rp "  اختر: " mode

case "$mode" in
    1|2|3)
        if ! python3 -c "from PIL import Image" 2>/dev/null; then
            echo -e "${YELLOW}  ⚠️  مكتبة Pillow غير مثبتة — الاستخراج يتطلبها.${NC}"
            echo -e "  جرّب: pip3 install Pillow"
            echo ""
            echo -e "${CYAN}  محاولة الاستخراج بـ strings بدلاً من ذلك:${NC}"
            strings -- "$img_file" | grep -Ei 'flag|ctf|\{[^}]+\}' | head -20
            exit 1
        fi
        ;;
esac

python3 - "$img_file" "$mode" <<'PYEOF'
import sys, os
try:
    from PIL import Image
    PIL_OK = True
except ImportError:
    PIL_OK = False

img_path = sys.argv[1]
mode = sys.argv[2]

def bits_to_bytes(bits):
    chars = []
    for i in range(0, len(bits)-7, 8):
        byte_bits = bits[i:i+8]
        byte_val = int(''.join(map(str, byte_bits)), 2)
        chars.append(byte_val)
    return bytes(chars)

def extract_lsb(img, channels='RGB', bit_plane=0):
    """استخراج بيانات LSB من قنوات محددة"""
    if img.mode not in ('RGB', 'RGBA', 'L'):
        img = img.convert('RGB')
    pixels = list(img.getdata())
    bits = []
    ch_map = {'R':0,'G':1,'B':2,'A':3}

    for px in pixels:
        if not isinstance(px, (tuple, list)):
            px = (px,)
        for ch in channels:
            idx = ch_map.get(ch, 0)
            if idx < len(px):
                bits.append((px[idx] >> bit_plane) & 1)

    raw = bits_to_bytes(bits)
    return raw

def find_flags(data):
    import re
    try:
        text = data.decode('utf-8', errors='replace')
    except:
        text = str(data)
    flags = re.findall(r'(?:flag|FLAG|CTF|ctf|picoCTF)\{[^}]{1,100}\}', text)
    return flags, text

if not PIL_OK:
    print("  ❌ Pillow غير متاحة")
    sys.exit(1)

img = Image.open(img_path)
w, h = img.size
print(f"  📐 الحجم: {w}×{h}  |  الوضع: {img.mode}")
print(f"  💾 الحجم الكلي للبيكسلات: {w*h} px")
print("")

if mode == '1':
    print("  🔍 استخراج LSB من RGB:")
    for ch in ['R', 'G', 'B', 'RGB']:
        raw = extract_lsb(img, ch)
        flags, txt = find_flags(raw)
        printable = ''.join(c if 32<=ord(c)<127 else '.' for c in txt[:80])
        print(f"    [{ch}]: {printable}")
        if flags:
            print(f"    🏴 FLAG: {flags}")

elif mode == '2':
    ch = input("  القناة (R/G/B/A/RGB/RGBA): ").strip().upper() or 'RGB'
    raw = extract_lsb(img, ch)
    flags, txt = find_flags(raw)
    print(f"\n  📋 أول 200 حرف مقروء:")
    printable = ''.join(c if 32<=ord(c)<127 else '.' for c in txt[:200])
    print("  " + printable)
    if flags:
        print(f"\n  🏴 FLAGS: {flags}")
    # اعرض كـ hex إن لم يكن مقروء
    printable_count = sum(1 for c in txt[:200] if 32<=ord(c)<127)
    if printable_count < 50:
        print(f"\n  🔢 Hex dump:")
        print("  " + raw[:64].hex(' '))

elif mode == '3':
    print("  🔎 تجربة أنماط LSB شائعة...")
    found_anything = False
    combos = [
        ('RGB', 0, "Standard RGB LSB"),
        ('R',   0, "Red channel only"),
        ('G',   0, "Green channel only"),
        ('B',   0, "Blue channel only"),
        ('RGB', 1, "Bit-plane 1 RGB"),
        ('RGB', 2, "Bit-plane 2 RGB"),
    ]
    for ch, bit, desc in combos:
        raw = extract_lsb(img, ch, bit)
        flags, txt = find_flags(raw)
        printable = ''.join(c if 32<=ord(c)<127 else '' for c in txt[:100])
        readable = len([c for c in txt[:200] if 32<=ord(c)<127]) / 200
        marker = "✅" if flags or readable > 0.7 else "  "
        print(f"  {marker} [{desc}]: {printable[:60]}")
        if flags:
            print(f"     🏴 FLAG: {flags}")
            found_anything = True
    if not found_anything:
        print("\n  ⚠️  لم يُعثر على flag واضح — جرّب stegsolve أو steghide")

elif mode == '4':
    import subprocess
    print("  🔢 magic bytes:")
    with open(img_path, 'rb') as f:
        header = f.read(16)
    print("  " + header.hex(' '))
    print("")
    result = subprocess.run(['strings', '-n', '4', img_path],
                            capture_output=True, text=True, errors='replace')
    lines = result.stdout.splitlines()
    import re
    flags = [l for l in lines if re.search(r'(?:flag|FLAG|CTF|ctf)\{', l)]
    suspicious = [l for l in lines if re.search(r'http|eval|exec|base64|php', l, re.I)]
    print(f"  📝 إجمالي الـ strings: {len(lines)}")
    if flags:
        print(f"\n  🏴 Flags:")
        for f in flags: print(f"    {f}")
    if suspicious:
        print(f"\n  ⚠️  Suspicious strings:")
        for s in suspicious[:10]: print(f"    {s}")
    if not flags and not suspicious:
        print("\n  أول 20 سطر من الـ strings:")
        for l in lines[:20]: print(f"  {l}")
PYEOF
