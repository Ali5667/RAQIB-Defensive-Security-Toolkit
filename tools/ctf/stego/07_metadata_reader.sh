#!/bin/bash
# =============================================================
#  RAQIB CTF — Metadata Reader
#  أداة #7: قراءة EXIF + metadata مخفية + embedded strings
#  يعمل بدون تبعيات — strings/file/exiftool اختياري
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🔍 Metadata Reader — EXIF + Hidden Data         ║${NC}"
echo -e "${CYAN}║  استخراج بيانات EXIF والـ metadata المخفية      ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  مسار الملف: " target_file
[ ! -f "$target_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }

echo ""
echo -e "${BOLD}══ 1. معلومات الملف الأساسية ══${NC}"
ls -lah -- "$target_file"
echo ""

echo -e "${BOLD}══ 2. نوع الملف الحقيقي ══${NC}"
if command -v file >/dev/null 2>&1; then
    file -- "$target_file"
else
    python3 - "$target_file" <<'PYEOF'
import sys
SIGS = {
    b'\x89PNG\r\n\x1a\n': 'PNG Image',
    b'\xff\xd8\xff':       'JPEG Image',
    b'GIF87a':             'GIF87 Image',
    b'GIF89a':             'GIF89 Image',
    b'BM':                 'BMP Image',
    b'PK\x03\x04':         'ZIP Archive',
    b'\x1f\x8b':           'GZip Archive',
    b'%PDF':               'PDF Document',
    b'MZ':                 'Windows PE',
    b'\x7fELF':            'ELF Executable',
    b'RIFF':               'RIFF (WAV/AVI)',
    b'\x00\x00\x00\x18ftyp': 'MP4 Video',
    b'\x49\x49\x2a\x00':  'TIFF (little-endian)',
    b'\x4d\x4d\x00\x2a':  'TIFF (big-endian)',
}
with open(sys.argv[1],'rb') as f:
    header = f.read(16)
detected = 'Unknown'
for sig, name in SIGS.items():
    if header.startswith(sig):
        detected = name; break
print(f"  → {detected} | hex: {header.hex()}")
PYEOF
fi
echo ""

echo -e "${BOLD}══ 3. EXIF Metadata ══${NC}"
if command -v exiftool >/dev/null 2>&1; then
    exiftool "$target_file" 2>/dev/null | head -60
else
    echo -e "  ${YELLOW}exiftool غير مثبت — محاولة استخراج EXIF يدوياً...${NC}"
    python3 - "$target_file" <<'PYEOF'
import sys, struct

def read_uint16_be(data, offset):
    return struct.unpack('>H', data[offset:offset+2])[0]

def read_uint32_be(data, offset):
    return struct.unpack('>I', data[offset:offset+4])[0]

EXIF_TAGS = {
    0x010E: 'ImageDescription', 0x010F: 'Make', 0x0110: 'Model',
    0x0112: 'Orientation',      0x011A: 'XResolution', 0x011B: 'YResolution',
    0x0128: 'ResolutionUnit',   0x0131: 'Software',    0x0132: 'DateTime',
    0x013B: 'Artist',           0x013E: 'WhitePoint',  0x0213: 'YCbCrPositioning',
    0x8298: 'Copyright',        0x8769: 'ExifIFD',     0x8825: 'GPSIFD',
    0x9000: 'ExifVersion',      0x9003: 'DateTimeOriginal', 0x9004: 'DateTimeDigitized',
    0x9286: 'UserComment',      0xA001: 'ColorSpace',  0xA002: 'PixelXDimension',
    0xA003: 'PixelYDimension',
}

with open(sys.argv[1], 'rb') as f:
    data = f.read()

found = False
# JPEG EXIF
if data[:2] == b'\xff\xd8':
    i = 2
    while i < len(data)-1:
        if data[i] != 0xFF:
            break
        marker = data[i+1]
        if marker == 0xE1:  # APP1 = EXIF
            length = read_uint16_be(data, i+2)
            app1 = data[i+4:i+2+length]
            if app1[:6] == b'Exif\x00\x00':
                tiff = app1[6:]
                byte_order = tiff[:2]
                endian = '>' if byte_order == b'MM' else '<'
                ifd_offset = struct.unpack(endian+'I', tiff[4:8])[0]
                num_entries = struct.unpack(endian+'H', tiff[ifd_offset:ifd_offset+2])[0]
                print(f"  📷 EXIF IFD entries: {num_entries}")
                for j in range(num_entries):
                    entry_offset = ifd_offset + 2 + j*12
                    tag = struct.unpack(endian+'H', tiff[entry_offset:entry_offset+2])[0]
                    typ = struct.unpack(endian+'H', tiff[entry_offset+2:entry_offset+4])[0]
                    cnt = struct.unpack(endian+'I', tiff[entry_offset+4:entry_offset+8])[0]
                    val_raw = tiff[entry_offset+8:entry_offset+12]
                    tag_name = EXIF_TAGS.get(tag, f'0x{tag:04X}')
                    if typ == 2:  # ASCII string
                        str_offset = struct.unpack(endian+'I', val_raw)[0]
                        value = tiff[str_offset:str_offset+cnt].decode('latin-1', errors='replace').strip('\x00')
                    else:
                        value = val_raw.hex()
                    print(f"  {tag_name}: {value}")
                found = True
            break
        elif marker in (0xD9, 0xDA):
            break
        else:
            length = read_uint16_be(data, i+2) if i+3 < len(data) else 0
            i += 2 + length

if not found:
    print("  لا توجد بيانات EXIF قابلة للاستخراج يدوياً.")
    print("  → قم بتثبيت exiftool للحصول على نتائج أفضل.")
PYEOF
fi
echo ""

echo -e "${BOLD}══ 4. Strings مشبوهة (flags + URLs + كلمات مرور) ══${NC}"
python3 - "$target_file" <<'PYEOF'
import sys, re, os

with open(sys.argv[1], 'rb') as f:
    data = f.read()

# استخراج strings (ASCII + UTF-16LE)
def extract_strings(data, min_len=4):
    result = []
    # ASCII
    ascii_strings = re.findall(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}', data)
    result.extend(s.decode('ascii', errors='replace') for s in ascii_strings)
    # UTF-16LE
    try:
        utf16 = data.decode('utf-16-le', errors='replace')
        utf16_strings = re.findall(r'[\x20-\x7e]{' + str(min_len) + r',}', utf16)
        result.extend(utf16_strings)
    except:
        pass
    return list(set(result))

strings = extract_strings(data)

flags    = [s for s in strings if re.search(r'(?:flag|FLAG|CTF|ctf|picoCTF)\{[^}]+\}', s)]
urls     = [s for s in strings if re.match(r'https?://', s)]
comments = [s for s in strings if re.search(r'<!--.*?-->', s)]
encoded  = [s for s in strings if re.search(r'[A-Za-z0-9+/]{30,}={0,2}$', s)]
secrets  = [s for s in strings if re.search(r'(?:password|secret|key|token|auth)\s*[:=]\s*\S+', s, re.I)]

categories = [
    ("🏴 FLAGS", flags),
    ("🌐 URLs", urls[:10]),
    ("💬 HTML Comments", comments[:5]),
    ("🔐 Secrets/Keys", secrets[:10]),
    ("📦 Base64-like strings", encoded[:5]),
]

total_found = 0
for title, items in categories:
    if items:
        print(f"  {title}:")
        for item in items:
            print(f"    {item[:120]}")
        total_found += len(items)
        print("")

if total_found == 0:
    print(f"  ✅ لا توجد strings مشبوهة واضحة.")
    print(f"  📊 إجمالي الـ strings: {len(strings)}")
    print(f"  أطول 5 strings:")
    for s in sorted(strings, key=len, reverse=True)[:5]:
        print(f"    {s[:80]}")
PYEOF

echo ""
echo -e "${BOLD}══ 5. فحص Steghide/StegSeek ══${NC}"
if command -v steghide >/dev/null 2>&1; then
    echo -e "  ${YELLOW}steghide متوفر — محاولة بكلمة مرور فارغة:${NC}"
    steghide extract -sf "$target_file" -p "" -f 2>/dev/null && \
        echo -e "  ${GREEN}✅ تم استخراج بيانات مخفية!${NC}" || \
        echo "  → لا توجد بيانات مخفية بكلمة مرور فارغة"
else
    echo -e "  ${GREY}steghide غير مثبت (اختياري)${NC}"
fi
