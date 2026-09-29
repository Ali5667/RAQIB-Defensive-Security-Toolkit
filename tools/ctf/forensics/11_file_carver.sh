#!/bin/bash
# =============================================================
#  RAQIB CTF — File Carver (binwalk-lite)
#  أداة #11: استخراج ملفات مخفية داخل ملفات أخرى
#  اللغة: Bash wrapper + Python heredoc
#         Python لأن binary search وfile carving يحتاج
#         struct/bytes operations — shell لا يكفي هنا
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🗃️  File Carver — binwalk-lite                   ║${NC}"
echo -e "${CYAN}║  استخرج ملفات مخفية داخل ملفات أخرى             ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# لو binwalk مثبت — استخدمه مباشرة (الأفضل)
if command -v binwalk >/dev/null 2>&1; then
    echo -e "  ${GREEN}[✓] binwalk مكتشف — سيُستخدم تلقائياً${NC}"
    echo ""
    read -rp "  مسار الملف: " target_file
    [ ! -f "$target_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }
    echo ""
    echo -e "  ${YELLOW}نتائج binwalk:${NC}"
    binwalk -- "$target_file"
    echo ""
    read -rp "  استخراج تلقائي؟ (y/n): " do_extract
    if [ "$do_extract" = "y" ]; then
        out_dir="raqib_carved_$(date +%s)"
        binwalk -e --directory="$out_dir" -- "$target_file"
        echo -e "  ${GREEN}تم الاستخراج في: $out_dir${NC}"
    fi
    pause
    exit 0
fi

echo -e "  ${GREY}[binwalk غير مثبت — سيُستخدم carver داخلي]${NC}"
echo ""
read -rp "  مسار الملف: " target_file
[ ! -f "$target_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }

read -rp "  مجلد الاستخراج (Enter = ./raqib_carved/): " out_dir
out_dir="${out_dir:-./raqib_carved_$(date +%s)}"
mkdir -p "$out_dir"

# Python heredoc — binary search + carving
python3 - "$target_file" "$out_dir" <<'PYEOF'
import sys, os, struct

src_path = sys.argv[1]
out_dir  = sys.argv[2]

# جدول Magic Bytes: (اسم, magic, امتداد, [end_magic اختياري])
SIGNATURES = [
    # Images
    ("JPEG",    b'\xff\xd8\xff',            ".jpg",  b'\xff\xd9'),
    ("PNG",     b'\x89PNG\r\n\x1a\n',       ".png",  b'\x00\x00\x00\x00IEND\xaeB`\x82'),
    ("GIF87",   b'GIF87a',                  ".gif",  b'\x00;'),
    ("GIF89",   b'GIF89a',                  ".gif",  b'\x00;'),
    ("BMP",     b'BM',                      ".bmp",  None),
    # Archives
    ("ZIP",     b'PK\x03\x04',             ".zip",  b'PK\x05\x06'),
    ("GZIP",    b'\x1f\x8b\x08',           ".gz",   None),
    ("BZIP2",   b'BZh',                    ".bz2",  b'\x17rE8P\x90'),
    ("7ZIP",    b'7z\xbc\xaf\x27\x1c',     ".7z",   None),
    ("RAR4",    b'Rar!\x1a\x07\x00',       ".rar",  None),
    ("RAR5",    b'Rar!\x1a\x07\x01\x00',   ".rar",  None),
    # Documents
    ("PDF",     b'%PDF',                   ".pdf",  b'%%EOF'),
    # Executables
    ("ELF",     b'\x7fELF',               ".elf",  None),
    ("PE_EXE",  b'MZ',                    ".exe",  None),
    # Media
    ("WAV",     b'RIFF',                  ".wav",  None),
    ("MP3",     b'ID3',                   ".mp3",  None),
    # Scripts / text hidden
    ("PHP",     b'<?php',                 ".php",  b'?>'),
    ("BASH",    b'#!/bin/bash',            ".sh",   None),
    ("PYTHON",  b'#!/usr/bin/python',      ".py",   None),
    # SQLite
    ("SQLITE",  b'SQLite format 3\x00',   ".db",   None),
]

with open(src_path, 'rb') as f:
    data = f.read()

total = len(data)
found = []

print(f"\n  🔍 يبحث في {total:,} بايت...")
print(f"  {'─'*50}")

for name, magic, ext, end_magic in SIGNATURES:
    pos = 0
    idx = 0
    while True:
        offset = data.find(magic, pos)
        if offset == -1:
            break

        # تخطي لو كان أول الملف وهو نفس النوع
        if offset == 0 and idx == 0:
            pos = offset + 1
            idx += 1
            continue

        # تحديد نهاية الملف المضمّن
        if end_magic:
            end_pos = data.find(end_magic, offset + len(magic))
            if end_pos != -1:
                end_pos += len(end_magic)
                chunk = data[offset:end_pos]
            else:
                # نأخذ حتى آخر الملف
                chunk = data[offset:]
        else:
            # نأخذ حتى آخر الملف (للأنواع بدون end signature)
            # لكن نقيّد الحجم الأقصى
            chunk = data[offset:offset + min(len(data) - offset, 50 * 1024 * 1024)]

        if len(chunk) < 8:
            pos = offset + 1
            idx += 1
            continue

        out_name = f"carved_{name}_{offset:08x}{ext}"
        out_path = os.path.join(out_dir, out_name)
        with open(out_path, 'wb') as out:
            out.write(chunk)

        found.append((name, offset, len(chunk), out_path))
        print(f"  ✅ [{name:10s}] offset=0x{offset:08x}  size={len(chunk):,}  → {out_name}")

        pos = offset + max(1, len(chunk))
        idx += 1

print(f"\n  {'─'*50}")
if found:
    print(f"  🏆 تم استخراج {len(found)} ملف/ملفات في: {out_dir}")
    print(f"\n  📋 ملخص:")
    for name, offset, size, path in found:
        print(f"    {name:10s}  @0x{offset:08x}  {size:>10,} bytes  → {os.path.basename(path)}")
else:
    print("  ⚠️  لم يُعثر على ملفات مضمّنة معروفة.")
    print("  💡 جرب binwalk لو مثبت — يدعم أنماط أكثر.")
print()
PYEOF

pause
