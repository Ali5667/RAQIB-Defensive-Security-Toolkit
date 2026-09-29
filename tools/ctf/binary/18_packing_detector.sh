#!/bin/bash
# =============================================================
#  RAQIB CTF — Packing Detector
#  أداة #18: كشف UPX + packers شائعة من signatures
#  يعمل بـ Python3 فقط — بدون تبعيات
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  📦 Packing Detector — UPX + Packer Signatures  ║${NC}"
echo -e "${CYAN}║  كشف التعبئة والـ obfuscation في الملفات         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  مسار الملف: " bin_file
[ ! -f "$bin_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }

echo ""
echo -e "${BOLD}══ 1. معلومات أساسية ══${NC}"
ls -lah -- "$bin_file"
command -v file >/dev/null 2>&1 && file -- "$bin_file"
echo ""

echo -e "${BOLD}══ 2. Packer Detection ══${NC}"

# فحص UPX المباشر
if command -v upx >/dev/null 2>&1; then
    echo -e "  ${GREEN}UPX متوفر — فحص مباشر:${NC}"
    upx -t "$bin_file" 2>&1 | head -5
    echo ""
fi

python3 - "$bin_file" <<'PYEOF'
import sys, re, math, struct

with open(sys.argv[1], 'rb') as f:
    data = f.read()

# ─── Packer Signatures ───
PACKER_SIGS = [
    (b'UPX!',           'UPX (نسخة جديدة)'),
    (b'UPX0',           'UPX (قسم 0)'),
    (b'UPX1',           'UPX (قسم 1)'),
    (b'UPX2',           'UPX (قسم 2)'),
    (b'$Info: This file is packed with the UPX', 'UPX (قديم)'),
    (b'MPRESS1',        'MPRESS Packer'),
    (b'MPRESS2',        'MPRESS Packer'),
    (b'Themida',        'Themida Protector'),
    (b'.nsp0',          'NSPack'),
    (b'PECompact2',     'PECompact'),
    (b'MEW',            'MEW Packer'),
    (b'PKLITE',         'PKLite Packer'),
    (b'ASPack',         'ASPack'),
    (b'ExeStealth',     'ExeStealth'),
    (b'!This program cannot be run',  'Standard DOS stub'),
    (b'Rar!',           'RAR SFX Archive'),
    (b'7z\xbc\xaf\x27\x1c', '7-Zip SFX Archive'),
]

found_packers = []
for sig, name in PACKER_SIGS:
    if sig in data:
        found_packers.append(name)

if found_packers:
    print("  🔴 Packers/Protectors مكتشفة:")
    for p in found_packers:
        print(f"    ✔ {p}")
else:
    print("  ✅ لا توجد signatures معروفة لأدوات التعبئة")

print("")

# ─── Entropy Analysis ───
def entropy(data_chunk):
    if not data_chunk:
        return 0
    freq = [0]*256
    for b in data_chunk:
        freq[b] += 1
    n = len(data_chunk)
    ent = 0
    for f in freq:
        if f > 0:
            p = f/n
            ent -= p * math.log2(p)
    return ent

full_entropy = entropy(data)
print(f"  📊 Entropy الكلي: {full_entropy:.3f} / 8.000")
if full_entropy > 7.2:
    print(f"  🔴 إنتروبيا عالية جداً → على الأرجح مُعبَّأ/مشفَّر")
elif full_entropy > 6.5:
    print(f"  🟡 إنتروبيا مرتفعة → قد يكون مضغوطاً")
else:
    print(f"  🟢 إنتروبيا طبيعية → على الأرجح غير مُعبَّأ")

# entropy للـ sections (إن ELF)
if data[:4] == b'\x7fELF':
    ei_class = data[4]
    endian = '<' if data[5] == 1 else '>'
    chunk_size = len(data) // 4
    print(f"\n  📈 Entropy بالأرباع:")
    for i in range(4):
        chunk = data[i*chunk_size:(i+1)*chunk_size]
        e = entropy(chunk)
        bar = '█' * int(e * 3)
        print(f"    Q{i+1}: {e:.3f}  {bar}")

print("")

# ─── Section names مشبوهة (PE) ───
suspicious_sections = []
pe_sections = [b'.text', b'.data', b'.rdata', b'.bss', b'.rsrc', b'.reloc', b'.pdata']
found_sections = re.findall(rb'\.[a-zA-Z0-9_]{1,7}\x00', data)
for sec in found_sections:
    sec_name = sec.strip(b'\x00')
    if sec_name not in pe_sections:
        suspicious_sections.append(sec_name.decode('ascii', errors='replace'))

if suspicious_sections:
    unique_secs = list(set(suspicious_sections))
    print(f"  ⚠️  Sections غير معتادة:")
    for s in unique_secs[:10]: print(f"    {s}")

# ─── Import Table analysis (PE) ───
if data[:2] == b'MZ':
    print(f"\n  🪟 Windows PE detected")
    # بحث عن imports
    imports = re.findall(rb'[A-Za-z0-9_]{3,}\.(dll|exe)', data, re.I)
    if imports:
        unique_dlls = list(set(m.decode('ascii', errors='replace') for m in set(b'.'.join(m) for m in
                                [re.split(rb'\.', imp) for imp in set(b''.join([b[0].encode() if isinstance(b[0],str) else b[0], b'.', b[1]]) for b in [(m,m) for m in imports])][:1])))
    dll_names = list(set(re.findall(rb'[A-Z][A-Za-z0-9_]+\.(dll|DLL)', data)))
    if dll_names:
        print(f"  📚 DLLs مستوردة:")
        for dll in dll_names[:15]:
            print(f"    {dll.decode('ascii', errors='replace')}")

# فحص TLS callbacks (anti-debug)
if b'TlsCallback' in data or b'.tls' in data:
    print(f"\n  ⚠️  TLS Callbacks مكتشفة — قد يكون هناك anti-debug")
PYEOF
echo ""

echo -e "${BOLD}══ 3. فك تعبئة UPX (تلقائي) ══${NC}"
if command -v upx >/dev/null 2>&1; then
    if python3 -c "
import sys
with open('$bin_file','rb') as f:
    data=f.read()
print('yes' if b'UPX' in data else 'no')
" | grep -q "yes"; then
        echo -e "  ${YELLOW}UPX مكتشف — محاولة فك التعبئة...${NC}"
        unpacked="/tmp/raqib_unpacked_$$.bin"
        cp "$bin_file" "$unpacked"
        if upx -d "$unpacked" 2>/dev/null; then
            echo -e "  ${GREEN}✅ تم فك التعبئة: $unpacked${NC}"
            echo -e "  ${CYAN}معلومات الملف المفكوك:${NC}"
            file -- "$unpacked" 2>/dev/null
        else
            echo -e "  ${RED}تعذّر فك التعبئة (قد يكون محمياً)${NC}"
            rm -f "$unpacked"
        fi
    else
        echo -e "  ${GREY}UPX غير مكتشف في الملف${NC}"
    fi
else
    echo -e "  ${GREY}UPX غير مثبت (اختياري) — apt install upx${NC}"
fi

echo ""
echo -e "${BOLD}══ 4. توصيات ══${NC}"
python3 - "$bin_file" <<'PYEOF'
import sys, math

with open(sys.argv[1], 'rb') as f:
    data = f.read()

freq = [0]*256
for b in data: freq[b] += 1
n = len(data)
ent = -sum((f/n)*math.log2(f/n) for f in freq if f > 0)

recommendations = []
if b'UPX' in data:
    recommendations.append("→ upx -d <file>  لفك تعبئة UPX")
if ent > 7.2:
    recommendations.append("→ قد تحتاج dynamic analysis (GDB/strace) لأن الكود مشفّر")
if b'\x7fELF' in data[:4]:
    recommendations.append("→ strace ./binary  لمراقبة system calls")
    recommendations.append("→ ltrace ./binary  لمراقبة library calls")
    recommendations.append("→ gdb ./binary     لـ dynamic debugging")
if b'MZ' in data[:2]:
    recommendations.append("→ استخدم x64dbg أو OllyDbg للتحليل الديناميكي")
    recommendations.append("→ strings binary | grep -i flag")

if recommendations:
    for r in recommendations: print(f"  {r}")
else:
    print("  ✅ لا توجد توصيات خاصة — جرّب strings أو static analysis عادي")
PYEOF
