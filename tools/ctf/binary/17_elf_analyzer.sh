#!/bin/bash
# =============================================================
#  RAQIB CTF — ELF Analyzer
#  أداة #17: تحليل ملفات ELF بدون objdump إلزامي
#  يعمل بـ Python3 فقط عند غياب البايناري tools
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ⚙️  ELF Analyzer — Headers/Sections/Symbols    ║${NC}"
echo -e "${CYAN}║  تحليل ملفات ELF بدون objdump إلزامي            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  مسار الملف (ELF/PE/Binary): " bin_file
[ ! -f "$bin_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }

echo ""

echo -e "${BOLD}══ 1. نوع الملف ══${NC}"
command -v file >/dev/null 2>&1 && file -- "$bin_file" || \
    python3 - "$bin_file" <<'PYEOF'
import sys
SIGS = {
    b'\x7fELF': 'ELF Executable/Library',
    b'MZ':      'Windows PE (EXE/DLL)',
    b'\xca\xfe\xba\xbe': 'Mach-O Fat Binary',
    b'\xce\xfa\xed\xfe': 'Mach-O 32-bit',
    b'\xcf\xfa\xed\xfe': 'Mach-O 64-bit',
    b'PK\x03\x04': 'ZIP/JAR/APK',
    b'\x1f\x8b': 'GZip',
}
with open(sys.argv[1], 'rb') as f:
    header = f.read(16)
for sig, name in SIGS.items():
    if header.startswith(sig):
        print(f"  → {name}")
        break
else:
    print(f"  → Unknown ({header[:8].hex()})")
PYEOF
echo ""

echo -e "${BOLD}══ 2. ELF Header Analysis ══${NC}"
python3 - "$bin_file" <<'PYEOF'
import sys, struct, os

with open(sys.argv[1], 'rb') as f:
    data = f.read()

if data[:4] != b'\x7fELF':
    print("  ليس ملف ELF — تخطّ تحليل ELF Header")
    sys.exit(0)

ei_class = data[4]  # 1=32bit, 2=64bit
ei_data  = data[5]  # 1=LE, 2=BE
ei_version = data[6]
ei_osabi = data[7]

CLASS_MAP = {1: 'ELF32 (32-bit)', 2: 'ELF64 (64-bit)'}
DATA_MAP  = {1: 'LSB (Little-Endian)', 2: 'MSB (Big-Endian)'}
OSABI_MAP = {0:'System V', 3:'Linux', 9:'FreeBSD', 0xFF:'Standalone'}

endian = '<' if ei_data == 1 else '>'

if ei_class == 2:  # 64-bit
    fmt = endian + 'HHIQQQIHHHHHH'
    size = struct.calcsize(fmt)
    if len(data) >= 4 + size:
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
         e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            struct.unpack(fmt, data[4:4+size])
else:  # 32-bit
    fmt = endian + 'HHIIIIIHHHHHH'
    size = struct.calcsize(fmt)
    if len(data) >= 4 + size:
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
         e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = \
            struct.unpack(fmt, data[4:4+size])
    else:
        e_type, e_machine, e_entry = 0, 0, 0
        e_phnum, e_shnum = 0, 0

TYPE_MAP = {0:'ET_NONE', 1:'ET_REL', 2:'ET_EXEC', 3:'ET_DYN', 4:'ET_CORE'}
MACHINE_MAP = {3:'x86', 40:'ARM', 62:'x86-64', 183:'AArch64',
               8:'MIPS', 20:'PowerPC', 21:'PowerPC64'}

print(f"  Class:       {CLASS_MAP.get(ei_class, str(ei_class))}")
print(f"  Data:        {DATA_MAP.get(ei_data, str(ei_data))}")
print(f"  OS/ABI:      {OSABI_MAP.get(ei_osabi, str(ei_osabi))}")
print(f"  Type:        {TYPE_MAP.get(e_type, str(e_type))}")
print(f"  Machine:     {MACHINE_MAP.get(e_machine, str(e_machine))}")
print(f"  Entry Point: 0x{e_entry:016x}")
print(f"  Sections:    {e_shnum}")
print(f"  Segments:    {e_phnum}")
PYEOF
echo ""

echo -e "${BOLD}══ 3. Sections و Symbols ══${NC}"
if command -v objdump >/dev/null 2>&1; then
    echo -e "  ${GREEN}objdump متوفر:${NC}"
    echo -e "  ${CYAN}Sections:${NC}"
    objdump -h "$bin_file" 2>/dev/null | head -25
    echo ""
    echo -e "  ${CYAN}Dynamic symbols:${NC}"
    objdump -T "$bin_file" 2>/dev/null | head -20
elif command -v readelf >/dev/null 2>&1; then
    echo -e "  ${GREEN}readelf متوفر:${NC}"
    readelf -S "$bin_file" 2>/dev/null | head -30
else
    echo -e "  ${YELLOW}objdump/readelf غير متوفر — تحليل sections يدوياً${NC}"
fi
echo ""

echo -e "${BOLD}══ 4. Strings مثيرة للاهتمام ══${NC}"
python3 - "$bin_file" <<'PYEOF'
import sys, re

with open(sys.argv[1], 'rb') as f:
    data = f.read()

strings = re.findall(rb'[\x20-\x7e]{4,}', data)
strings = [s.decode('ascii', errors='replace') for s in strings]

flags   = [s for s in strings if re.search(r'(?:flag|FLAG|CTF|ctf|picoCTF)\{[^}]+\}', s)]
urls    = [s for s in strings if re.match(r'https?://', s)]
cmds    = [s for s in strings if re.search(r'system|exec|popen|/bin/sh|/bin/bash|cmd\.exe|powershell', s, re.I)]
formats = [s for s in strings if re.match(r'%[0-9]*[sdxXopf]', s) and len(s) < 100]  # printf formats
paths   = [s for s in strings if re.match(r'(/[a-zA-Z0-9_.-]+){2,}', s)]

print(f"  📊 إجمالي strings: {len(strings)}")
print("")

if flags:
    print(f"  🏴 FLAGS:")
    for f in flags: print(f"    {f}")
if urls:
    print(f"\n  🌐 URLs:")
    for u in urls[:5]: print(f"    {u}")
if cmds:
    print(f"\n  ⚠️  Shell Commands:")
    for c in cmds[:5]: print(f"    {c}")
if paths:
    print(f"\n  📁 File Paths:")
    for p in paths[:10]: print(f"    {p}")
if formats:
    print(f"\n  🖨️  Format Strings (بحث format string vuln):")
    for f in formats[:5]: print(f"    {f!r}")

# البحث عن hardcoded credentials
creds = [s for s in strings if re.search(r'(?:password|passwd|secret|admin|root)\s*[=:]\s*\S+', s, re.I)]
if creds:
    print(f"\n  🔑 Hardcoded Credentials:")
    for c in creds[:5]: print(f"    {c[:80]}")
PYEOF
echo ""

echo -e "${BOLD}══ 5. Security Features ══${NC}"
if command -v checksec >/dev/null 2>&1; then
    checksec --file="$bin_file" 2>/dev/null
elif command -v python3 >/dev/null 2>&1; then
    python3 - "$bin_file" <<'PYEOF'
import sys, struct

with open(sys.argv[1], 'rb') as f:
    data = f.read()

if data[:4] != b'\x7fELF':
    print("  ليس ELF — تعذّر فحص security features")
    sys.exit(0)

# فحص PIE
ei_class = data[4]
endian = '<' if data[5] == 1 else '>'
e_type = struct.unpack(endian+'H', data[16:18])[0]

print("  Security Features:")
pie = "✅ PIE (Position Independent)" if e_type == 3 else "❌ No PIE"
print(f"    {pie}")

# فحص Stack Canary (بحث عن __stack_chk_fail)
has_canary = b'__stack_chk_fail' in data
print(f"    {'✅ Stack Canary' if has_canary else '❌ No Stack Canary'}")

# RELRO (بحث عن .got.plt)
has_relro = b'.got.plt' in data
print(f"    {'⚠️  Partial RELRO' if has_relro else '✅ Full RELRO (likely)'}")

# NX — صعب كشفه بدون readelf
print(f"    ℹ️  NX: استخدم checksec للتحقق الدقيق")
PYEOF
fi

echo ""
echo -e "${BOLD}══ 6. Disassembly (main function) ══${NC}"
if command -v objdump >/dev/null 2>&1; then
    echo -e "  ${CYAN}أول 30 تعليمة:${NC}"
    objdump -d "$bin_file" 2>/dev/null | grep -A 30 "<main>" | head -35
else
    echo -e "  ${GREY}objdump غير متوفر لعرض الـ disassembly${NC}"
fi
