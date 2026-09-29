#!/bin/bash
# =============================================================
#  RAQIB CTF — PCAP Analyzer
#  أداة #10: تحليل ملفات PCAP بدون Wireshark
#  يعتمد على tcpdump/tshark + strings + python3
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  📡 PCAP Analyzer — بدون Wireshark               ║${NC}"
echo -e "${CYAN}║  تحليل حزم الشبكة، HTTP، DNS، credentials       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  مسار ملف PCAP: " pcap_file
[ ! -f "$pcap_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }

echo ""

# ─── تحقق من الأدوات ───
HAS_TSHARK=0; HAS_TCPDUMP=0
command -v tshark   >/dev/null 2>&1 && HAS_TSHARK=1
command -v tcpdump  >/dev/null 2>&1 && HAS_TCPDUMP=1

echo -e "${BOLD}══ 1. معلومات الملف ══${NC}"
ls -lah -- "$pcap_file"
python3 - "$pcap_file" <<'PYEOF'
import sys, struct
with open(sys.argv[1],'rb') as f:
    magic = f.read(4)
if magic == b'\xd4\xc3\xb2\xa1':
    print("  صيغة: pcap (little-endian)")
elif magic == b'\xa1\xb2\xc3\xd4':
    print("  صيغة: pcap (big-endian)")
elif magic[:4] == b'\x0a\x0d\x0d\x0a':
    print("  صيغة: pcapng")
else:
    print(f"  صيغة: غير معروفة ({magic.hex()})")
PYEOF
echo ""

echo -e "${BOLD}══ 2. ملخص الجلسات ══${NC}"
if [ "$HAS_TSHARK" = "1" ]; then
    echo -e "  ${GREEN}tshark متوفر:${NC}"
    echo -e "  📊 إحصائيات البروتوكولات:"
    tshark -r "$pcap_file" -q -z io,phs 2>/dev/null | head -30
    echo ""
    echo -e "  🌐 أبرز المحادثات (IP):"
    tshark -r "$pcap_file" -q -z conv,ip 2>/dev/null | head -20
elif [ "$HAS_TCPDUMP" = "1" ]; then
    echo -e "  ${YELLOW}tcpdump (نتائج محدودة):${NC}"
    tcpdump -r "$pcap_file" -n 2>/dev/null | head -30
else
    echo -e "  ${YELLOW}لا توجد أدوات PCAP — تحليل خام:${NC}"
    python3 - "$pcap_file" <<'PYEOF'
import sys, struct, socket, collections

with open(sys.argv[1], 'rb') as f:
    data = f.read()

# pcap (little-endian)
if data[:4] != b'\xd4\xc3\xb2\xa1':
    print("  صيغة PCAP غير قياسية — تعذّر التحليل الكامل")
    sys.exit(0)

offset = 24  # تخطّ global header
packets = []
while offset + 16 <= len(data):
    ts_sec, ts_usec, cap_len, orig_len = struct.unpack('<IIII', data[offset:offset+16])
    pkt = data[offset+16:offset+16+cap_len]
    packets.append(pkt)
    offset += 16 + cap_len

print(f"  📦 إجمالي الحزم: {len(packets)}")

# تحليل Ethernet/IP
src_ips = collections.Counter()
dst_ips = collections.Counter()
for pkt in packets:
    if len(pkt) < 34:
        continue
    eth_type = struct.unpack('>H', pkt[12:14])[0]
    if eth_type == 0x0800:  # IPv4
        src = socket.inet_ntoa(pkt[26:30])
        dst = socket.inet_ntoa(pkt[30:34])
        src_ips[src] += 1
        dst_ips[dst] += 1

print(f"\n  🔝 أكثر IPs مصدراً:")
for ip, cnt in src_ips.most_common(5):
    print(f"    {ip}: {cnt} حزمة")
print(f"\n  🔝 أكثر IPs وجهة:")
for ip, cnt in dst_ips.most_common(5):
    print(f"    {ip}: {cnt} حزمة")
PYEOF
fi
echo ""

echo -e "${BOLD}══ 3. استخراج HTTP ══${NC}"
if [ "$HAS_TSHARK" = "1" ]; then
    echo -e "  ${CYAN}HTTP Requests:${NC}"
    tshark -r "$pcap_file" -Y "http.request" -T fields \
        -e ip.src -e http.request.method -e http.host -e http.request.uri \
        2>/dev/null | head -20
    echo ""
    echo -e "  ${CYAN}HTTP Credentials (Authorization):${NC}"
    tshark -r "$pcap_file" -Y "http.authorization" -T fields \
        -e ip.src -e http.authorization \
        2>/dev/null | head -10
else
    echo -e "  ${GREY}استخراج HTTP يتطلب tshark — محاولة عبر strings:${NC}"
    strings -- "$pcap_file" | grep -E "^(GET|POST|PUT|DELETE|HTTP)" | head -20
fi
echo ""

echo -e "${BOLD}══ 4. استخراج DNS ══${NC}"
if [ "$HAS_TSHARK" = "1" ]; then
    echo -e "  ${CYAN}DNS Queries:${NC}"
    tshark -r "$pcap_file" -Y "dns.flags.response == 0" -T fields \
        -e dns.qry.name 2>/dev/null | sort -u | head -20
else
    strings -- "$pcap_file" | grep -E '\.(com|net|org|io|gov|mil)$' | sort -u | head -20
fi
echo ""

echo -e "${BOLD}══ 5. بحث عن Flags ══${NC}"
python3 - "$pcap_file" <<'PYEOF'
import sys, re
with open(sys.argv[1], 'rb') as f:
    data = f.read()
# استخراج strings
strings = re.findall(rb'[\x20-\x7e]{4,}', data)
strings_txt = [s.decode('ascii', errors='replace') for s in strings]

flags = [s for s in strings_txt if re.search(r'(?:flag|FLAG|CTF|ctf|picoCTF)\{[^}]+\}', s)]
creds = [s for s in strings_txt if re.search(r'(?:password|passwd|pass|Authorization: Basic)\s*[:=]?\s*\S+', s, re.I)]
b64   = [s for s in strings_txt if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s)]

if flags:
    print(f"  🏴 FLAGS:")
    for f in set(flags): print(f"    {f}")
if creds:
    print(f"\n  🔑 Credentials:")
    for c in creds[:5]: print(f"    {c[:100]}")
if b64:
    print(f"\n  📦 Base64 strings ({len(b64)}):")
    for b in b64[:3]:
        import base64
        try:
            dec = base64.b64decode(b + '==').decode('utf-8', errors='replace')
            print(f"    {b[:40]} → {dec[:60]}")
        except:
            print(f"    {b[:40]}")

if not flags and not creds and not b64:
    print("  لم يُعثر على flags أو credentials واضحة")
PYEOF

echo ""
echo -e "${BOLD}══ 6. استخراج ملفات مضمّنة ══${NC}"
if [ "$HAS_TSHARK" = "1" ]; then
    out_dir="/tmp/raqib_pcap_files_$$"
    mkdir -p "$out_dir"
    tshark -r "$pcap_file" --export-objects "http,$out_dir" 2>/dev/null
    count=$(ls -1 "$out_dir" 2>/dev/null | wc -l)
    if [ "$count" -gt 0 ]; then
        echo -e "  ${GREEN}✅ تم استخراج $count ملف HTTP:${NC}"
        ls -lah "$out_dir"
        echo -e "  المسار: $out_dir"
    else
        echo -e "  لا توجد ملفات HTTP مضمّنة"
        rm -rf "$out_dir"
    fi
else
    echo -e "  ${GREY}استخراج الملفات يتطلب tshark${NC}"
fi
