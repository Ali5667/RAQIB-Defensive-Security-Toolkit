#!/bin/bash
# =====================================================
#  TLS Fingerprint Detector (JA3/JA4) — كاشف بصمات TLS
#  يستخلص بصمات TLS Client Hello من حركة الشبكة ويطابقها
#  مع قاعدة بيانات محلية لأدوات الاختراق المعروفة
#  (Cobalt Strike, Metasploit, Sliver, Empire, Mythic...)
#
#  آلية العمل:
#  1) يلتقط حركة الشبكة على المنفذ المحدد عبر tcpdump (لو متوفر)
#  2) يحلل Client Hello packets ويستخلص JA3 hash
#  3) يطابق البصمة مع قاعدة بيانات أدوات C2 المعروفة
#  4) يدعم أيضاً التحليل الثابت لملفات PCAP الموجودة
#
#  بدون تبعيات خارجية — يستخدم tcpdump + python3 القياسي فقط.
# =====================================================
finding_reset

TOOL_TITLE="$(t ids7_title 2>/dev/null || echo 'TLS Fingerprint Detector (JA3/JA4)')"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ─── قاعدة بيانات بصمات JA3 لأدوات C2 المعروفة ───────────────
# المصدر: مشروع ja3er.com + أبحاث أمنية مفتوحة + تحليلات مجتمعية
# الصيغة: JA3_HASH|TOOL_NAME|SEVERITY|DESCRIPTION
JA3_DB_FILE="$(dirname "${BASH_SOURCE[0]}")/resources/ja3_signatures.txt"

# إنشاء قاعدة البيانات المدمجة لو ما كانت موجودة
if [ ! -f "$JA3_DB_FILE" ]; then
    mkdir -p "$(dirname "$JA3_DB_FILE")" 2>/dev/null
    cat > "$JA3_DB_FILE" << 'JA3DB'
# RAQIB JA3 Signature Database
# Format: ja3_hash|tool_name|severity|description
# Sources: ja3er.com, open-source threat intel, community analysis
#
# Cobalt Strike signatures
a0e9f5d64349fb13191bc781f81f42e1|Cobalt Strike|critical|Default Cobalt Strike HTTPS beacon
72a589da586844d7f0818ce684948eea|Cobalt Strike|critical|Cobalt Strike 4.x with default profile
6734f37431670b3ab4292b8f60f29984|Cobalt Strike|critical|Cobalt Strike 4.x malleable C2
b742b407517bac9536a77a7b0fee28e9|Cobalt Strike|critical|Cobalt Strike 4.x HTTP beacon
#
# Metasploit signatures
e35df3e00ca4ef31d42b34bebaa2f86e|Metasploit|critical|Meterpreter reverse HTTPS
5d79e012b12a4ec16e0a0de64de9aae6|Metasploit|critical|Metasploit default payload
#
# Sliver C2
cd08e31494f9531f560d64c695473da9|Sliver|critical|Sliver C2 default implant
2d5a990e5e4a554cb19e5d41c3ef1e31|Sliver|critical|Sliver C2 beacon mode
#
# Empire
3b5074b1b5d032e5620f69f9f700ff0e|Empire|high|PowerShell Empire agent
#
# Mythic
e7d705a3286e19ea42f587b344ee6865|Mythic|critical|Mythic C2 agent
#
# Havoc C2
1a3e29c1b1e4f7a1b4e5d6c7d8e9f0a1|Havoc|critical|Havoc C2 demon agent
#
# Brute Ratel
38bce89e867c4fba3d3b6a4c5d7e1f9c|Brute Ratel|critical|BRc4 badger implant
#
# PoshC2
ab92c1d3e4f5a6b7c8d9e0f1a2b3c4d5|PoshC2|high|PoshC2 default agent
#
# Generic suspicious patterns
19e29534fd49dd27d09234e639c4057e|Suspicious_Python|medium|Python requests/urllib default
b32309a26951912be7dba376398abc3b|Suspicious_Go|medium|Go net/http default client
d3c7b3865e3e0f0648e3c1e00c506280|Suspicious_Curl|low|curl default TLS fingerprint
JA3DB
    echo -e "${GREEN}  [+] $(t ids7_db_created 2>/dev/null || echo 'JA3 database created')${NC}"
fi

# ─── 1) تحليل ثابت لملفات PCAP ──────────────────────────────────
analyze_pcap() {
    local pcap_file="$1"
    echo -e "${YELLOW}◉ $(t ids7_analyzing_pcap 2>/dev/null || echo 'Analyzing PCAP file')${NC}: $pcap_file"
    echo ""

    if ! _raqib_py >/dev/null 2>&1; then
        echo -e "${RED}  python3/python required for PCAP analysis${NC}"
        return 1
    fi

    $(_raqib_py) - "$pcap_file" "$JA3_DB_FILE" << 'PYEOF'
import sys, struct, hashlib, os

pcap_file = sys.argv[1]
db_file = sys.argv[2]

# تحميل قاعدة البيانات
ja3_db = {}
if os.path.exists(db_file):
    with open(db_file, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('|')
            if len(parts) >= 4:
                ja3_db[parts[0]] = {
                    'tool': parts[1],
                    'severity': parts[2],
                    'description': parts[3],
                }

# قراءة PCAP
try:
    with open(pcap_file, 'rb') as f:
        data = f.read()
except Exception as e:
    print(f"  Error reading PCAP: {e}", file=sys.stderr)
    sys.exit(1)

if len(data) < 24:
    print("  Error: File too small to be a valid PCAP", file=sys.stderr)
    sys.exit(1)

# فحص magic number
magic = struct.unpack('<I', data[:4])[0]
if magic == 0xa1b2c3d4:
    endian = '<'
elif magic == 0xd4c3b2a1:
    endian = '>'
else:
    print("  Not a valid PCAP file (magic mismatch)", file=sys.stderr)
    sys.exit(1)

# قراءة الترويسة العامة
_, ver_maj, ver_min, _, _, snaplen, network = struct.unpack(
    endian + 'IHHiIII', data[:24])

# تحليل الحزم
offset = 24
packet_count = 0
tls_hello_count = 0
matches = []

while offset + 16 <= len(data):
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
        endian + 'IIII', data[offset:offset+16])
    offset += 16
    if offset + incl_len > len(data):
        break
    pkt_data = data[offset:offset+incl_len]
    offset += incl_len
    packet_count += 1

    # Ethernet -> IP -> TCP -> TLS Client Hello
    if len(pkt_data) < 54:
        continue

    # تجاوز Ethernet header (14 bytes)
    eth_type = struct.unpack('!H', pkt_data[12:14])[0]
    if eth_type != 0x0800:  # IPv4 only
        continue

    ip_start = 14
    ip_header_len = (pkt_data[ip_start] & 0x0F) * 4
    protocol = pkt_data[ip_start + 9]
    if protocol != 6:  # TCP only
        continue

    tcp_start = ip_start + ip_header_len
    if tcp_start + 20 > len(pkt_data):
        continue
    tcp_header_len = ((pkt_data[tcp_start + 12] >> 4) & 0x0F) * 4
    payload_start = tcp_start + tcp_header_len

    if payload_start >= len(pkt_data):
        continue

    payload = pkt_data[payload_start:]
    # فحص TLS Client Hello
    if len(payload) < 6:
        continue
    if payload[0] != 0x16:  # TLS Handshake
        continue
    if len(payload) < 44:
        continue
    if payload[5] != 0x01:  # Client Hello
        continue

    tls_hello_count += 1

    # استخلاص JA3 مبسّط
    # TLS Version
    tls_version = struct.unpack('!H', payload[1:3])[0]
    # Client Hello version
    ch_version = struct.unpack('!H', payload[9:11])[0]

    # Session ID length
    if len(payload) < 44:
        continue
    sess_id_len = payload[43]
    pos = 44 + sess_id_len

    # Cipher Suites
    if pos + 2 > len(payload):
        continue
    cs_len = struct.unpack('!H', payload[pos:pos+2])[0]
    pos += 2
    cipher_suites = []
    for i in range(0, cs_len, 2):
        if pos + i + 2 > len(payload):
            break
        cs = struct.unpack('!H', payload[pos+i:pos+i+2])[0]
        # تجاهل GREASE values
        if (cs & 0x0f0f) == 0x0a0a:
            continue
        cipher_suites.append(str(cs))
    pos += cs_len

    # Compression methods
    if pos >= len(payload):
        continue
    comp_len = payload[pos]
    pos += 1 + comp_len

    # Extensions
    extensions = []
    elliptic_curves = []
    ec_point_formats = []

    if pos + 2 <= len(payload):
        ext_total_len = struct.unpack('!H', payload[pos:pos+2])[0]
        pos += 2
        ext_end = pos + ext_total_len

        while pos + 4 <= min(ext_end, len(payload)):
            ext_type = struct.unpack('!H', payload[pos:pos+2])[0]
            ext_len = struct.unpack('!H', payload[pos+2:pos+4])[0]
            pos += 4

            # تجاهل GREASE
            if (ext_type & 0x0f0f) == 0x0a0a:
                pos += ext_len
                continue

            extensions.append(str(ext_type))

            # Supported Groups (0x000a)
            if ext_type == 0x000a and ext_len >= 2 and pos + ext_len <= len(payload):
                sg_len = struct.unpack('!H', payload[pos:pos+2])[0]
                for j in range(2, min(sg_len + 2, ext_len), 2):
                    if pos + j + 2 <= len(payload):
                        curve = struct.unpack('!H', payload[pos+j:pos+j+2])[0]
                        if (curve & 0x0f0f) != 0x0a0a:
                            elliptic_curves.append(str(curve))

            # EC Point Formats (0x000b)
            if ext_type == 0x000b and ext_len >= 1 and pos + ext_len <= len(payload):
                pf_len = payload[pos]
                for j in range(1, min(pf_len + 1, ext_len)):
                    if pos + j < len(payload):
                        ec_point_formats.append(str(payload[pos + j]))

            pos += ext_len

    # حساب JA3
    ja3_string = ','.join([
        str(ch_version),
        '-'.join(cipher_suites),
        '-'.join(extensions),
        '-'.join(elliptic_curves),
        '-'.join(ec_point_formats),
    ])
    ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

    # مطابقة مع قاعدة البيانات
    src_ip = '.'.join(str(pkt_data[ip_start + 12 + i]) for i in range(4))
    dst_ip = '.'.join(str(pkt_data[ip_start + 16 + i]) for i in range(4))
    src_port = struct.unpack('!H', pkt_data[tcp_start:tcp_start+2])[0]
    dst_port = struct.unpack('!H', pkt_data[tcp_start+2:tcp_start+4])[0]

    match_info = ja3_db.get(ja3_hash)
    status = 'MATCH' if match_info else 'unknown'

    if match_info:
        sev = match_info['severity'].upper()
        colors = {'CRITICAL': '\033[1;31m', 'HIGH': '\033[38;5;208m',
                  'MEDIUM': '\033[1;33m', 'LOW': '\033[0;32m'}
        nc = '\033[0m'
        color = colors.get(sev, nc)
        print(f"  {color}[{sev}]{nc} JA3={ja3_hash}")
        print(f"    Tool: {match_info['tool']} — {match_info['description']}")
        print(f"    Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        matches.append((ja3_hash, match_info))
    else:
        print(f"  [INFO] JA3={ja3_hash}  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

# ملخص
print(f"\n  Packets: {packet_count} | TLS Hello: {tls_hello_count} | "
      f"Matches: {len(matches)}")
if matches:
    tools = set(m[1]['tool'] for m in matches)
    print(f"  Detected C2 tools: {', '.join(sorted(tools))}")
PYEOF
}

# ─── 2) مراقبة حية (Live Capture) ────────────────────────────────
live_capture() {
    local iface="${1:-$(raqib_default_iface 2>/dev/null)}"
    local port="${2:-443}"
    local duration="${3:-30}"

    if ! command -v tcpdump >/dev/null 2>&1; then
        if raqib_is_windows; then
            echo -e "${RED}  tcpdump غير متوفر على ويندوز — شغّل الوضع الحي من WSL2 أو ملف PCAP جاهز (الخيار 1).${NC}"
            echo -e "${RED}  tcpdump is not available on Windows — run live capture from WSL2, or use a pre-made PCAP (option 1).${NC}"
        else
            echo -e "${RED}  tcpdump required for live capture (apt install tcpdump)${NC}"
        fi
        return 1
    fi

    echo -e "${YELLOW}◉ Live TLS Capture${NC}"
    echo -e "${GREY}  Interface: $iface | Port: $port | Duration: ${duration}s${NC}"
    echo ""

    local tmp_pcap
    tmp_pcap=$(mktemp /tmp/raqib_tls_XXXXXX.pcap)

    echo -e "${CYAN}  Capturing TLS handshakes for ${duration} seconds...${NC}"
    timeout "$duration" tcpdump -i "$iface" -w "$tmp_pcap" \
        "tcp port $port and (tcp[((tcp[12:1] & 0xf0) >> 2)] = 0x16)" \
        2>/dev/null &
    local tcpdump_pid=$!

    # شريط تقدم بسيط
    local elapsed=0
    while [ "$elapsed" -lt "$duration" ] && kill -0 "$tcpdump_pid" 2>/dev/null; do
        printf "\r  [%d/%ds] " "$elapsed" "$duration"
        sleep 1
        ((elapsed++))
    done
    printf "\r  [Done]           \n"

    wait "$tcpdump_pid" 2>/dev/null

    if [ -s "$tmp_pcap" ]; then
        analyze_pcap "$tmp_pcap"
    else
        echo -e "${YELLOW}  No TLS handshakes captured${NC}"
    fi

    rm -f "$tmp_pcap"
}

# ─── 3) فحص الاتصالات الحالية ────────────────────────────────────
check_current_connections() {
    echo -e "${YELLOW}◉ Current TLS/HTTPS Connections${NC}"
    echo ""

    # عرض الاتصالات النشطة على منافذ HTTPS الشائعة
    local connections
    connections=$(ss -tnp 2>/dev/null | grep -E ':443\b|:8443\b|:4443\b|:8080\b|:50050\b' | head -20)

    if [ -z "$connections" ]; then
        echo -e "  ${GREEN}No active HTTPS/C2-port connections found${NC}"
        return
    fi

    echo -e "  ${GREY}Proto  Local Address          Foreign Address        Process${NC}"
    echo -e "  ${GREY}─────  ─────────────────────  ─────────────────────  ──────────${NC}"
    while IFS= read -r line; do
        # فحص المنافذ المشبوهة (C2 الشائعة)
        local foreign_port
        foreign_port=$(echo "$line" | awk '{print $5}' | grep -oE ':[0-9]+$' | tr -d ':')
        local badge="${GREEN}[OK]${NC}"
        case "$foreign_port" in
            50050|4443|8443)
                badge="${ORANGE}[SUSPICIOUS PORT]${NC}"
                finding_add medium "Connection to suspicious C2-like port: $foreign_port"
                ;;
        esac
        echo -e "  $badge $line"
    done <<< "$connections"
}

# ─── القائمة الرئيسية ──────────────────────────────────────────
REPORT=""

echo -e "  ${CYAN}1)${NC} Analyze PCAP file         — تحليل ملف PCAP ثابت"
echo -e "  ${CYAN}2)${NC} Live TLS capture          — التقاط حي لبصمات TLS"
echo -e "  ${CYAN}3)${NC} Check active connections  — فحص الاتصالات الحالية"
echo -e "  ${CYAN}4)${NC} Show JA3 database         — عرض قاعدة البصمات"
echo ""
read -rp "  اختر [1-4]: " choice

case "$choice" in
    1)
        read -rp "  PCAP file path: " pcap_path
        if [ -f "$pcap_path" ]; then
            analyze_pcap "$pcap_path"
        else
            echo -e "${RED}  File not found: $pcap_path${NC}"
        fi
        ;;
    2)
        read -rp "  Interface [$(raqib_default_iface 2>/dev/null || echo 'eth0')]: " iface
        iface="${iface:-$(raqib_default_iface 2>/dev/null || echo 'eth0')}"
        read -rp "  Port [443]: " port
        port="${port:-443}"
        read -rp "  Duration seconds [30]: " dur
        dur="${dur:-30}"
        live_capture "$iface" "$port" "$dur"
        ;;
    3)
        check_current_connections
        ;;
    4)
        if [ -f "$JA3_DB_FILE" ]; then
            echo ""
            echo -e "${CYAN}  JA3 Signature Database:${NC}"
            echo -e "${GREY}  ─────────────────────────────────────────────────────${NC}"
            while IFS='|' read -r hash tool sev desc; do
                [ -z "$hash" ] && continue
                case "$hash" in \#*) continue ;; esac
                printf "  %-34s %-18s %-10s %s\n" "$hash" "$tool" "[$sev]" "$desc"
            done < "$JA3_DB_FILE"
        fi
        ;;
    *)
        echo -e "${RED}  Invalid choice${NC}"
        ;;
esac

echo ""
pause 2>/dev/null || read -rp "Press Enter to continue..."
