#!/bin/bash
# raqib_collector_server.sh
# سيرفر تجميع مركزي خفيف — يستقبل أحداث من أجهزة RAQIB ثانية عبر HTTP،
# ويكتبها بنفس صيغة/مسار سجل الأحداث المحلي ($RAQIB_EVENTS_FILE). هذا يخلي
# كل أدوات العرض الموجودة أصلاً (siem_correlator.sh, dashboard_generator.sh,
# audit_log_viewer.sh) تشتغل مباشرة على البيانات المجمّعة من كل الأجهزة،
# بدون أي تعديل عليها هي نفسها.
#
# صفر تبعيات خارجية — يستخدم http.server المدمج بـPython.

echo -e "${CYAN}$(t colsrv_title)${NC}"
echo -e "${GREY}$(t colsrv_disclaimer)${NC}"
echo ""

read -rp "$(t colsrv_port_prompt)" port
[[ "$port" =~ ^[0-9]+$ ]] || port=8765

SERVER_CONF="$SCRIPT_DIR/.raqib_collector_server.conf"
if [ -f "$SERVER_CONF" ] && grep -q "^API_KEY=" "$SERVER_CONF"; then
    api_key=$(sed -n 's/^API_KEY=//p' "$SERVER_CONF" | head -1)
else
    api_key=$(python3 -c "import secrets; print(secrets.token_hex(16))")
    printf 'API_KEY=%s\n' "$api_key" > "$SERVER_CONF"
    chmod 600 "$SERVER_CONF" 2>/dev/null
fi

echo -e "${BOLD}${ORANGE}$(t colsrv_api_key_label)${NC} ${CYAN}${api_key}${NC}"
echo -e "${GREY}$(t colsrv_api_key_hint)${NC}"
echo ""
echo -e "${YELLOW}$(tf colsrv_starting "$port")${NC}"
echo -e "${GREY}$(t colsrv_ctrl_c)${NC}"
echo ""

RAQIB_EVENTS_FILE="$RAQIB_EVENTS_FILE" RAQIB_COLLECTOR_API_KEY="$api_key" python3 - "$port" << 'PYEOF'
import sys, json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])
EVENTS_FILE = os.environ["RAQIB_EVENTS_FILE"]
API_KEY = os.environ["RAQIB_COLLECTOR_API_KEY"]
REQUIRED_KEYS = {"timestamp", "severity", "tool", "message"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # يخلي الإخراج نظيف — نطبع أنفسنا بس

    def do_POST(self):
        if self.path != "/event":
            self.send_response(404)
            self.end_headers()
            return

        if self.headers.get("X-API-Key", "") != API_KEY:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error":"invalid or missing API key"}')
            print(f"[!] rejected event from {self.client_address[0]} — bad/missing API key")
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            data = json.loads(body)
        except Exception:
            self.send_response(400)
            self.end_headers()
            return

        if not REQUIRED_KEYS.issubset(data.keys()):
            self.send_response(422)
            self.end_headers()
            return

        # نعلّم الحدث بالمصدر الفعلي (IP اللي أرسل الطلب)، ونحافظ على أي
        # اسم مضيف أرسله العميل نفسه بحقل منفصل
        record = {
            "timestamp": data.get("timestamp"),
            "host": data.get("host", "unknown"),
            "severity": data.get("severity", "low"),
            "tool": data.get("tool", "unknown"),
            "message": data.get("message", ""),
            "operator": data.get("operator", "unknown"),
            "product": "RAQIB",
            "source_ip": self.client_address[0],
        }
        with open(EVENTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        print(f"[+] event received from {self.client_address[0]}: "
              f"{record['tool']} ({record['severity']}) — {record['message']}")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')


try:
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
except KeyboardInterrupt:
    print("\n[+] collector stopped")
except OSError as e:
    print(f"[!] could not bind port {PORT}: {e}")
PYEOF
