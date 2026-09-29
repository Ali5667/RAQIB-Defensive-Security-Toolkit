#!/bin/bash
# =============================================================
#  RAQIB CTF — Header Inspector
#  أداة #14: فحص HTTP headers + security misconfigs
#  يعمل بـ curl فقط — بدون تبعيات إضافية
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🌐 Header Inspector — HTTP Security Headers     ║${NC}"
echo -e "${CYAN}║  كشف misconfiguration + headers مخفية            ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

if ! command -v curl >/dev/null 2>&1; then
    echo -e "${RED}  curl مطلوب لهذه الأداة${NC}"
    exit 1
fi

read -rp "  URL (مثال: https://target.com): " target_url
[ -z "$target_url" ] && { echo -e "${RED}لم تدخل URL${NC}"; exit 1; }

# أضف https:// لو ما فيه بروتوكول
[[ "$target_url" =~ ^https?:// ]] || target_url="https://$target_url"

echo ""
echo -e "${YELLOW}  جارٍ الفحص: $target_url${NC}"
echo ""

# ─── اجمع الـ headers ───
headers_raw=$(curl -sI --max-time 10 -L \
    -A "Mozilla/5.0 (compatible; RAQIB/2.1)" \
    "$target_url" 2>/dev/null)

if [ -z "$headers_raw" ]; then
    # جرّب HTTP عادي
    target_url_http="${target_url/https:/http:}"
    headers_raw=$(curl -sI --max-time 10 \
        -A "Mozilla/5.0 (compatible; RAQIB/2.1)" \
        "$target_url_http" 2>/dev/null)
fi

if [ -z "$headers_raw" ]; then
    echo -e "${RED}  تعذّر الاتصال بالهدف${NC}"
    exit 1
fi

echo -e "${BOLD}══ 1. Raw Headers ══${NC}"
echo "$headers_raw" | head -40
echo ""

echo -e "${BOLD}══ 2. Security Headers Analysis ══${NC}"
python3 - "$headers_raw" <<'PYEOF'
import sys, re

headers_raw = sys.argv[1]

# حوّل لـ dict
headers = {}
for line in headers_raw.splitlines():
    m = re.match(r'^([^:]+):\s*(.+)$', line.strip())
    if m:
        headers[m.group(1).lower()] = m.group(2).strip()

# HTTP Status
status_line = headers_raw.splitlines()[0] if headers_raw else ""
print(f"  📊 Status: {status_line}")
print("")

# Security headers المطلوبة
SECURITY_HEADERS = {
    'strict-transport-security':  ('HSTS', 'يمنع Downgrade attacks'),
    'content-security-policy':    ('CSP',  'يمنع XSS/Injection'),
    'x-frame-options':            ('XFO',  'يمنع Clickjacking'),
    'x-content-type-options':     ('XCTO', 'يمنع MIME sniffing'),
    'x-xss-protection':           ('XSS',  'حماية XSS (قديم)'),
    'referrer-policy':            ('RP',   'يتحكم بـ Referer header'),
    'permissions-policy':         ('PP',   'يقيّد صلاحيات API'),
    'access-control-allow-origin':('CORS', 'سياسة CORS'),
}

print("  🔐 Security Headers:")
for header, (short, desc) in SECURITY_HEADERS.items():
    val = headers.get(header, '')
    if val:
        print(f"  ✅  [{short}] {header}: {val[:80]}")
    else:
        print(f"  ❌  [{short}] {header}: مفقود ← {desc}")

print("")

# Headers مثيرة للاهتمام في CTF
INTERESTING = [
    'server', 'x-powered-by', 'x-aspnet-version', 'x-generator',
    'x-drupal-cache', 'x-wordpress-cache', 'x-debug', 'x-custom-header',
    'x-flag', 'flag', 'x-secret', 'x-token', 'x-admin', 'x-internal',
    'set-cookie', 'location', 'x-redirect-by',
]

print("  🔍 Headers مثيرة للاهتمام (CTF):")
found = False
for h in INTERESTING:
    val = headers.get(h, '')
    if val:
        print(f"  ⚠️   {h}: {val[:100]}")
        found = True

# ابحث عن أي header يحتوي flag
for h, v in headers.items():
    if re.search(r'(?:flag|FLAG|CTF|ctf|picoCTF)\{[^}]+\}', v):
        print(f"  🏴  FLAG في header [{h}]: {v}")
        found = True

if not found:
    print("  لا توجد headers لافتة للنظر")

print("")

# تحليل Set-Cookie
cookies = [v for h, v in headers.items() if h == 'set-cookie']
if cookies:
    print("  🍪 Cookies Analysis:")
    for cookie in cookies:
        flags_found = []
        if 'httponly' not in cookie.lower(): flags_found.append("⚠️ لا httponly")
        if 'secure' not in cookie.lower(): flags_found.append("⚠️ لا secure")
        if 'samesite' not in cookie.lower(): flags_found.append("⚠️ لا samesite")
        print(f"  {cookie[:80]}")
        if flags_found:
            print(f"    {', '.join(flags_found)}")
PYEOF
echo ""

echo -e "${BOLD}══ 3. Hidden Paths + Secrets ══${NC}"
echo -e "  ${YELLOW}فحص مسارات CTF الشائعة...${NC}"

PATHS=("/robots.txt" "/.well-known/security.txt" "/sitemap.xml"
       "/.git/HEAD" "/.env" "/flag.txt" "/flag" "/secret" "/admin"
       "/backup" "/config.php" "/.htaccess" "/api" "/api/v1"
       "/swagger.json" "/phpinfo.php" "/server-status" "/debug")

found_paths=()
for path in "${PATHS[@]}"; do
    full_url="${target_url%/}${path}"
    code=$(curl -sIo /dev/null --max-time 5 -w "%{http_code}" "$full_url" 2>/dev/null)
    if [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ]; then
        echo -e "  ${GREEN}[$code]${NC} $full_url"
        found_paths+=("$full_url")
    fi
done

[ ${#found_paths[@]} -eq 0 ] && echo -e "  لا توجد مسارات مكشوفة من القائمة المعتادة"

echo ""
echo -e "${BOLD}══ 4. Method Tampering ══${NC}"
echo -e "  ${YELLOW}اختبار HTTP Methods...${NC}"
for method in OPTIONS TRACE PUT DELETE PATCH; do
    code=$(curl -sIo /dev/null --max-time 5 -X "$method" -w "%{http_code}" "$target_url" 2>/dev/null)
    [ "$code" = "200" ] && echo -e "  ${YELLOW}⚠️  $method مسموح! (${code})${NC}" || echo -e "  ${GREEN}[$code]${NC} $method"
done
