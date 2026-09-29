#!/bin/bash
# =============================================================
#  RAQIB CTF — Robots & Secrets
#  أداة #16: استكشاف robots.txt + hidden paths + directory enum
#  يعمل بـ curl فقط — بدون تبعيات إضافية
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🤖 Robots & Secrets — Hidden Path Discovery    ║${NC}"
echo -e "${CYAN}║  robots.txt + sitemap + CTF paths enumeration   ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

if ! command -v curl >/dev/null 2>&1; then
    echo -e "${RED}  curl مطلوب لهذه الأداة${NC}"
    exit 1
fi

read -rp "  URL الهدف (مثال: http://target.com): " target_url
[ -z "$target_url" ] && { echo -e "${RED}لم تدخل URL${NC}"; exit 1; }
[[ "$target_url" =~ ^https?:// ]] || target_url="http://$target_url"
base_url="${target_url%/}"

echo ""
echo -e "${YELLOW}  الهدف: $base_url${NC}"
echo ""

fetch_url() {
    curl -sL --max-time 10 -A "Mozilla/5.0 (compatible; RAQIB/2.1)" "$1" 2>/dev/null
}

fetch_code() {
    curl -sIo /dev/null --max-time 5 -w "%{http_code}" "$1" 2>/dev/null
}

# ─── 1. robots.txt ───
echo -e "${BOLD}══ 1. robots.txt ══${NC}"
robots=$(fetch_url "${base_url}/robots.txt")
if [ -n "$robots" ]; then
    echo "$robots"
    echo ""
    # استخراج المسارات المحظورة
    disallowed=$(echo "$robots" | grep -i "disallow\|allow" | grep -v "^#")
    if [ -n "$disallowed" ]; then
        echo -e "  ${YELLOW}🔍 مسارات مثيرة للاهتمام من robots.txt:${NC}"
        echo "$disallowed" | while read -r line; do
            path=$(echo "$line" | sed 's/[Dd]isallow:\s*//;s/[Aa]llow:\s*//' | tr -d ' ')
            [ -z "$path" ] || [ "$path" = "/" ] && continue
            full="${base_url}${path}"
            code=$(fetch_code "$full")
            echo -e "  [$code] $full"
        done
    fi
else
    echo -e "  ${GREY}robots.txt غير موجود أو فارغ${NC}"
fi
echo ""

# ─── 2. sitemap.xml ───
echo -e "${BOLD}══ 2. sitemap.xml ══${NC}"
sitemap=$(fetch_url "${base_url}/sitemap.xml")
if [ -n "$sitemap" ]; then
    echo "$sitemap" | grep -o '<loc>[^<]*</loc>' | sed 's/<[^>]*>//g' | head -20
else
    echo -e "  ${GREY}sitemap.xml غير موجود${NC}"
fi
echo ""

# ─── 3. security.txt ───
echo -e "${BOLD}══ 3. /.well-known/security.txt ══${NC}"
sec_txt=$(fetch_url "${base_url}/.well-known/security.txt")
[ -n "$sec_txt" ] && echo "$sec_txt" | head -10 || echo -e "  ${GREY}غير موجود${NC}"
echo ""

# ─── 4. CTF-specific paths ───
echo -e "${BOLD}══ 4. CTF Hidden Paths Enumeration ══${NC}"
echo -e "  ${YELLOW}فحص ${#CTF_PATHS[@]} مسار شائع في CTF...${NC}"

CTF_PATHS=(
    "/flag" "/flag.txt" "/FLAG" "/flag.php" "/secret" "/secret.txt"
    "/.flag" "/.secret" "/hidden" "/admin" "/admin.php"
    "/admin/flag" "/superadmin" "/backdoor" "/shell" "/cmd"
    "/.git/HEAD" "/.git/config" "/.env" "/.env.backup" "/.env.local"
    "/backup" "/backup.zip" "/backup.tar.gz" "/dump.sql"
    "/config" "/config.php" "/config.yaml" "/config.json"
    "/api" "/api/flag" "/api/secret" "/api/admin" "/api/v1/flag"
    "/phpinfo.php" "/info.php" "/test.php" "/debug.php"
    "/logs" "/log.txt" "/.htaccess" "/.htpasswd"
    "/server-status" "/server-info" "/status"
    "/wp-config.php" "/wp-admin" "/wp-login.php"
    "/login" "/dashboard" "/panel" "/cpanel"
    "/.DS_Store" "/Thumbs.db" "/desktop.ini"
    "/upload" "/uploads" "/files" "/file" "/static"
    "/robots" "/humans.txt" "/crossdomain.xml"
    "/changelog.txt" "/CHANGELOG" "/version.txt" "/VERSION"
    "/source" "/src" "/dev" "/test" "/staging"
)

echo ""
found_count=0
for path in "${CTF_PATHS[@]}"; do
    full="${base_url}${path}"
    code=$(fetch_code "$full")
    case "$code" in
        200) echo -e "  ${GREEN}[200]${NC} $full" ; ((found_count++)) ;;
        301|302) echo -e "  ${YELLOW}[$code]${NC} $full (redirect)" ;;
        403) echo -e "  ${ORANGE}[403]${NC} $full (Forbidden — يستحق فحصاً يدوياً)" ; ((found_count++)) ;;
    esac
done

echo ""
[ "$found_count" -eq 0 ] && echo -e "  ${GREY}لا توجد مسارات مكشوفة${NC}" || \
    echo -e "  ${GREEN}✅ وُجد $found_count مسار مثير للاهتمام${NC}"

echo ""

# ─── 5. Source code analysis ───
echo -e "${BOLD}══ 5. تحليل Source Code الصفحة الرئيسية ══${NC}"
page_source=$(fetch_url "$base_url")
if [ -n "$page_source" ]; then
    python3 - "$page_source" <<'PYEOF'
import sys, re

source = sys.argv[1]

# بحث عن flags
flags = re.findall(r'(?:flag|FLAG|CTF|ctf|picoCTF)\{[^}]+\}', source)

# تعليقات HTML
comments = re.findall(r'<!--[\s\S]*?-->', source)

# روابط مخفية
hidden_links = re.findall(r'href=["\']([^"\']+)["\']', source)
suspicious_links = [l for l in hidden_links if
                    re.search(r'flag|secret|hidden|admin|debug|test|backup', l, re.I)]

# JavaScript secrets
js_secrets = re.findall(r'(?:password|secret|token|key|api_key|apikey)\s*[=:]\s*["\']([^"\']+)["\']', source, re.I)

# base64 مضمّن
b64_strings = re.findall(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']', source)

if flags:
    print(f"  🏴 FLAGS في السورس:")
    for f in flags: print(f"    {f}")

if comments:
    print(f"\n  💬 HTML Comments ({len(comments)}):")
    for c in comments[:5]: print(f"    {c[:150]}")

if suspicious_links:
    print(f"\n  🔗 روابط مشبوهة:")
    for l in suspicious_links[:10]: print(f"    {l}")

if js_secrets:
    print(f"\n  🔑 Secrets في JavaScript:")
    for s in js_secrets[:5]: print(f"    {s}")

if b64_strings:
    print(f"\n  📦 Base64 strings:")
    for b in b64_strings[:3]:
        import base64
        try:
            dec = base64.b64decode(b + '==').decode('utf-8', errors='replace')
            print(f"    {b[:40]} → {dec[:60]}")
        except:
            print(f"    {b[:40]}")

if not any([flags, comments, suspicious_links, js_secrets, b64_strings]):
    print("  لم يُعثر على شيء لافت في السورس")
PYEOF
else
    echo -e "  ${GREY}تعذّر جلب الصفحة الرئيسية${NC}"
fi

echo ""
read -rp "  هل تريد فحص مسار مخصص؟ (أدخل المسار أو اضغط Enter للتخطي): " custom_path
if [ -n "$custom_path" ]; then
    [[ "$custom_path" =~ ^/ ]] || custom_path="/$custom_path"
    full="${base_url}${custom_path}"
    echo ""
    echo -e "${CYAN}  محتوى $full :${NC}"
    fetch_url "$full" | head -50
fi
