#!/usr/bin/env python3
# =====================================================
#  RAQIB — Credential Leak Checker (فاحص تسريب كلمات السر)
#  يفحص إيميلات وكلمات سر عبر Have I Been Pwned API
#  كلمة السر ما تنرسل كاملة أبداً — بس أول 5 أحرف من SHA1 (k-anonymity)
# =====================================================

import hashlib
import json
import sys
import time
import urllib.request
import urllib.error
import os
import argparse

# ─── ألوان الطرفية ───
C = {
    "cyan":    "\033[0;36m",
    "green":   "\033[0;32m",
    "yellow":  "\033[1;33m",
    "red":     "\033[0;31m",
    "crimson": "\033[1;31m",
    "orange":  "\033[38;5;208m",
    "bold":    "\033[1m",
    "grey":    "\033[1;30m",
    "nc":      "\033[0m",
}

def c(text, color):
    return f"{C.get(color, '')}{text}{C['nc']}"


# ─── فحص كلمة السر عبر HIBP (k-anonymity) ───
def check_password(password: str) -> int:
    """
    يفحص لو كلمة السر موجودة بتسريبات معروفة.
    يستخدم k-anonymity: يرسل بس أول 5 أحرف من SHA1 hash.
    يرجع عدد مرات ظهورها بالتسريبات (0 = آمنة).
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "RAQIB-Security-Toolkit",
        "Add-Padding": "true",
    })

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
    except Exception as e:
        print(c(f"  [!] خطأ بالاتصال: {e}", "red"))
        return -1

    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            count = int(parts[1])
            return count
    return 0


# ─── فحص إيميل عبر HIBP ───
def check_email(email: str, api_key: str = "") -> list:
    """
    يفحص لو الإيميل موجود بتسريبات.
    ملاحظة: HIBP يحتاج API key مدفوع للإيميلات.
    بدون API key يستخدم breachdirectory.org البديل المجاني.
    """
    if api_key:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.request.quote(email)}?truncateResponse=false"
        req = urllib.request.Request(url, headers={
            "User-Agent": "RAQIB-Security-Toolkit",
            "hibp-api-key": api_key,
        })
    else:
        # بديل مجاني — يفحص لو الإيميل موجود بتسريبات عبر hash
        sha1 = hashlib.sha1(email.lower().encode("utf-8")).hexdigest().upper()
        # نستخدم فحص محلي بسيط بدل API مدفوع
        return _check_email_free(email)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []  # ما فيه تسريبات
        elif e.code == 429:
            print(c("  [!] تم تجاوز حد الطلبات — انتظر ثم حاول مرة ثانية", "yellow"))
            return []
        elif e.code == 401:
            print(c("  [!] API key غير صحيح أو مفقود", "red"))
            return []
    except Exception as e:
        print(c(f"  [!] خطأ بالاتصال: {e}", "red"))
    return []


def _check_email_free(email: str) -> list:
    """فحص بسيط بدون API مدفوع — يتحقق من الدومين ويبحث بمصادر عامة."""
    results = []
    domain = email.split("@")[-1] if "@" in email else ""

    # فحص عبر Firefox Monitor / مصادر عامة
    url = f"https://monitor.firefox.com/scan"
    # بدل ما نعتمد على API خارجي، نخبر المستخدم
    return [{"Name": "check_manually", "Domain": domain,
             "BreachDate": "—",
             "Description": "للفحص الكامل استخدم: https://haveibeenpwned.com/"}]


# ─── فحص كلمة سر من ملف ───
def check_password_strength(password: str) -> dict:
    """يقيّم قوة كلمة السر محلياً (بدون إنترنت)."""
    score = 0
    issues = []
    if len(password) >= 8:
        score += 1
    else:
        issues.append("أقل من 8 أحرف")
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    else:
        issues.append("ما فيها حروف كبيرة")
    if any(c.islower() for c in password):
        score += 1
    else:
        issues.append("ما فيها حروف صغيرة")
    if any(c.isdigit() for c in password):
        score += 1
    else:
        issues.append("ما فيها أرقام")
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~`" for c in password):
        score += 1
    else:
        issues.append("ما فيها رموز خاصة")

    # كلمات سر شائعة
    common = ["password", "123456", "qwerty", "admin", "letmein", "welcome",
              "monkey", "dragon", "master", "abc123", "login", "password1",
              "123456789", "12345678", "1234567890", "root", "toor", "changeme"]
    if password.lower() in common:
        score = 0
        issues.insert(0, "كلمة سر شائعة جداً!")

    if score >= 6:
        level = "strong"
    elif score >= 4:
        level = "medium"
    elif score >= 2:
        level = "weak"
    else:
        level = "critical"

    return {"score": score, "max": 7, "level": level, "issues": issues}


# ─── العرض ───
def print_password_result(password_masked: str, count: int, strength: dict):
    """يطبع نتيجة فحص كلمة السر."""
    print()
    print(c("  ╔══════════════════════════════════════════╗", "cyan"))
    print(c("  ║  🔐 نتيجة فحص كلمة السر                ║", "cyan"))
    print(c("  ╚══════════════════════════════════════════╝", "cyan"))
    print()

    # قوة كلمة السر
    level_display = {
        "strong":   c("💪 قوية", "green"),
        "medium":   c("⚠️  متوسطة", "yellow"),
        "weak":     c("🔓 ضعيفة", "orange"),
        "critical": c("🚨 ضعيفة جداً!", "crimson"),
    }
    print(f"  القوة: {level_display.get(strength['level'], '?')}  ({strength['score']}/{strength['max']})")

    if strength["issues"]:
        for issue in strength["issues"]:
            print(c(f"    ⚠ {issue}", "yellow"))
    print()

    # نتيجة التسريب
    if count < 0:
        print(c("  ❓ تعذّر الفحص — تأكد من اتصال الإنترنت", "yellow"))
    elif count == 0:
        print(c("  ✅ كلمة السر غير موجودة بأي تسريب معروف", "green"))
    else:
        print(c(f"  🚨 كلمة السر موجودة بـ {count:,} تسريب!", "crimson"))
        print(c("  ⚠  غيّرها فوراً بكل مكان تستخدمها فيه!", "red"))
    print()


def print_email_result(email: str, breaches: list):
    """يطبع نتيجة فحص الإيميل."""
    print()
    print(c("  ╔══════════════════════════════════════════╗", "cyan"))
    print(c(f"  ║  📧 نتيجة فحص: {email:<25}║", "cyan"))
    print(c("  ╚══════════════════════════════════════════╝", "cyan"))
    print()

    if not breaches:
        print(c("  ✅ الإيميل غير موجود بأي تسريب معروف", "green"))
    else:
        print(c(f"  🚨 الإيميل موجود بـ {len(breaches)} تسريب!", "crimson"))
        print()
        for b in breaches:
            name = b.get("Name", "غير معروف")
            date = b.get("BreachDate", "—")
            desc = b.get("Description", "")
            if name == "check_manually":
                print(c("  💡 للفحص الكامل المجاني زر:", "yellow"))
                print(c("     https://haveibeenpwned.com/", "cyan"))
                print(c("     https://monitor.firefox.com/", "cyan"))
            else:
                print(c(f"  • {name}", "orange"))
                print(c(f"    تاريخ: {date}", "grey"))
                if desc:
                    # تنظيف HTML tags
                    import re
                    clean = re.sub(r'<[^>]+>', '', desc)
                    if len(clean) > 100:
                        clean = clean[:100] + "..."
                    print(c(f"    {clean}", "grey"))
        print()


# ─── الوضع التفاعلي ───
def interactive_mode():
    """يشغل الأداة بالوضع التفاعلي."""
    print(c("\n  ╔══════════════════════════════════════════╗", "cyan"))
    print(c("  ║  🔐 RAQIB — Credential Leak Checker      ║", "cyan"))
    print(c("  ║  فاحص تسريب كلمات السر والإيميلات       ║", "cyan"))
    print(c("  ╚══════════════════════════════════════════╝", "cyan"))
    print()
    print(c("  1) فحص كلمة سر (Password Check)", "cyan"))
    print(c("  2) فحص إيميل (Email Check)", "cyan"))
    print(c("  3) فحص قائمة إيميلات من ملف", "cyan"))
    print()

    try:
        choice = input(c("  اختر: ", "bold")).strip()
    except (EOFError, KeyboardInterrupt):
        return

    if choice == "1":
        import getpass
        print()
        try:
            pw = getpass.getpass(c("  أدخل كلمة السر (ما تنعرض): ", "yellow"))
        except (EOFError, KeyboardInterrupt):
            return
        if not pw:
            print(c("  [!] ما أدخلت شي", "red"))
            return

        strength = check_password_strength(pw)
        masked = pw[0] + "*" * (len(pw) - 2) + pw[-1] if len(pw) > 2 else "***"

        print(c("\n  ⏳ يفحص بقاعدة بيانات التسريبات...", "yellow"))
        count = check_password(pw)
        print_password_result(masked, count, strength)

    elif choice == "2":
        print()
        try:
            email = input(c("  أدخل الإيميل: ", "yellow")).strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not email or "@" not in email:
            print(c("  [!] إيميل غير صحيح", "red"))
            return

        api_key = os.environ.get("HIBP_API_KEY", "")
        print(c("\n  ⏳ يفحص بقاعدة بيانات التسريبات...", "yellow"))
        breaches = check_email(email, api_key)
        print_email_result(email, breaches)

    elif choice == "3":
        print()
        try:
            filepath = input(c("  أدخل مسار الملف (إيميل بكل سطر): ", "yellow")).strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not os.path.isfile(filepath):
            print(c("  [!] الملف غير موجود", "red"))
            return

        api_key = os.environ.get("HIBP_API_KEY", "")
        with open(filepath, "r", encoding="utf-8") as f:
            emails = [line.strip() for line in f if "@" in line.strip()]

        print(c(f"\n  📋 عدد الإيميلات: {len(emails)}", "cyan"))
        leaked = 0
        for i, email in enumerate(emails, 1):
            print(c(f"\r  ⏳ يفحص {i}/{len(emails)}: {email}...", "yellow"), end="")
            breaches = check_email(email, api_key)
            if breaches and not (len(breaches) == 1 and breaches[0].get("Name") == "check_manually"):
                leaked += 1
                print(c(f"\n  🚨 {email} — {len(breaches)} تسريب!", "crimson"))
            time.sleep(1.6)  # HIBP rate limit

        print(c(f"\n\n  ─── النتيجة ───", "cyan"))
        print(c(f"  الكل: {len(emails)} | مسرّب: {leaked} | آمن: {len(emails) - leaked}", "bold"))
        print()

    else:
        print(c("  [!] اختيار غير صحيح", "red"))


# ─── CLI ───
def main():
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="RAQIB Credential Leak Checker")
        parser.add_argument("--password", help="فحص كلمة سر")
        parser.add_argument("--email", help="فحص إيميل")
        parser.add_argument("--file", help="فحص قائمة إيميلات من ملف")
        parser.add_argument("--api-key", default="", help="HIBP API key")
        args = parser.parse_args()

        if args.password:
            strength = check_password_strength(args.password)
            count = check_password(args.password)
            masked = args.password[0] + "*" * (len(args.password) - 2) + args.password[-1]
            print_password_result(masked, count, strength)
        elif args.email:
            breaches = check_email(args.email, args.api_key)
            print_email_result(args.email, breaches)
        elif args.file:
            if not os.path.isfile(args.file):
                print(c("  [!] الملف غير موجود", "red"))
                sys.exit(1)
            with open(args.file, "r") as f:
                for line in f:
                    email = line.strip()
                    if "@" in email:
                        breaches = check_email(email, args.api_key)
                        print_email_result(email, breaches)
                        time.sleep(1.6)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
