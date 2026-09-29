#!/bin/bash
# =============================================================
#  RAQIB CTF — RSA Helper
#  أداة #3: مساعد RSA للمسابقات
#  اللغة: Bash wrapper + Python heredoc (الحساب الرياضي ثقيل)
#  يغطي: small N factoring, e=3 cube root, Wiener attack,
#         Chinese Remainder Theorem, common CTF RSA scenarios
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🔑 RSA Helper — CTF Edition                     ║${NC}"
echo -e "${CYAN}║  يحل أشيع هجمات RSA في المسابقات                ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${YELLOW}1)${NC} Factorize N صغير (brute force / Fermat)"
echo -e "  ${YELLOW}2)${NC} e=3 Attack (Small Public Exponent)"
echo -e "  ${YELLOW}3)${NC} Wiener Attack (Small Private Key d)"
echo -e "  ${YELLOW}4)${NC} فك تشفير RSA عادي (لو عندك p, q, e, c)"
echo -e "  ${YELLOW}5)${NC} Common Modulus Attack (نفس N مع e مختلف)"
echo ""
read -rp "  اختر: " rsa_mode

python3 - "$rsa_mode" <<'PYEOF'
import sys, math

mode = sys.argv[1]

def modinv(a, m):
    """Extended Euclidean Algorithm"""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def iroot(n, k):
    """Integer k-th root"""
    if n < 0:
        return None
    if n == 0:
        return 0
    x = int(round(n ** (1/k)))
    # refine
    for candidate in [x - 1, x, x + 1]:
        if candidate >= 0 and candidate ** k == n:
            return candidate
    # binary search for large numbers
    lo, hi = 0, min(n, 10**50)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo if lo ** k == n else None

def fermat_factor(n, max_iter=1_000_000):
    """Fermat's factorization — fast when p ≈ q"""
    a = math.isqrt(n)
    if a * a == n:
        return a, a
    a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None, None

def trial_division(n, limit=10_000_000):
    """Trial division up to limit"""
    if n % 2 == 0:
        return 2, n // 2
    i = 3
    while i * i <= n and i <= limit:
        if n % i == 0:
            return i, n // i
        i += 2
    return None, None

def continued_fraction(n, d):
    """Generate continued fraction coefficients of n/d"""
    while d:
        yield n // d
        n, d = d, n % d

def convergents(cf):
    """Generate convergents from continued fraction coefficients"""
    n0, n1 = 1, 0
    d0, d1 = 0, 1
    for a in cf:
        n0, n1 = a * n0 + n1, n0
        d0, d1 = a * d0 + d1, d0
        yield n0, d0

def wiener_attack(e, n):
    """Wiener's attack on small d"""
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # solve x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        disc = b * b - 4 * n
        if disc < 0:
            continue
        sq = math.isqrt(disc)
        if sq * sq == disc:
            p = (b + sq) // 2
            q = (b - sq) // 2
            if p * q == n:
                return d, p, q
    return None, None, None

SEP = "═" * 55

print(f"\n{SEP}")

# ─── Mode 1: Factorize N ──────────────────────────────────────
if mode == "1":
    print("  🔢 Factorize N")
    print(SEP)
    n_str = input("  أدخل N: ").strip()
    try:
        N = int(n_str)
    except ValueError:
        print("  ❌ قيمة غير صحيحة"); sys.exit(1)

    print(f"\n  N = {N}")
    print(f"  طول N = {N.bit_length()} bit\n")

    # Trial division
    p, q = trial_division(N)
    if p:
        print(f"  ✅ Trial Division نجح:")
        print(f"     p = {p}")
        print(f"     q = {q}")
    else:
        # Fermat
        print("  جاري محاولة Fermat factorization...")
        p, q = fermat_factor(N)
        if p:
            print(f"  ✅ Fermat نجح (p ≈ q):")
            print(f"     p = {p}")
            print(f"     q = {q}")
        else:
            print("  ⚠️  فشل الـ factoring المحلي.")
            print("  💡 جرب: https://www.factordb.com/ أو https://mersenne.org/")

# ─── Mode 2: e=3 Cube Root Attack ────────────────────────────
elif mode == "2":
    print("  🎯 e=3 Small Exponent Attack")
    print(SEP)
    c_str = input("  أدخل C (ciphertext): ").strip()
    try:
        C = int(c_str)
    except ValueError:
        print("  ❌ قيمة غير صحيحة"); sys.exit(1)

    # m = cube_root(C) — يشتغل لو m^3 < N (plaintext صغير)
    m = iroot(C, 3)
    if m is not None:
        print(f"\n  ✅ Cube root نجح!")
        print(f"  m (int) = {m}")
        try:
            msg = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8', errors='replace')
            print(f"  m (text) = {msg}")
        except Exception:
            pass
    else:
        print("  ⚠️  C ليس مكعباً كاملاً — المُرسَل أضاف padding.")
        print("  💡 جرب Hastad's broadcast attack لو عندك نفس الرسالة لـ 3 مفاتيح مختلفة.")

# ─── Mode 3: Wiener Attack ────────────────────────────────────
elif mode == "3":
    print("  🌀 Wiener Attack (Small d)")
    print(SEP)
    try:
        e = int(input("  أدخل e: ").strip())
        n = int(input("  أدخل N: ").strip())
    except ValueError:
        print("  ❌ قيمة غير صحيحة"); sys.exit(1)

    d, p, q = wiener_attack(e, n)
    if d:
        print(f"\n  ✅ Wiener Attack نجح!")
        print(f"  d = {d}")
        print(f"  p = {p}")
        print(f"  q = {q}")
        c_str = input("\n  أدخل C لفك التشفير (أو Enter للتخطي): ").strip()
        if c_str:
            try:
                C = int(c_str)
                m = pow(C, d, n)
                print(f"  m (int) = {m}")
                msg = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8', errors='replace')
                print(f"  m (text) = {msg}")
            except Exception as ex:
                print(f"  خطأ: {ex}")
    else:
        print("  ⚠️  Wiener فشل — d ليس صغيراً بما يكفي.")

# ─── Mode 4: Standard RSA Decrypt ────────────────────────────
elif mode == "4":
    print("  🔓 فك تشفير RSA (عندك p, q, e, c)")
    print(SEP)
    try:
        p = int(input("  p = ").strip())
        q = int(input("  q = ").strip())
        e = int(input("  e = ").strip())
        C = int(input("  c = ").strip())
    except ValueError:
        print("  ❌ قيمة غير صحيحة"); sys.exit(1)

    n   = p * q
    phi = (p - 1) * (q - 1)
    d   = modinv(e, phi)
    if d is None:
        print("  ❌ e غير قابل للعكس mod phi(n)"); sys.exit(1)
    m   = pow(C, d, n)
    print(f"\n  n   = {n}")
    print(f"  phi = {phi}")
    print(f"  d   = {d}")
    print(f"  m (int) = {m}")
    try:
        msg = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8', errors='replace')
        print(f"  m (text) = {msg}")
    except Exception:
        pass

# ─── Mode 5: Common Modulus Attack ───────────────────────────
elif mode == "5":
    print("  🔗 Common Modulus Attack")
    print("  (نفس الرسالة مشفرة بنفس N ولكن e مختلف)")
    print(SEP)
    try:
        n  = int(input("  N = ").strip())
        e1 = int(input("  e1 = ").strip())
        c1 = int(input("  c1 = ").strip())
        e2 = int(input("  e2 = ").strip())
        c2 = int(input("  c2 = ").strip())
    except ValueError:
        print("  ❌ قيمة غير صحيحة"); sys.exit(1)

    g, a, b = extended_gcd(e1, e2)
    if g != 1:
        print(f"  ⚠️  gcd(e1,e2) = {g} ≠ 1 — الهجوم لا ينطبق مباشرةً"); sys.exit(1)

    if a < 0:
        c1_inv = modinv(c1, n)
        if c1_inv is None:
            print("  ❌ c1 غير قابل للعكس mod n"); sys.exit(1)
        m = (pow(c1_inv, -a, n) * pow(c2, b, n)) % n
    else:
        m = (pow(c1, a, n) * pow(c2, b, n)) % n

    print(f"\n  ✅ Common Modulus Attack:")
    print(f"  m (int) = {m}")
    try:
        msg = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8', errors='replace')
        print(f"  m (text) = {msg}")
    except Exception:
        pass

else:
    print("  اختيار غير صحيح")

print()
PYEOF

pause
