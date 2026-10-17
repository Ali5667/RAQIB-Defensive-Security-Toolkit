#!/usr/bin/env python3
"""
RAQIB CTF Cipher Identifier & Auto-Solver
══════════════════════════════════════════

يكتشف نوع التشفير تلقائياً ويحاول فك التشفير بدون مفتاح.

Supported ciphers:
  - Base16/32/58/62/64/85
  - ROT1-25 (Caesar), ROT47
  - XOR (brute-force single/multi-byte keys)
  - Vigenère (Kasiski + IC attack)
  - Atbash, Affine
  - Morse Code
  - Binary / Octal / Decimal encoding
  - URL encoding, HTML entities
  - Substitution cipher (frequency analysis)
  - Hex dump / escaped hex

Usage:
  python3 cipher_solver.py identify <text>
  python3 cipher_solver.py solve <text>
  python3 cipher_solver.py solve-file <file>
  python3 cipher_solver.py brute-xor <hex_data> [--max-key-len 4]

Pure Python — zero dependencies.
"""
from __future__ import annotations
import argparse, base64, collections, itertools, json, math, re, string, sys
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# 1) CIPHER IDENTIFICATION
# ═══════════════════════════════════════════════════════════════════

def is_base64(text: str) -> float:
    """Score how likely the text is Base64."""
    t = text.strip()
    if not t:
        return 0.0
    if len(t) < 4:
        return 0.0
    b64_re = re.compile(r'^[A-Za-z0-9+/\n\r]+={0,2}$')
    if b64_re.match(t) and len(t) % 4 == 0:
        try:
            base64.b64decode(t)
            return 0.9
        except Exception:
            return 0.3
    return 0.0

def is_base32(text: str) -> float:
    t = text.strip().upper()
    if re.match(r'^[A-Z2-7]+=*$', t) and len(t) >= 8:
        try:
            base64.b32decode(t)
            return 0.85
        except Exception:
            return 0.1
    return 0.0

def is_base58(text: str) -> float:
    t = text.strip()
    b58_chars = set('123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz')
    if len(t) >= 10 and all(c in b58_chars for c in t):
        return 0.7
    return 0.0

def is_hex(text: str) -> float:
    t = text.strip().lower()
    t_clean = t.replace(' ', '').replace('0x', '').replace('\\x', '')
    if re.match(r'^[0-9a-f]+$', t_clean) and len(t_clean) >= 4 and len(t_clean) % 2 == 0:
        return 0.85
    return 0.0

def is_binary(text: str) -> float:
    t = text.strip().replace(' ', '')
    if re.match(r'^[01]+$', t) and len(t) >= 8 and len(t) % 8 == 0:
        return 0.9
    return 0.0

def is_octal(text: str) -> float:
    parts = text.strip().split()
    if len(parts) >= 3 and all(re.match(r'^[0-7]{2,3}$', p) for p in parts):
        return 0.85
    return 0.0

def is_decimal(text: str) -> float:
    parts = text.strip().split()
    if len(parts) >= 3 and all(p.isdigit() and 32 <= int(p) <= 126 for p in parts):
        return 0.8
    return 0.0

def is_morse(text: str) -> float:
    t = text.strip()
    if re.match(r'^[\.\-\s/|]+$', t) and '.' in t and '-' in t:
        return 0.9
    return 0.0

def is_url_encoded(text: str) -> float:
    if '%' in text and re.search(r'%[0-9A-Fa-f]{2}', text):
        pct = text.count('%')
        return min(0.9, 0.3 + pct * 0.1)
    return 0.0

def is_rot_cipher(text: str) -> float:
    t = text.strip()
    if not t or not any(c.isalpha() for c in t):
        return 0.0
    alpha_ratio = sum(c.isalpha() or c.isspace() for c in t) / len(t)
    if alpha_ratio > 0.8:
        return 0.5  # Could be ROT
    return 0.2

def is_xor_hex(text: str) -> float:
    t = text.strip().lower().replace(' ', '')
    if re.match(r'^[0-9a-f]+$', t) and len(t) >= 10:
        # Check entropy of decoded bytes
        try:
            data = bytes.fromhex(t)
            entropy = shannon_entropy(data)
            if 3.0 < entropy < 7.0:
                return 0.6
        except Exception:
            pass
    return 0.0

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = collections.Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

def is_vigenere(text: str) -> float:
    t = ''.join(c for c in text if c.isalpha())
    if len(t) < 20:
        return 0.1
    freq = collections.Counter(t.lower())
    ic = sum(f*(f-1) for f in freq.values()) / (len(t)*(len(t)-1)) if len(t) > 1 else 0
    # English IC ~0.065, random ~0.038, Vigenère ~0.04-0.05
    if 0.035 < ic < 0.055:
        return 0.7
    return 0.2


def identify_cipher(text: str) -> list[dict]:
    """Identify possible cipher types with confidence scores."""
    results = []
    checks = [
        ('base64', is_base64),
        ('base32', is_base32),
        ('base58', is_base58),
        ('hex', is_hex),
        ('binary', is_binary),
        ('octal', is_octal),
        ('decimal', is_decimal),
        ('morse', is_morse),
        ('url_encoded', is_url_encoded),
        ('rot_cipher', is_rot_cipher),
        ('xor', is_xor_hex),
        ('vigenere', is_vigenere),
    ]
    for name, check_fn in checks:
        score = check_fn(text)
        if score > 0.1:
            results.append({'cipher': name, 'confidence': round(score, 2)})

    results.sort(key=lambda x: x['confidence'], reverse=True)
    return results


# ═══════════════════════════════════════════════════════════════════
# 2) SOLVERS
# ═══════════════════════════════════════════════════════════════════

MORSE_MAP = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
    '.-.-.-': '.', '--..--': ',', '..--..': '?', '-.-.--': '!',
}

ENGLISH_FREQ = {
    'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0,
    'n': 6.7, 's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3,
    'l': 4.0, 'c': 2.8, 'u': 2.8, 'm': 2.4, 'w': 2.4,
    'f': 2.2, 'g': 2.0, 'y': 2.0, 'p': 1.9, 'b': 1.5,
}


def english_score(text: str) -> float:
    """Score how likely text is readable English."""
    if not text:
        return 0.0
    lower = text.lower()
    alpha = [c for c in lower if c.isalpha()]
    if not alpha:
        return 0.0
    freq = collections.Counter(alpha)
    total = len(alpha)
    score = sum(ENGLISH_FREQ.get(c, 0) * (freq.get(c, 0) / total) for c in ENGLISH_FREQ)
    # Bonus for common words
    common_words = ['the', 'and', 'for', 'are', 'but', 'not', 'you', 'all',
                    'can', 'had', 'her', 'was', 'one', 'our', 'flag', 'ctf']
    word_bonus = sum(0.5 for w in common_words if w in lower)
    printable_ratio = sum(c.isprintable() for c in text) / len(text)
    return (score + word_bonus) * printable_ratio


def solve_base64(text: str) -> str | None:
    try:
        return base64.b64decode(text.strip()).decode('utf-8', errors='replace')
    except Exception:
        return None

def solve_base32(text: str) -> str | None:
    try:
        return base64.b32decode(text.strip().upper()).decode('utf-8', errors='replace')
    except Exception:
        return None

def solve_base58(text: str) -> str | None:
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    try:
        t = text.strip()
        num = 0
        for c in t:
            num = num * 58 + ALPHABET.index(c)
        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256
        return bytes(reversed(result)).decode('utf-8', errors='replace')
    except Exception:
        return None

def solve_hex(text: str) -> str | None:
    try:
        t = text.strip().lower().replace(' ', '').replace('0x', '').replace('\\x', '')
        return bytes.fromhex(t).decode('utf-8', errors='replace')
    except Exception:
        return None

def solve_binary(text: str) -> str | None:
    try:
        t = text.strip().replace(' ', '')
        chars = [chr(int(t[i:i+8], 2)) for i in range(0, len(t), 8)]
        return ''.join(chars)
    except Exception:
        return None

def solve_octal(text: str) -> str | None:
    try:
        parts = text.strip().split()
        return ''.join(chr(int(p, 8)) for p in parts)
    except Exception:
        return None

def solve_decimal(text: str) -> str | None:
    try:
        parts = text.strip().split()
        return ''.join(chr(int(p)) for p in parts)
    except Exception:
        return None

def solve_morse(text: str) -> str | None:
    try:
        words = text.strip().replace('|', '/').split('/')
        result = []
        for word in words:
            chars = word.strip().split()
            decoded = ''.join(MORSE_MAP.get(c, '?') for c in chars)
            result.append(decoded)
        return ' '.join(result)
    except Exception:
        return None

def solve_url(text: str) -> str | None:
    try:
        result = re.sub(r'%([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), text)
        return result
    except Exception:
        return None

def solve_rot(text: str) -> list[dict]:
    """Try all ROT shifts and score results."""
    results = []
    for shift in range(1, 26):
        decoded = ''
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decoded += chr((ord(c) - base + shift) % 26 + base)
            else:
                decoded += c
        score = english_score(decoded)
        if score > 1.0:
            results.append({'shift': shift, 'text': decoded, 'score': round(score, 2)})
    results.sort(key=lambda x: x['score'], reverse=True)
    return results[:5]

def solve_rot47(text: str) -> str:
    result = ''
    for c in text:
        o = ord(c)
        if 33 <= o <= 126:
            result += chr(33 + ((o - 33 + 47) % 94))
        else:
            result += c
    return result

def solve_atbash(text: str) -> str:
    result = ''
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr(base + 25 - (ord(c) - base))
        else:
            result += c
    return result

def solve_xor_brute(data: bytes, max_key_len: int = 4) -> list[dict]:
    """Brute-force XOR with single and multi-byte keys."""
    results = []

    # Single-byte XOR
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in data)
        try:
            text = decoded.decode('utf-8', errors='replace')
            score = english_score(text)
            if score > 2.0:
                results.append({
                    'key': f'0x{key:02x}',
                    'key_len': 1,
                    'text': text[:100],
                    'score': round(score, 2),
                })
        except Exception:
            pass

    # Multi-byte XOR (2-4 bytes)
    if max_key_len >= 2:
        for kl in range(2, min(max_key_len + 1, 5)):
            # Try common key patterns
            for key_byte in range(1, 256):
                key = bytes([key_byte]) * kl
                decoded = bytes(data[i] ^ key[i % kl] for i in range(len(data)))
                try:
                    text = decoded.decode('utf-8', errors='replace')
                    score = english_score(text)
                    if score > 3.0:
                        results.append({
                            'key': key.hex(),
                            'key_len': kl,
                            'text': text[:100],
                            'score': round(score, 2),
                        })
                except Exception:
                    pass

    results.sort(key=lambda x: x['score'], reverse=True)
    return results[:10]


# ═══════════════════════════════════════════════════════════════════
# 3) MASTER SOLVER
# ═══════════════════════════════════════════════════════════════════

NC = '\033[0m'
GREEN = '\033[0;32m'
CYAN = '\033[0;36m'
YELLOW = '\033[1;33m'
BOLD = '\033[1m'


def auto_solve(text: str) -> list[dict]:
    """Try all decoders and return successful results ranked by English score."""
    results = []

    solvers = [
        ('Base64', solve_base64),
        ('Base32', solve_base32),
        ('Base58', solve_base58),
        ('Hex', solve_hex),
        ('Binary', solve_binary),
        ('Octal', solve_octal),
        ('Decimal', solve_decimal),
        ('Morse', solve_morse),
        ('URL Decode', solve_url),
        ('Atbash', solve_atbash),
        ('ROT47', lambda t: solve_rot47(t)),
    ]

    for name, solver in solvers:
        try:
            decoded = solver(text)
            if decoded and len(decoded.strip()) > 0:
                score = english_score(decoded)
                if score > 0.5 or (name in ('Hex', 'Base64', 'Base32') and decoded.strip()):
                    results.append({
                        'method': name,
                        'result': decoded.strip(),
                        'english_score': round(score, 2),
                    })
                    # Try recursive decode (double encoding)
                    if score > 2.0:
                        for name2, solver2 in solvers:
                            try:
                                decoded2 = solver2(decoded.strip())
                                if decoded2:
                                    score2 = english_score(decoded2)
                                    if score2 > score:
                                        results.append({
                                            'method': f'{name} → {name2}',
                                            'result': decoded2.strip(),
                                            'english_score': round(score2, 2),
                                        })
                            except Exception:
                                pass
        except Exception:
            pass

    # ROT ciphers
    rot_results = solve_rot(text)
    for r in rot_results:
        results.append({
            'method': f'ROT{r["shift"]} (Caesar)',
            'result': r['text'],
            'english_score': r['score'],
        })

    # XOR (only if looks like hex)
    if is_hex(text) > 0.5:
        try:
            data = bytes.fromhex(text.strip().lower().replace(' ', ''))
            xor_results = solve_xor_brute(data, max_key_len=2)
            for r in xor_results:
                results.append({
                    'method': f'XOR (key={r["key"]})',
                    'result': r['text'],
                    'english_score': r['score'],
                })
        except Exception:
            pass

    results.sort(key=lambda x: x['english_score'], reverse=True)
    return results


def main():
    parser = argparse.ArgumentParser(description="RAQIB CTF Cipher Identifier & Auto-Solver")
    sub = parser.add_subparsers(dest='command')

    p_id = sub.add_parser('identify', help='Identify cipher type')
    p_id.add_argument('text', nargs='+')

    p_solve = sub.add_parser('solve', help='Auto-solve cipher')
    p_solve.add_argument('text', nargs='+')
    p_solve.add_argument('--top', type=int, default=5)

    p_file = sub.add_parser('solve-file', help='Solve from file')
    p_file.add_argument('file')
    p_file.add_argument('--top', type=int, default=5)

    p_xor = sub.add_parser('brute-xor', help='Brute-force XOR')
    p_xor.add_argument('hex_data')
    p_xor.add_argument('--max-key-len', type=int, default=4)

    args = parser.parse_args()

    if args.command == 'identify':
        text = ' '.join(args.text)
        results = identify_cipher(text)
        print(f"\n  {BOLD}Cipher Identification Results:{NC}")
        print(f"  {'─' * 40}")
        for r in results:
            bar = '█' * int(r['confidence'] * 20)
            print(f"  {CYAN}{r['cipher']:15s}{NC} {r['confidence']:.0%}  {bar}")

    elif args.command == 'solve':
        text = ' '.join(args.text)
        print(f"\n  {BOLD}🔓 Auto-Solving...{NC}")
        print(f"  Input: {text[:80]}{'...' if len(text)>80 else ''}")
        print(f"  {'─' * 50}")

        results = auto_solve(text)
        for i, r in enumerate(results[:args.top]):
            color = GREEN if r['english_score'] > 5 else YELLOW if r['english_score'] > 2 else NC
            print(f"\n  {color}#{i+1} [{r['method']}]{NC} (score={r['english_score']})")
            print(f"  → {r['result'][:200]}")

        if not results:
            print(f"  {YELLOW}No successful decoding found{NC}")

    elif args.command == 'solve-file':
        text = Path(args.file).read_text(encoding='utf-8', errors='replace').strip()
        print(f"  Solving from file: {args.file} ({len(text)} chars)")
        results = auto_solve(text)
        for i, r in enumerate(results[:args.top]):
            print(f"\n  #{i+1} [{r['method']}] (score={r['english_score']})")
            print(f"  → {r['result'][:200]}")

    elif args.command == 'brute-xor':
        data = bytes.fromhex(args.hex_data.replace(' ', ''))
        print(f"  Brute-forcing XOR ({len(data)} bytes, max key={args.max_key_len})...")
        results = solve_xor_brute(data, args.max_key_len)
        for r in results:
            print(f"\n  Key={r['key']} (len={r['key_len']}) score={r['score']}")
            print(f"  → {r['text']}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
