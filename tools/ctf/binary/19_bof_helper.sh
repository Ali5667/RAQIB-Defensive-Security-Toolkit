#!/bin/bash
# =============================================================
#  RAQIB CTF — BOF Helper (Buffer Overflow)
#  أداة #19: مساعد Buffer Overflow — pattern gen + offset
#  اللغة: Bash wrapper + Python heredoc
#         Python لأن De Bruijn sequence generation ومعالجة
#         binary data — shell لا يكفي هنا أبداً
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  💥 BOF Helper — Buffer Overflow Assistant        ║${NC}"
echo -e "${CYAN}║  Pattern Generator + Offset Finder + ROP helper  ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

echo -e "  ${YELLOW}1)${NC} Generate cyclic pattern (De Bruijn)"
echo -e "  ${YELLOW}2)${NC} Find offset من قيمة EIP/RIP"
echo -e "  ${YELLOW}3)${NC} Generate NOP sled + shellcode wrapper"
echo -e "  ${YELLOW}4)${NC} Endianness converter (addr ↔ bytes)"
echo -e "  ${YELLOW}5)${NC} ret2win: حساب padding + jump address"
echo ""
read -rp "  اختر: " bof_mode

python3 - "$bof_mode" <<'PYEOF'
import sys, struct

mode = sys.argv[1]

def de_bruijn(alphabet, n):
    """Generate De Bruijn sequence B(len(alphabet), n)"""
    k = len(alphabet)
    a = [0] * k * n
    sequence = []

    def db(t, p):
        if t > n:
            if n % p == 0:
                sequence.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    db(1, 1)
    return ''.join(alphabet[i] for i in sequence)

def cyclic(length):
    """Cyclic pattern using De Bruijn sequence (pwntools style)"""
    pattern = de_bruijn('abcdefghijklmnopqrstuvwxyz', 4)
    return (pattern * (length // len(pattern) + 1))[:length]

def cyclic_find(value, length=None):
    """Find offset of 4-byte value in cyclic pattern"""
    pattern = de_bruijn('abcdefghijklmnopqrstuvwxyz', 4)
    if isinstance(value, int):
        # Try little-endian 32-bit
        try:
            needle = struct.pack('<I', value & 0xFFFFFFFF).decode('latin-1')
            idx = pattern.find(needle)
            if idx != -1:
                return idx, 'little-endian 32-bit'
        except Exception:
            pass
        # Try little-endian 64-bit
        try:
            needle = struct.pack('<Q', value & 0xFFFFFFFFFFFFFFFF).decode('latin-1')
            idx = pattern.find(needle)
            if idx != -1:
                return idx, 'little-endian 64-bit'
        except Exception:
            pass
    elif isinstance(value, str):
        idx = pattern.find(value)
        if idx != -1:
            return idx, 'string match'
    return -1, None

SEP = "═" * 55

print(f"\n{SEP}")

# ─── Mode 1: Generate Pattern ─────────────────────────────────
if mode == "1":
    length_str = input("  طول الـ pattern (default: 200): ").strip()
    try:
        length = int(length_str) if length_str else 200
    except ValueError:
        length = 200
    pattern = cyclic(length)
    print(f"\n  ✅ Cyclic Pattern ({length} bytes):")
    print(f"\n  {pattern}")
    print(f"\n  نسخ للـ payload:")
    print(f"  python3: payload = b\"{pattern}\"")
    print(f"  gdb:     r <<< $(python3 -c \"print('{pattern}')\")")

# ─── Mode 2: Find Offset ─────────────────────────────────────
elif mode == "2":
    print("  أدخل قيمة EIP/RIP المُتحكَّم بها:")
    print("  (hex مثل: 0x61616164  أو  str مثل: aaab)")
    val_str = input("  القيمة: ").strip()

    if val_str.startswith('0x') or val_str.startswith('0X'):
        try:
            val = int(val_str, 16)
            offset, method = cyclic_find(val)
        except ValueError:
            print("  ❌ قيمة غير صحيحة"); sys.exit(1)
    else:
        offset, method = cyclic_find(val_str)

    if offset >= 0:
        print(f"\n  ✅ Offset = {offset} bytes  [{method}]")
        print(f"\n  Exploit skeleton:")
        print(f"  payload = b'A' * {offset}  # padding")
        print(f"  payload += b'\\xef\\xbe\\xad\\xde'  # new EIP (0xdeadbeef)")
        print(f"  payload += b'\\x90' * 16  # NOP sled (اختياري)")
        print(f"  payload += shellcode")
    else:
        print(f"\n  ❌ لم يُعثر على القيمة في الـ pattern.")
        print("  تأكد أن القيمة من نفس pattern المُولَّد.")

# ─── Mode 3: NOP Sled + Shellcode ────────────────────────────
elif mode == "3":
    try:
        nop_len = int(input("  طول NOP sled (default: 32): ").strip() or "32")
        pad_len = int(input("  طول padding قبل NOP (offset): ").strip() or "0")
    except ValueError:
        nop_len, pad_len = 32, 0

    print(f"\n  ✅ Payload Structure:")
    print(f"  padding  = b'A' * {pad_len}      # حتى EIP")
    print(f"  ret_addr = b'\\x?\\x?\\x?\\x?'    # عنوان يقع على NOP sled")
    print(f"  nop      = b'\\x90' * {nop_len}   # NOP sled")
    print(f"  shellcode = b'...'               # shellcode")
    print(f"\n  payload = padding + ret_addr + nop + shellcode")
    print(f"\n  Python one-liner:")
    print(f"  python3 -c \"import sys; sys.stdout.buffer.write(b'A'*{pad_len} + b'BBBB' + b'\\x90'*{nop_len} + b'<shellcode here>')\"")

# ─── Mode 4: Endianness ──────────────────────────────────────
elif mode == "4":
    print("  أدخل العنوان كـ hex (مثل: 0x08049396):")
    addr_str = input("  العنوان: ").strip()
    try:
        addr = int(addr_str, 16)
    except ValueError:
        print("  ❌ قيمة غير صحيحة"); sys.exit(1)

    le32 = struct.pack('<I', addr & 0xFFFFFFFF)
    be32 = struct.pack('>I', addr & 0xFFFFFFFF)
    le64 = struct.pack('<Q', addr & 0xFFFFFFFFFFFFFFFF)
    be64 = struct.pack('>Q', addr & 0xFFFFFFFFFFFFFFFF)

    def to_hex_str(b):
        return ' '.join(f'\\x{x:02x}' for x in b)

    print(f"\n  العنوان: {hex(addr)}")
    print(f"\n  Little-endian 32-bit: {to_hex_str(le32)}")
    print(f"  Big-endian    32-bit: {to_hex_str(be32)}")
    print(f"  Little-endian 64-bit: {to_hex_str(le64)}")
    print(f"  Big-endian    64-bit: {to_hex_str(be64)}")
    print(f"\n  Python: struct.pack('<I', {hex(addr)}) = {le32}")
    print(f"  p32({hex(addr)}) = {le32}  ← pwntools format")

# ─── Mode 5: ret2win ─────────────────────────────────────────
elif mode == "5":
    print("  ret2win: القفز لدالة win() أو system('/bin/sh')")
    try:
        offset = int(input("  offset إلى EIP/RIP: ").strip())
        win_addr_str = input("  عنوان دالة win() (hex): ").strip()
        arch = input("  32-bit أو 64-bit? (32/64, default: 32): ").strip() or "32"
        win_addr = int(win_addr_str, 16)
    except (ValueError, EOFError):
        print("  ❌ قيمة غير صحيحة"); sys.exit(1)

    if arch == "64":
        addr_bytes = struct.pack('<Q', win_addr)
    else:
        addr_bytes = struct.pack('<I', win_addr & 0xFFFFFFFF)

    addr_escaped = ''.join(f'\\x{b:02x}' for b in addr_bytes)

    print(f"\n  ✅ ret2win Exploit:")
    print(f"  payload = b'A' * {offset}  # padding")
    print(f"  payload += b\"{addr_escaped}\"  # {hex(win_addr)}")
    print(f"\n  Python3 script:")
    print(f"  from pwn import *")
    print(f"  p = process('./binary')")
    print(f"  p.sendline(b'A' * {offset} + p{'32' if arch == '32' else '64'}({hex(win_addr)}))")
    print(f"  p.interactive()")

else:
    print("  اختيار غير صحيح")

print()
PYEOF

pause
