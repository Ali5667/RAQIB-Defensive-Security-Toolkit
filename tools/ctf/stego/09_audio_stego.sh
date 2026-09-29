#!/bin/bash
# =============================================================
#  RAQIB CTF — Audio Stego
#  أداة #9: كشف إشارات مخفية بالصوت
#  يدعم: spectrogram hints (Sox), Morse في القناة، DTMF
# =============================================================

echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  🎵 Audio Stego — Spectrogram + Morse + DTMF    ║${NC}"
echo -e "${CYAN}║  تحليل ملفات صوتية بحثاً عن بيانات مخفية       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

read -rp "  مسار الملف الصوتي (WAV/MP3): " audio_file
[ ! -f "$audio_file" ] && { echo -e "${RED}الملف غير موجود${NC}"; exit 1; }

echo ""
echo -e "${BOLD}══ 1. معلومات الملف ══${NC}"
if command -v file >/dev/null 2>&1; then
    file -- "$audio_file"
fi
ls -lah -- "$audio_file"
echo ""

echo -e "${BOLD}══ 2. Strings وFlags مضمّنة ══${NC}"
python3 - "$audio_file" <<'PYEOF'
import sys, re

with open(sys.argv[1], 'rb') as f:
    data = f.read()

strings = re.findall(rb'[\x20-\x7e]{4,}', data)
strings = [s.decode('ascii', errors='replace') for s in strings]

flags = [s for s in strings if re.search(r'(?:flag|FLAG|CTF|ctf|picoCTF)\{[^}]+\}', s)]
urls  = [s for s in strings if re.match(r'https?://', s)]
suspicious = [s for s in strings if re.search(r'password|secret|hidden|morse|steg', s, re.I)]

if flags:
    print(f"  🏴 FLAGS في الملف:")
    for f in flags: print(f"    {f}")
if urls:
    print(f"  🌐 URLs:")
    for u in urls[:5]: print(f"    {u}")
if suspicious:
    print(f"  ⚠️  كلمات مشبوهة:")
    for s in suspicious[:10]: print(f"    {s}")

# معلومات رأس WAV
if data[:4] == b'RIFF':
    print(f"  📻 WAV Header:")
    if len(data) >= 44:
        import struct
        channels = struct.unpack('<H', data[22:24])[0]
        sample_rate = struct.unpack('<I', data[24:28])[0]
        bits_per_sample = struct.unpack('<H', data[34:36])[0]
        print(f"    Channels: {channels}  |  Sample Rate: {sample_rate} Hz  |  Bits: {bits_per_sample}")

if not flags and not urls and not suspicious:
    print(f"  ✅ لم يُعثر على شيء واضح في الـ strings")
    print(f"  📊 إجمالي strings مستخرجة: {len(strings)}")
PYEOF
echo ""

echo -e "${BOLD}══ 3. تحليل الـ Spectrogram (Sox) ══${NC}"
if command -v sox >/dev/null 2>&1; then
    echo -e "  ${GREEN}Sox متوفر${NC}"
    spec_file="/tmp/raqib_spectrogram_$(date +%s).png"
    if sox "$audio_file" -n spectrogram -o "$spec_file" 2>/dev/null; then
        echo -e "  ${GREEN}✅ تم إنشاء الـ spectrogram: ${spec_file}${NC}"
        echo -e "  افتحه بأي عارض صور للبحث عن نصوص/أنماط مخفية"
        if command -v eog >/dev/null 2>&1; then
            eog "$spec_file" &>/dev/null & disown
        elif command -v xdg-open >/dev/null 2>&1; then
            xdg-open "$spec_file" &>/dev/null & disown
        fi
    else
        echo -e "  ${YELLOW}تعذّر إنشاء الـ spectrogram — الملف قد لا يكون WAV${NC}"
    fi
else
    echo -e "  ${GREY}Sox غير مثبت (اختياري) — قم بتثبيته لعرض الـ spectrogram:${NC}"
    echo -e "  ${GREY}  apt install sox  أو  brew install sox${NC}"
fi
echo ""

echo -e "${BOLD}══ 4. فحص Morse Code (محاولة) ══${NC}"
if command -v sox >/dev/null 2>&1; then
    python3 - "$audio_file" <<'PYEOF'
import sys, subprocess, os, struct, math

# استخراج الـ PCM data
audio = sys.argv[1]

# نحوّل لـ WAV 8kHz mono مؤقت إن أمكن
tmp_wav = f"/tmp/raqib_morse_{os.getpid()}.wav"
result = subprocess.run(['sox', audio, '-r', '8000', '-c', '1', tmp_wav],
                        capture_output=True)
if result.returncode != 0:
    print("  تعذّر تحويل الصوت — تأكد من صحة الصيغة")
    sys.exit(0)

try:
    with open(tmp_wav, 'rb') as f:
        f.seek(44)  # تخطّ WAV header
        raw = f.read()

    # حوّل لـ amplitudes
    samples = struct.unpack(f'<{len(raw)//2}h', raw[:len(raw)//2*2])
    if not samples:
        print("  لا توجد بيانات صوتية")
        os.unlink(tmp_wav)
        sys.exit(0)

    max_amp = max(abs(s) for s in samples) or 1
    threshold = max_amp * 0.15  # 15% من الذروة

    # كشف silence vs sound
    chunk_ms = 50  # 50ms chunks
    rate = 8000
    chunk_size = rate * chunk_ms // 1000

    signal_chunks = []
    for i in range(0, len(samples)-chunk_size, chunk_size):
        chunk = samples[i:i+chunk_size]
        rms = math.sqrt(sum(s*s for s in chunk) / len(chunk))
        signal_chunks.append(rms > threshold)

    if not any(signal_chunks):
        print("  الصوت صامت أو المستوى منخفض جداً")
        os.unlink(tmp_wav)
        sys.exit(0)

    # رمّز كـ Morse (. = نبضة قصيرة, - = نبضة طويلة)
    runs = []
    current = signal_chunks[0]
    count = 0
    for v in signal_chunks:
        if v == current:
            count += 1
        else:
            runs.append((current, count))
            current = v
            count = 1
    runs.append((current, count))

    avg_on  = sum(c for v,c in runs if v) / max(1, sum(1 for v,c in runs if v))
    avg_off = sum(c for v,c in runs if not v) / max(1, sum(1 for v,c in runs if not v))

    MORSE_DECODE = {
        '.-':'A', '-...':'B', '-.-.':'C', '-..':'D', '.':'E', '..-.':'F',
        '--.':'G', '....':'H', '..':'I', '.---':'J', '-.-':'K', '.-..':'L',
        '--':'M', '-.':'N', '---':'O', '.--.':'P', '--.-':'Q', '.-.':'R',
        '...':'S', '-':'T', '..-':'U', '...-':'V', '.--':'W', '-..-':'X',
        '-.--':'Y', '--..':'Z', '-----':'0', '.----':'1', '..---':'2',
        '...--':'3', '....-':'4', '.....':'5', '-....':'6', '--...':'7',
        '---..':'8', '----.':'9',
    }

    morse_chars = []
    current_morse = []
    prev_was_sound = False
    for is_sound, count in runs:
        if is_sound:
            if count < avg_on * 1.5:
                current_morse.append('.')
            else:
                current_morse.append('-')
            prev_was_sound = True
        else:
            if count > avg_off * 3:
                morse_chars.append(''.join(current_morse))
                current_morse = []
            elif count > avg_off * 7:
                morse_chars.append(''.join(current_morse))
                current_morse = []
                morse_chars.append(' ')

    morse_str = ' '.join(morse_chars[:30])
    print(f"  📡 Morse pattern (أول 30 رمز): {morse_str}")

    # حاول فك التشفير
    words = []
    for symbol in morse_chars:
        if symbol == ' ':
            words.append(' ')
        elif symbol in MORSE_DECODE:
            words.append(MORSE_DECODE[symbol])
        else:
            words.append('?')
    decoded = ''.join(words)
    print(f"  💬 Decoded: {decoded[:100]}")

except Exception as e:
    print(f"  تعذّر تحليل Morse: {e}")
finally:
    try:
        os.unlink(tmp_wav)
    except:
        pass
PYEOF
else
    echo -e "  ${GREY}Sox غير متوفر — تعذّر تحليل Morse${NC}"
fi

echo ""
echo -e "${BOLD}══ 5. فحص DTMF Tones ══${NC}"
echo -e "  ${GREY}(لفك DTMF بدقة استخدم: multimon-ng -t WAV -a DTMF $audio_file)${NC}"
if command -v multimon-ng >/dev/null 2>&1; then
    multimon-ng -t WAV -a DTMF "$audio_file" 2>/dev/null | head -20
else
    echo -e "  ${GREY}multimon-ng غير مثبت (اختياري)${NC}"
fi
