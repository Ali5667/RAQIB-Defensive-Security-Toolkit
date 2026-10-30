#!/bin/bash
# =====================================================
#  RAQIB Platform Layer — طبقة المنصات للأنظمة المتعددة
#  يدعم: Kali/Linux · WSL2 · macOS · Windows (Git Bash / MSYS2 / Cyberwin)
#
#  يوفر هذا الملف:
#   • raqib_detect_os            → RAQIB_OS = linux | wsl | darwin | msys | cygwin | unknown
#   • raqib_is_windows/_macos/…  → اختبارات رخيصة جداً (بدون أوامر خارجية)
#   • raqib_win_ps               → تنفيذ آمن لسطر PowerShell من ويندوز أو WSL
#   • raqib_tr                   → نصّ ثنائي اللغة (عربي/إنجليزي) للمنصات الجديدة
#   • raqib_linux_only           → رسالة واضحة بدل انهيار الأدوات المخصّصة لـ /proc أو systemd
#   • Shims                      → تعويض أوامر GNU عند غيابها (macOS / Git Bash):
#                                  sha256sum, md5sum, tac, readlink -f, shred,
#                                  timeout, sed -i, stat -c, ss (بنفس ترتيب أعمدة ss الحقيقي)
#
#  كل shim يُعرَّف كدالة Bash فقط عندما الأمر الأصلي غير متوفر (أو بنيته
#  مختلفة على macOS) — وبالتالي لا يتغير أي سلوك على لينكس إطلاقاً.
# =====================================================
# RAQIB-Defensive-Security-Toolkit · Portability Layer (GPLv3)

# -----------------------------------------------------
#  كشف النظام — POSIX قياسي فقط، لا أوامر خارجية
# -----------------------------------------------------
raqib_detect_os() {
    [ -n "${RAQIB_OS:-}" ] && return 0
    local uname_s=""
    if command -v uname >/dev/null 2>&1; then
        uname_s="$(uname -s 2>/dev/null || true)"
    fi
    if [[ "$uname_s" == CYGWIN* ]]; then
        RAQIB_OS=cygwin
    elif [[ "$uname_s" == MINGW* || "$uname_s" == MSYS* || "${OSTYPE:-}" == msys* || "${OSTYPE:-}" == cygwin* || "${OSTYPE:-}" == win32 ]]; then
        RAQIB_OS=msys
    elif [ "$uname_s" = "Darwin" ]; then
        RAQIB_OS=darwin
    elif [ "$uname_s" = "Linux" ]; then
        RAQIB_OS=linux
        if [ -n "${WSL_DISTRO_NAME:-}" ] || grep -qi "microsoft" /proc/version 2>/dev/null; then
            RAQIB_OS=wsl
        fi
    else
        RAQIB_OS=unknown
    fi
    export RAQIB_OS
}
export -f raqib_detect_os
raqib_detect_os

# -----------------------------------------------------
#  اختبارات رخيصة للنظام
# -----------------------------------------------------
raqib_is_windows() { [ "${RAQIB_OS:-unknown}" = "msys" ] || [ "${RAQIB_OS:-unknown}" = "cygwin" ]; }
export -f raqib_is_windows

raqib_is_macos() { [ "${RAQIB_OS:-unknown}" = "darwin" ]; }
export -f raqib_is_macos

raqib_is_linux() { [ "${RAQIB_OS:-unknown}" = "linux" ] || [ "${RAQIB_OS:-unknown}" = "wsl" ]; }
export -f raqib_is_linux

raqib_is_wsl() { [ "${RAQIB_OS:-unknown}" = "wsl" ]; }
export -f raqib_is_wsl

# -----------------------------------------------------
#  جسر PowerShell — يعمل من Git Bash (MSYS) ومن داخل WSL حيث
#  يُتاح powershell.exe تلقائياً في PATH
# -----------------------------------------------------
raqib_has_windows_bridge() {
    command -v powershell.exe >/dev/null 2>&1 || command -v powershell >/dev/null 2>&1
}
export -f raqib_has_windows_bridge

# raqib_win_ps "<PowerShell code>" → يطبع الناتج بترميز UTF-8
raqib_win_ps() {
    local ps_bin=""
    if command -v powershell.exe >/dev/null 2>&1; then
        ps_bin="powershell.exe"
    elif command -v powershell >/dev/null 2>&1; then
        ps_bin="$(command -v powershell)"
    else
        return 1
    fi
    "$ps_bin" -NoProfile -NonInteractive -ExecutionPolicy Bypass \
        -Command "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \$ErrorActionPreference='SilentlyContinue'; $1" 2>/dev/null
}
export -f raqib_win_ps

# -----------------------------------------------------
#  نصّ ثنائي اللغة للمنصات الجديدة — الترجمة من RealLang.registry
#  الاستخدام: raqib_tr "نص عربي" "English text"
# -----------------------------------------------------
raqib_tr() {
    local ar_text="$1" en_text="$2"
    if [ "${LANG_CODE:-ar}" = "ar" ]; then
        printf '%s' "$ar_text"
    else
        printf '%s' "$en_text"
    fi
}
export -f raqib_tr

# -----------------------------------------------------
#  رسالة واضحة بدل الانهيار — للأدوات التي تعتمد على مكونات لينكس حصراً
#  (/proc، systemd، dpkg، ufw، iptables، auth.log...)
#  رمز الرجوع 2 = خطأ الاستخدام (الأسلوب المتبع في بقية أدوات المشروع)
# -----------------------------------------------------
raqib_linux_only() {
    local feature_ar="$1"
    local feature_en="${2:-$1}"
    echo ""
    echo -e "${BOLD}${ORANGE}$(raqib_tr "⚠️  ميزة مخصّصة لأنظمة Linux" "⚠️  Linux-only feature")${NC}: ${YELLOW}$(raqib_tr "$feature_ar" "$feature_en")${NC}"
    echo ""
    echo -e "  ${GREY}$(raqib_tr "هذه الأداة تعتمد على مكوّن مخصّص لـ Linux (مثل /proc أو systemd أو iptables)." "This tool depends on a Linux-specific subsystem (e.g. /proc, systemd or iptables).")${NC}"
    if raqib_has_windows_bridge; then
        echo -e "  ${CYAN}➤ $(raqib_tr "على ويندوز: جرّب حزمة الدفاع الأصلية:" "On Windows: try the native Windows Defense Suite:")${NC} ${BOLD}$(raqib_tr "تقوية الأنظمة → حزمة دفاع ويندوز" "System Hardening → Windows Defense Suite")${NC}"
        echo -e "  ${CYAN}➤ $(raqib_tr "أو شغّل الأداة كاملة داخل WSL2 (كل ميزات لينكس)." "or run this tool fully inside WSL2 for the full Linux feature set.")${NC}"
    else
        echo -e "  ${CYAN}➤ $(raqib_tr "ثبّت Git for Windows ليصبح RAQIB يعمل كأصلية على ويندوز، أو WSL2 لميزات لينكس كاملة." "Install Git for Windows for a native Windowsized RAQIB, or use WSL2 for full Linux features.")${NC}"
    fi
    echo -e "  ${CYAN}➤ $(raqib_tr "على macOS:" "On macOS:")${NC} ${GREY}$(raqib_tr "هذه الأداة لينكس حصراً — استخدم الأدوات المكافئة المدعومة (ماسح الاستمرارية، فاحص الجدار، سجل الدخول)." "This tool is Linux-exclusive - use the supported equivalents (persistence scanner, firewall checker, login history report).")${NC}"
    echo ""
    return 2
}
export -f raqib_linux_only

# رسالة نظيرة للأدوات المخصّصة لويندوز فقط
raqib_windows_only() {
    local feature_ar="$1"
    local feature_en="${2:-$1}"
    echo ""
    echo -e "${BOLD}${ORANGE}$(raqib_tr "⚠️  ميزة مخصّصة لأنظمة Windows" "⚠️  Windows-only feature")${NC}: ${YELLOW}$(raqib_tr "$feature_ar" "$feature_en")${NC}"
    echo -e "  ${GREY}$(raqib_tr "تشتغل من ويندوز أصلي (Git Bash) — تحتاج powershell.exe ووصولاً إلى واجهات النظام." "Requires a native Windows host (Git Bash) with powershell.exe and system access.")${NC}"
    echo ""
    return 2
}
export -f raqib_windows_only

# -----------------------------------------------------
#  إيجاد مترجم بايثون مرة واحدة (python3 / python / py -3)
# -----------------------------------------------------
_raqib_py() {
    if [ -n "${_RAQIB_PY_BIN:-}" ]; then
        printf '%s' "$_RAQIB_PY_BIN"
        return 0
    fi
    local py=""
    if command -v python3 >/dev/null 2>&1; then
        py="python3"
    elif command -v python >/dev/null 2>&1; then
        py="python"
    elif command -v py >/dev/null 2>&1 && py -3 -c "import sys" >/dev/null 2>&1; then
        py="py -3"
    else
        return 1
    fi
    _RAQIB_PY_BIN="$py"
    export _RAQIB_PY_BIN
    printf '%s' "$py"
}
export -f _raqib_py

# =====================================================================
#  SHIMS — تعويض الأوامر الناقصة/المختلفة على macOS و Git Bash
# =====================================================================

# -----------------------------------------------------
#  sha256sum / md5sum → shasum (macOS) أو بايثون (Windows)
# -----------------------------------------------------
if ! command -v sha256sum >/dev/null 2>&1; then
    if command -v shasum >/dev/null 2>&1; then
        # نعطي خرج shasum كما هو: "<hash>  <file>" — نفس شكل sha256sum
        sha256sum() { shasum -a 256 "$@"; }
        export -f sha256sum
    elif _raqib_py >/dev/null 2>&1; then
        sha256sum() {
            $(_raqib_py) - "$@" <<'PYEOF'
import sys, hashlib
rc = 0
for path in sys.argv[1:]:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        print(h.hexdigest())
    except OSError as e:
        sys.stderr.write(f"sha256sum: {e}\n")
        rc = 1
sys.exit(rc)
PYEOF
        }
        export -f sha256sum
    fi
fi

if ! command -v md5sum >/dev/null 2>&1; then
    if command -v md5 >/dev/null 2>&1; then
        # md5 -r يعطي: "<hash> <file>" — نفس ترتيب md5sum
        md5sum() { md5 -r "$@"; }
        export -f md5sum
    elif _raqib_py >/dev/null 2>&1; then
        md5sum() {
            $(_raqib_py) - "$@" <<'PYEOF'
import sys, hashlib
rc = 0
for path in sys.argv[1:]:
    try:
        h = hashlib.md5()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                h.update(chunk)
        print(h.hexdigest())
    except OSError as e:
        sys.stderr.write(f"md5sum: {e}\n")
        rc = 1
sys.exit(rc)
PYEOF
        }
        export -f md5sum
    fi
fi

# -----------------------------------------------------
#  tac → معاكسة الأسطر (macOS بلا tac) — ملفات و stdin وmultiple args
# -----------------------------------------------------
if ! command -v tac >/dev/null 2>&1; then
    tac() {
        awk '{buf[NR]=$0} END {for (i=NR; i>=1; i--) print buf[i]}' "$@"
    }
    export -f tac
fi

# -----------------------------------------------------
#  readlink -f → بايثون (macOS القديم لا يدعم -f)
# -----------------------------------------------------
if ! readlink -f / >/dev/null 2>&1; then
    readlink() {
        if [ "${1:-}" = "-f" ] && _raqib_py >/dev/null 2>&1; then
            shift
            $(_raqib_py) - "$@" <<'PYEOF'
import os, sys
for path in sys.argv[1:]:
    print(os.path.realpath(path))
PYEOF
        else
            command readlink "$@"
        fi
    }
    export -f readlink
fi

# -----------------------------------------------------
#  shred → نسخة بايثون آمنة (macOS/Windows) بأعلام متوافقة:
#  -n <عدد> مرات كتابة عشوائية، -z صفر أخير، -u حذف الملف بعدها
# -----------------------------------------------------
if ! command -v shred >/dev/null 2>&1; then
    shred() {
        if ! _raqib_py >/dev/null 2>&1; then
            rm -f "$@"
            return $?
        fi
        $(_raqib_py) - "$@" <<'PYEOF'
import sys, os

args = sys.argv[1:]
passes, zero_out, remove = 3, False, False
files = []
i = 0
while i < len(args):
    a = args[i]
    if a == "-n" and i + 1 < len(args):
        try:
            passes = max(1, int(args[i + 1]))
        except ValueError:
            passes = 3
        i += 2
        continue
    if a.startswith("--passes="):
        try:
            passes = max(1, int(a.split("=", 1)[1]))
        except ValueError:
            passes = 3
        i += 1
        continue
    if a in ("-z", "--zero"):
        zero_out = True
        i += 1
        continue
    if a in ("-u", "--remove"):
        remove = True
        i += 1
        continue
    if a in ("-f", "--force", "-v", "--verbose", "-x", "--exact", "-s"):
        i += 1
        continue
    if a == "--":
        files.extend(args[i + 1:])
        break
    files.append(a)
    i += 1

rc = 0
for path in files:
    try:
        size = os.path.getsize(path)
        if size == 0:
            if remove:
                os.unlink(path)
            continue
        total_writes = passes + (1 if zero_out else 0)
        with open(path, "r+b") as fh:
            for p in range(total_writes):
                fh.seek(0)
                left = size
                final_zero = zero_out and p == passes
                while left > 0:
                    n = min(65536, left)
                    chunk = b"\x00" * n if final_zero else os.urandom(n)
                    fh.write(chunk)
                    left -= n
                fh.flush()
                os.fsync(fh.fileno())
        if remove:
            os.unlink(path)
    except (OSError, ValueError) as e:
        sys.stderr.write(f"shred: {e}\n")
        rc = 1
sys.exit(rc)
PYEOF
    }
    export -f shred
fi

# -----------------------------------------------------
#  timeout → perl alarm (perl موجود دوماً على macOS/MSYS) أو حلقة bash
#  يدعم النمط المستخدم في المشروع: timeout <ثوانٍ> <cmd...>
# -----------------------------------------------------
if ! command -v timeout >/dev/null 2>&1; then
    if command -v perl >/dev/null 2>&1; then
        timeout() {
            local secs="$1"; shift
            perl -e '
                my $secs = shift;
                $secs = int($secs) || 0;          # "" / غير رقمي → 0
                $SIG{ALRM} = sub { exit 124 };     # 124 = رمز timeout القياسي
                alarm($secs) if $secs > 0;
                exec @ARGV or exit 127;            # exec يستبدل الصورة — المؤقت ينقلب SIGALRM للعملية الجديدة
            ' -- "$secs" "$@"
        }
        export -f timeout
    else
        timeout() {
            local secs="${1:-5}"; shift
            "$@" &
            local cmd_pid=$!
            local waited=0
            while kill -0 "$cmd_pid" 2>/dev/null && [ "$waited" -lt "$secs" ]; do
                sleep 1
                waited=$((waited + 1))
            done
            if ! kill -0 "$cmd_pid" 2>/dev/null; then
                wait "$cmd_pid" 2>/dev/null
                return $?
            fi
            kill "$cmd_pid" 2>/dev/null
            return 124
        }
        export -f timeout
    fi
fi

# -----------------------------------------------------
#  sed -i على macOS (BSD sed يتطلب فاصلة فارغة: sed -i '' ;)
#  نكشف BSD sed بعدم دعم --version ونُعيد فقط كتابة الأعلام -i/-i.bak
# -----------------------------------------------------
if ! command sed --version >/dev/null 2>&1; then
    sed() {
        case "${1:-}" in
            -i)
                shift
                local -a _sed_rest=("$@")
                command sed -i '' "${_sed_rest[@]}"
                return $?
                ;;
            -i.*)
                local _sed_suffix="${1#-i}"
                shift
                local -a _sed_rest=("$@")
                command sed -i "$_sed_suffix" "${_sed_rest[@]}"
                return $?
                ;;
            *)
                command sed "$@"
                return $?
                ;;
        esac
    }
    export -f sed
fi

# -----------------------------------------------------
#  stat -c على macOS (BSD stat يستخدم -f). نترجم الأكواد GNU الشائعة فقط:
#  %a %A %s %n %N %b %B %f %u %U %g %G %Y %y %F %h %i %z %X
#  الطلبات من غير -c تُمرّر لـ BSD stat كما هي (تعمل عادي)
# -----------------------------------------------------
if ! command stat --version >/dev/null 2>&1; then
    stat() {
        if [ "${1:-}" != "-c" ] && [ "${1:-}" != "--format" ]; then
            command stat "$@"
            return $?
        fi
        [ $# -ge 2 ] || { echo "stat: usage: stat -c SYNTAX FILE..." >&2; return 1; }
        local fmt="$2"
        shift 2
        if ! _raqib_py >/dev/null 2>&1; then
            command stat "$@"
            return $?
        fi
        $(_raqib_py) - "$fmt" "$@" <<'PYEOF'
import sys, os, time
import stat as st

fmt = sys.argv[1]
paths = sys.argv[2:]
rc = 0

def perms_octal(m):
    return format(st.S_IMODE(m), "04o")

def perms_text(p, m):
    bits = ""
    tr = "rwxrwxrwx"
    for i in range(9):
        bits += tr[i] if m & (1 << (8 - i)) else "-"
    if os.path.islink(p):
        kind = "l"
    elif st.S_ISDIR(m):
        kind = "d"
    elif st.S_ISREG(m):
        kind = "-"
    elif st.S_ISFIFO(m):
        kind = "p"
    elif st.S_ISSOCK(m):
        kind = "s"
    elif st.S_ISCHR(m):
        kind = "c"
    elif st.S_ISBLK(m):
        kind = "b"
    else:
        kind = "?"
    return kind + bits

def type_name(m):
    if st.S_ISREG(m):   return "regular file"
    if st.S_ISDIR(m):   return "directory"
    if st.S_ISLNK(m):   return "symbolic link"
    if st.S_ISFIFO(m):  return "fifo"
    if st.S_ISSOCK(m):  return "socket"
    if st.S_ISCHR(m):   return "character device"
    if st.S_ISBLK(m):   return "block device"
    return "unknown"

def quoted_name(p, m):
    if st.S_ISLNK(m):
        try:
            target = os.readlink(p)
            return "'%s' -> '%s'" % (p, target)
        except OSError:
            pass
    return "'%s'" % p

def user_name(uid_num):
    try:
        import pwd
        return pwd.getpwuid(uid_num).pw_name
    except Exception:
        return str(uid_num)

def group_name(gid_num):
    try:
        import grp
        return grp.getgrgid(gid_num).gr_name
    except Exception:
        return str(gid_num)

def render(p, s):
    m = s.st_mode
    table = {
        "a": lambda: perms_octal(m),
        "A": lambda: perms_text(p, m),
        "s": lambda: str(s.st_size),
        "n": lambda: p,
        "N": lambda: quoted_name(p, m),
        "b": lambda: str(s.st_blocks),
        "B": lambda: "512",
        "f": lambda: format(s.st_mode & 0o101777, "04x"),
        "u": lambda: str(s.st_uid),
        "U": lambda: user_name(s.st_uid),
        "g": lambda: str(s.st_gid),
        "G": lambda: group_name(s.st_gid),
        "Y": lambda: str(int(s.st_mtime)),
        "y": lambda: time.strftime("%Y-%m-%d %H:%M:%S.000000000 %z", time.localtime(s.st_mtime)),
        "z": lambda: str(int(s.st_ctime)),
        "X": lambda: str(int(s.st_atime)),
        "F": lambda: type_name(m),
        "h": lambda: str(s.st_nlink),
        "i": lambda: str(s.st_ino),
    }
    out = []
    i = 0
    while i < len(fmt):
        ch = fmt[i]
        if ch == "%" and (i + 1) < len(fmt):
            code = fmt[i + 1]
            i += 2
            if code == "%":
                out.append("%")
                continue
            fn = table.get(code)
            if fn is None:
                sys.stderr.write("stat: unsupported format code %%%s (RAQIB portable shim)\n" % code)
                globals()["rc"] = 1
                out.append("%" + code)
            else:
                out.append(fn())
        else:
            out.append(ch)
            i += 1
    return "".join(out)

for p in paths:
    try:
        s = os.lstat(p)
    except OSError as e:
        sys.stderr.write("stat: cannot statx '%s': %s\n" % (p, e))
        rc = 1
        continue
    print(render(p, s))
sys.exit(rc)
PYEOF
    }
    export -f stat
fi

# -----------------------------------------------------
#  ss → shim لنتائج مترابطة 100% مع ترتيب أعمدة `ss` الحقيقي:
#      State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
#  الأنماط المدعومة (كل ما يستخدمه المشروع):
#     ss -tulnp · ss -tuln · ss -tnp · ss -tunap
#     ss -tn state established · ss -tn state syn-recv
#     ss -tunap state established
#  المصدر على ويندوز: Get-NetTCPConnection + Get-NetUDPEndpoint (PID + اسم العملية)
#  المصدر على macOS : lsof -nP -iTCP/-iUDP
# -----------------------------------------------------
if ! command -v ss >/dev/null 2>&1; then

    # تجميع سطر users:(...) بالشكل المتوافق مع ss الأصلي

    ss() {
        # ---------- تفكيك الأعلام ----------
        local want_tcp=0 want_udp=0 want_listen=0 want_all=0 want_procs=0
        local state_filter="" state_next=0
        local arg c i chars len
        for arg in "$@"; do
            case "$arg" in
                -h|--help)
                    echo "Usage: ss [flags] [state <name>]  (RAQIB portable shim)"
                    return 0 ;;
                -V|--version)
                    echo "ss (RAQIB portable shim v1)"; return 0 ;;
                state)
                    state_next=1 ;;
                established|syn-recv|listen|accepted|connected|all|time-wait|close-wait|fin-wait-1|fin-wait-2)
                    if [ "$state_next" -eq 1 ]; then
                        state_filter="$arg"
                        state_next=0
                    else
                        state_filter="$arg"
                    fi
                    ;;
                -) ;; # stdin في ss الحقيقي — غير مدعوم هنا
                --) ;;
                -*)
                    chars="${arg#-}"
                    len="${#chars}"
                    for (( i=0; i<len; i++ )); do
                        c="${chars:i:1}"
                        case "$c" in
                            t) want_tcp=1 ;;
                            u) want_udp=1 ;;
                            l) want_listen=1 ;;
                            a) want_all=1 ;;
                            p) want_procs=1 ;;
                            n) : ;;
                            *) : ;; # تجاهل الأعلام الأخرى بأمان
                        esac
                    done
                    ;;
                *) state_filter="$arg" ; state_next=0 ;;
            esac
        done
        [ $want_tcp -eq 0 ] && [ $want_udp -eq 0 ] && want_tcp=1
        [ $want_all -eq 1 ] && want_listen=1
        if [ -z "$state_filter" ]; then
            if [ $want_listen -eq 1 ]; then
                state_filter="listen"
            else
                state_filter="connected"
            fi
        fi

        echo "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process"

        # -------------------- المصدر: Windows عبر PowerShell --------------------
        if [ "$(raqib_is_windows && echo 1 || echo 0)" = "1" ] && raqib_has_windows_bridge; then
            export _RAQIB_SS_TCP="$want_tcp" _RAQIB_SS_UDP="$want_udp"
            raqib_win_ps '
                $procs = @{}
                try { Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName } } catch {}
                if ($env:_RAQIB_SS_TCP -eq "1") {
                    try {
                        Get-NetTCPConnection | ForEach-Object {
                            $st = $_.State
                            if ($st -eq "Listen") { $st = "LISTEN" }
                            elseif ($st -eq "Established") { $st = "ESTAB" }
                            elseif ($st -eq "SynReceived") { $st = "SYN-RECV" }
                            elseif ($st -eq "TimeWait") { $st = "TIME-WAIT" }
                            elseif ($st -eq "CloseWait") { $st = "CLOSE-WAIT" }
                            elseif ($st -eq "FinWait1") { $st = "FIN-WAIT1" }
                            elseif ($st -eq "FinWait2") { $st = "FIN-WAIT2" }
                            $pname = $procs[[int]$_.OwningProcess]
                            if (-not $pname) { $pname = "" }
                            "{0}|0|0|{1}:{2}|{3}:{4}|{5}|{6}" -f $st, $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $_.OwningProcess, $pname
                        }
                    } catch {}
                }
                if ($env:_RAQIB_SS_UDP -eq "1") {
                    try {
                        Get-NetUDPEndpoint | ForEach-Object {
                            $pname = $procs[[int]$_.OwningProcess]
                            if (-not $pname) { $pname = "" }
                            "UNCONN|0|0|{0}:{1}|*:*|{2}|{3}" -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess, $pname
                        }
                    } catch {}
                }
            ' | awk -F '|' -v FILTER="$state_filter" -v PFLAG="$want_procs" -v WANTU="$want_udp" '
                {
                    st    = $1
                    local = $4
                    peer  = $5
                    pid   = $6
                    pname = $7
                    # فلتر الحالة — بنفس دلالات ss الحقيقي:
                    #   listen    → LISTEN (TCP) + UNCONN (UDP إذا طُلب -u)
                    #           connected → TCP غير مستمع + UDP إذا طُلب -u
                    if (FILTER == "listen") {
                        if (st == "LISTEN") { }
                        else if (st == "UNCONN") { if (WANTU != 1) next }
                        else next
                    } else if (FILTER == "connected") {
                        if (st == "LISTEN") next
                        if (st == "UNCONN") { if (WANTU != 1) next }
                    } else if (FILTER == "established") {
                        if (st != "ESTAB") next
                    } else if (FILTER == "syn-recv") {
                        if (st != "SYN-RECV") next
                    } else if (FILTER == "all") {
                        # بلا فلترة
                    } else {
                        low = tolower(st); fl = tolower(FILTER)
                        if (index(low, fl) == 0) next
                    }
                    proc_col = ""
                    if (PFLAG == 1 && pname != "") {
                        gsub(/[^A-Za-z0-9_.-]/, "", pname)
                        proc_col = sprintf("users:((\"%s\",pid=%s,fd=1))", pname, pid)
                    }
                    printf "%-10s %-7s %-7s %-24s %-24s %s\n", st, "0", "0", local, peer, proc_col
                }
            ' 2>/dev/null
            unset _RAQIB_SS_TCP _RAQIB_SS_UDP
            return $?
        fi

        # -------------------- المصدر: macOS عبر lsof --------------------
        if [ "$(raqib_is_macos && echo 1 || echo 0)" = "1" ] && command -v lsof >/dev/null 2>&1; then
            local lsof_args=()
            [ $want_tcp -eq 1 ] && lsof_args+=( -iTCP )
            [ $want_udp -eq 1 ] && lsof_args+=( -iUDP )
            if [ ${#lsof_args[@]} -eq 0 ]; then
                return 0
            fi
            command lsof -nP "${lsof_args[@]}" 2>/dev/null | awk -v FILTER="$state_filter" -v PFLAG="$want_procs" -v WANTU="$want_udp" '
                NR == 1 { next }
                $1 == "COMMAND" { next }
                {
                    node = $8
                    pid  = $2
                    cmdn = $1
                    name_line = ""
                    arrow_idx = 0
                    for (i = 9; i <= NF; i++) {
                        if (index($i, "->") > 0) { arrow_idx = i; name_line = $i }
                    }
                    state_raw = ""
                    local_ = ""
                    peer_  = "*:*"
                    st = ""
                    if (node == "TCP") {
                        if (arrow_idx > 0) {
                            split(name_line, parts, "->")
                            local_ = parts[1]; peer_ = parts[2]
                            state_raw = $(arrow_idx + 1)
                            gsub(/[()]/, "", state_raw)
                            if (index(state_raw, "ESTABLISHED"))       st = "ESTAB"
                            else if (index(state_raw, "LISTEN"))        st = "LISTEN"
                            else if (index(state_raw, "SYN_RCVD") || index(state_raw, "SYN_RECEIVED")) st = "SYN-RECV"
                            else if (index(state_raw, "TIME_WAIT"))     st = "TIME-WAIT"
                            else if (index(state_raw, "CLOSE_WAIT"))    st = "CLOSE-WAIT"
                            else if (index(state_raw, "FIN_WAIT_1") || index(state_raw, "FIN_WAIT1")) st = "FIN-WAIT1"
                            else if (index(state_raw, "FIN_WAIT_2") || index(state_raw, "FIN_WAIT2")) st = "FIN-WAIT2"
                            else st = state_raw
                        } else {
                            # استماع: NAME بدون سهم — مثل *:22
                            for (i = 9; i <= NF; i++) {
                                if ($i ~ /:/) { name_line = $i }
                            }
                            local_ = name_line
                            peer_  = "0.0.0.0:*"
                            st     = "LISTEN"
                        }
                    } else {
                        # UDP: بلا حالة — نعاملها UNCONN
                        for (i = 9; i <= NF; i++) {
                            if ($i ~ /:/) { name_line = $i }
                        }
                        if (name_line == "") next
                        local_ = name_line
                        peer_  = "*:*"
                        st     = "UNCONN"
                    }
                    # فلتر الحالة — بنفس دلالات ss الحقيقي
                    if (FILTER == "listen") {
                        if (st == "LISTEN") { }
                        else if (st == "UNCONN") { if (WANTU != 1) next }
                        else next
                    } else if (FILTER == "connected") {
                        if (st == "LISTEN") next
                        if (st == "UNCONN") { if (WANTU != 1) next }
                    } else if (FILTER == "established") {
                        if (st != "ESTAB") next
                    } else if (FILTER == "syn-recv") {
                        if (st != "SYN-RECV") next
                    } else if (FILTER == "all") {
                        # بلا فلترة
                    } else {
                        low = tolower(st); fl = tolower(FILTER)
                        if (index(low, fl) == 0) next
                    }
                    proc_col = ""
                    if (PFLAG == 1 && pid != "") {
                        gsub(/[^A-Za-z0-9_.-]/, "", cmdn)
                        proc_col = sprintf("users:((\"%s\",pid=%s,fd=1))", cmdn, pid)
                    }
                    printf "%-10s %-7s %-7s %-24s %-24s %s\n", st, "0", "0", local_, peer_, proc_col
                }
            ' 2>/dev/null
            return $?
        fi

        # دون مصدر — رسالة تشخيصية على stderr (الأنابيب تستمر بسلامة)
        echo "ss: RAQIB portable shim: no socket data source for this platform (RAQIB_OS=${RAQIB_OS:-unknown})" >&2
        return 1
    }
        # الضبط النهائي للدالة ss عبر بيئة المشروع
    export -f ss
fi

# حفظ المتغيّرات النهائية
export RAQIB_OS
