#!/bin/bash
# =====================================================
#  دوال توافق الأنظمة (Cross-system portability helpers)
#  تعالج فروقات GNU coreutils مقابل BSD/macOS، ومدراء
#  الحزم المختلفة (apt/dnf/yum/pacman/zypper/apk)، ودعم
#  grep -P (PCRE) لو غير متوفر بالنظام.
# =====================================================

# raqib_hash <md5|sha1|sha256> <file> -> يطبع الهاش، أو يفشل (exit != 0) لو ما فيه أداة مناسبة
raqib_hash() {
    local algo="$1" file="$2"
    case "$algo" in
        md5)
            if command -v md5sum >/dev/null 2>&1; then md5sum -- "$file" 2>/dev/null | awk '{print $1}'
            elif command -v md5 >/dev/null 2>&1; then md5 -q -- "$file" 2>/dev/null
            else return 1; fi ;;
        sha1)
            if command -v sha1sum >/dev/null 2>&1; then sha1sum -- "$file" 2>/dev/null | awk '{print $1}'
            elif command -v shasum >/dev/null 2>&1; then shasum -a 1 -- "$file" 2>/dev/null | awk '{print $1}'
            else return 1; fi ;;
        sha256)
            if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$file" 2>/dev/null | awk '{print $1}'
            elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- "$file" 2>/dev/null | awk '{print $1}'
            else return 1; fi ;;
        *) return 1 ;;
    esac
}
export -f raqib_hash

# raqib_stat_perm <file> -> صلاحيات الملف بصيغة octal (زي 644)، GNU stat أو BSD/macOS stat
raqib_stat_perm() {
    local file="$1"
    if stat -c '%a' -- "$file" >/dev/null 2>&1; then
        stat -c '%a' -- "$file" 2>/dev/null
    elif stat -f '%Lp' -- "$file" >/dev/null 2>&1; then
        stat -f '%Lp' -- "$file" 2>/dev/null
    fi
}
export -f raqib_stat_perm

# raqib_stat_size <file> -> حجم الملف بالبايت، GNU stat أو BSD/macOS stat أو wc كحل أخير
raqib_stat_size() {
    local file="$1"
    if stat -c '%s' -- "$file" >/dev/null 2>&1; then
        stat -c '%s' -- "$file" 2>/dev/null
    elif stat -f '%z' -- "$file" >/dev/null 2>&1; then
        stat -f '%z' -- "$file" 2>/dev/null
    else
        wc -c < "$file" 2>/dev/null | tr -d ' '
    fi
}
export -f raqib_stat_size

# raqib_date_epoch "<date string>" -> ثواني Unix؛ يدعم GNU date (-d) وBSD/macOS date (-j -f)
# بأشهر صيغ تاريخ انتهاء شهادات SSL (openssl x509 -enddate).
raqib_date_epoch() {
    local ds="$1" out
    out=$(date -d "$ds" +%s 2>/dev/null) && { echo "$out"; return 0; }
    out=$(date -j -f "%b %e %T %Y %Z" "$ds" +%s 2>/dev/null) && { echo "$out"; return 0; }
    out=$(date -j -f "%b %d %T %Y %Z" "$ds" +%s 2>/dev/null) && { echo "$out"; return 0; }
    return 1
}
export -f raqib_date_epoch

# raqib_pkg_manager -> يطبع أول مدير حزم مكتشف بالنظام (apt/dnf/yum/pacman/zypper/apk)
raqib_pkg_manager() {
    local m
    for m in apt dnf yum pacman zypper apk; do
        command -v "$m" >/dev/null 2>&1 && { echo "$m"; return 0; }
    done
    return 1
}
export -f raqib_pkg_manager

# raqib_owns_file <file> -> صفر (نجاح) لو الملف تابع لحزمة مثبتة، حسب مدير الحزم المكتشف
raqib_owns_file() {
    local f="$1" mgr
    mgr=$(raqib_pkg_manager)
    case "$mgr" in
        apt)    command -v dpkg   >/dev/null 2>&1 && dpkg -S -- "$f" >/dev/null 2>&1 ;;
        dnf|yum|zypper) command -v rpm >/dev/null 2>&1 && rpm -qf -- "$f" >/dev/null 2>&1 ;;
        pacman) command -v pacman >/dev/null 2>&1 && pacman -Qo -- "$f" >/dev/null 2>&1 ;;
        apk)    command -v apk    >/dev/null 2>&1 && apk info -W -- "$f" >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}
export -f raqib_owns_file

# raqib_pcre_ok -> صفر لو grep -P (PCRE) مدعوم فعلياً بهذا النظام (BusyBox/BSD grep لا يدعمونه عادة)
raqib_pcre_ok() {
    if [ -z "${_RAQIB_PCRE_CHECKED:-}" ]; then
        if printf 'x' | grep -P 'x' >/dev/null 2>&1; then
            _RAQIB_PCRE_OK=1
        else
            _RAQIB_PCRE_OK=0
        fi
        _RAQIB_PCRE_CHECKED=1
        export _RAQIB_PCRE_OK _RAQIB_PCRE_CHECKED
    fi
    [ "$_RAQIB_PCRE_OK" = "1" ]
}
export -f raqib_pcre_ok

# raqib_default_iface -> يحاول إيجاد واجهة الشبكة الافتراضية عبر ip، وإلا route، وإلا ifconfig
raqib_default_iface() {
    local iface
    if command -v ip >/dev/null 2>&1; then
        iface=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
    fi
    if [ -z "$iface" ] && command -v route >/dev/null 2>&1; then
        iface=$(route -n 2>/dev/null | awk '$1=="0.0.0.0"{print $8; exit}')
    fi
    if [ -z "$iface" ] && command -v ifconfig >/dev/null 2>&1; then
        iface=$(ifconfig 2>/dev/null | awk '/^[a-zA-Z0-9]+:?/{iface=$1} /inet /{print iface; exit}' | tr -d ':')
    fi
    echo "$iface"
}
export -f raqib_default_iface

# raqib_realpath <path> -> مسار مطلق بدون روابط رمزية؛ realpath أو readlink -f
# أو perl/python كحل أخير (بعض أنظمة macOS/BSD ما فيها realpath افتراضياً)
raqib_realpath() {
    local p="$1" out
    if out=$(realpath -- "$p" 2>/dev/null) && [ -n "$out" ]; then echo "$out"; return 0; fi
    if out=$(readlink -f -- "$p" 2>/dev/null) && [ -n "$out" ]; then echo "$out"; return 0; fi
    if command -v perl >/dev/null 2>&1; then
        out=$(perl -MCwd=abs_path -e 'print abs_path(shift)' "$p" 2>/dev/null) && [ -n "$out" ] && { echo "$out"; return 0; }
    fi
    if command -v python3 >/dev/null 2>&1; then
        out=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$p" 2>/dev/null) && [ -n "$out" ] && { echo "$out"; return 0; }
    fi
    return 1
}
export -f raqib_realpath

show_tool_list() {
    local title="$1"; shift
    echo ""
    echo -e "${BOLD}${title}${NC}"
    local i=1
    for entry in "$@"; do
        echo -e "  ${CYAN}${i})${NC} ${entry}"
        ((i++))
    done
    echo -e "  ${RED}0)${NC} $(t back)"
}

run_tool() {
    local script="$1"
    echo ""
    if [ ! -x "$script" ]; then chmod +x "$script"; fi
    # Run in a subshell (not a fresh `bash` process) so that the t()/tf()
    # translation functions and their associative-array data (which cannot
    # be exported to a brand-new bash process) remain available to the tool.
    # `exit` inside a ( ... ) subshell only ends the subshell, not the menu.
    ( source "$script" )
}

# يبحث عن ملف auth log القياسي، وإذا ما لقاه يطلبه من المستخدم.
# النتيجة تُطبع بالمخرجات (stdout)؛ استخدمها بـ: LOGFILE=$(find_auth_log) || exit 1
find_auth_log() {
    local f
    for f in /var/log/auth.log /var/log/secure; do
        if [ -f "$f" ]; then
            echo "$f"
            return 0
        fi
    done
    read -rp "$(t c_prompt_auth_log)" f
    if [ -n "$f" ] && [ -f "$f" ]; then
        echo "$f"
        return 0
    fi
    echo -e "${RED}$(t c_file_not_found)${NC}" >&2
    return 1
}
export -f find_auth_log

# تحقق من صحة عنوان IPv4
is_valid_ip() {
    local ip="$1" octet
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        [ "$octet" -le 255 ] || return 1
    done
    return 0
}
export -f is_valid_ip

# تحقق من صحة رقم منفذ (1-65535)
is_valid_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
export -f is_valid_port

# يعرض على المستخدم خيار حفظ نص التقرير بملف
# يولّد أيضاً معرّف تقرير فريد (رقم تسلسلي + بصمة) ويسجّل العملية بسجل آخر 10 فحوصات
# الاستخدام: save_report "$report_text" "اسم_افتراضي.txt" "عنوان الأداة"
save_report() {
    local content="$1"
    local default_name="${2:-raqib_report_$(date +%Y%m%d_%H%M%S).txt}"
    local tool_title="${3:--}"
    echo ""
    read -rp "$(t c_save_report_prompt)" ans
    if [ "$ans" = "y" ]; then
        read -rp "$(tf c_filename_prompt "$default_name")" fname
        fname=${fname:-$default_name}
        printf '%s\n' "$content" > "$fname"
        echo -e "${GREEN}$(tf c_report_saved "$fname")${NC}"

        local report_id
        report_id=$(_raqib_new_report_id "$fname")
        echo -e "${CYAN}$(tf c_report_id_line "$report_id")${NC}"
        _raqib_log_history "$report_id" "$tool_title" "$fname"

        read -rp "$(t c_encrypt_prompt)" enc_ans
        if [ "$enc_ans" = "y" ]; then
            raqib_encrypt_file "$fname"
        fi
    fi
}
export -f save_report

# =====================================================
#  تشفير/فك تشفير الملفات — AES-256-GCM (مصادَق عليه)
#  KDF: Argon2id (افتراضي، مقاوم لهجمات GPU/ASIC) مع رجوع تلقائي لـ Scrypt
#  إذا كانت مكتبة بايثون المثبتة لا تدعم Argon2id.
#  File encryption/decryption — AES-256-GCM (AEAD)
#  KDF: Argon2id by default (memory-hard, GPU/ASIC resistant), with automatic
#  fallback to Scrypt if the installed "cryptography" version lacks Argon2id.
#  الصيغة (RQBv2) موصوفة ذاتياً: تخزّن معرّف الـKDF وبارامتراته داخل الملف
#  نفسه، فيبقى فكّ ملفات RQBv1 القديمة (Scrypt الثابت) يعمل دائماً.
#  The (RQBv2) format is self-describing: it stores the KDF id and its cost
#  parameters inside the file itself, so old RQBv1 files (fixed Scrypt)
#  always remain decryptable.
# =====================================================

# يطبع تحذيراً إذا كانت كلمة المرور قصيرة/ضعيفة ويسأل عن المتابعة
# يرجع 0 للمتابعة، 1 للإلغاء
_raqib_check_pass_strength() {
    local pass="$1" len classes=0
    len=${#pass}
    [[ "$pass" =~ [a-z] ]] && ((classes++))
    [[ "$pass" =~ [A-Z] ]] && ((classes++))
    [[ "$pass" =~ [0-9] ]] && ((classes++))
    [[ "$pass" =~ [^a-zA-Z0-9] ]] && ((classes++))
    if [ "$len" -lt 12 ] || [ "$classes" -lt 3 ]; then
        echo -e "${YELLOW}$(t c_encrypt_weak_pass_warn)${NC}"
        local cont
        read -rp "$(t c_encrypt_weak_pass_continue)" cont
        [ "$cont" = "y" ] || return 1
    fi
    return 0
}
export -f _raqib_check_pass_strength

# raqib_encrypt_file <path> — يشفّر الملف مكانه وينتج <path>.enc، ثم يحذف الأصل بأمان
raqib_encrypt_file() {
    local target="$1"
    [ -f "$target" ] || { echo -e "${RED}$(t c_file_not_found)${NC}"; return 1; }

    if ! python3 -c "import cryptography" >/dev/null 2>&1; then
        echo -e "${RED}$(t c_encrypt_lib_missing)${NC}"
        return 1
    fi

    local pass1 pass2
    read -rsp "$(t c_encrypt_pass_prompt)" pass1; echo ""
    read -rsp "$(t c_encrypt_pass_confirm)" pass2; echo ""
    if [ -z "$pass1" ]; then
        echo -e "${RED}$(t c_encrypt_pass_empty)${NC}"; return 1
    fi
    if [ "$pass1" != "$pass2" ]; then
        echo -e "${RED}$(t c_encrypt_pass_mismatch)${NC}"; return 1
    fi
    if ! _raqib_check_pass_strength "$pass1"; then
        pass1=""; pass2=""
        echo -e "${YELLOW}$(t c_encrypt_cancelled)${NC}"
        return 1
    fi

    local out="${target}.enc" pyscript algo_used rc
    pyscript=$(mktemp)
    cat > "$pyscript" << 'PYEOF'
import sys, os, secrets, struct

MAGIC = b"RQBv2"
AAD = b"RAQIB-REPORT-v2"

in_path, out_path = sys.argv[1], sys.argv[2]
# كلمة المرور تُقرأ من stdin (سطر واحد) وليس من متغير بيئة، لتفادي ظهورها
# في /proc/<pid>/environ أثناء عمل العملية الفرعية.
password = sys.stdin.buffer.readline().rstrip(b"\n")

with open(in_path, "rb") as f:
    data = f.read()

salt = secrets.token_bytes(16)
nonce = secrets.token_bytes(12)

try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    time_cost, mem_mib, parallelism = 3, 64, 4  # 64 MiB, 3 passes, 4 lanes
    key = Argon2id(salt=salt, length=32, iterations=time_cost,
                    lanes=parallelism, memory_cost=mem_mib * 1024).derive(password)
    kdf_id = 2
    # mem_mib as 1 byte (MiB, max 255) instead of KiB, so it fits the field
    params = struct.pack(">BBB", time_cost, mem_mib, parallelism).ljust(8, b"\x00")
    print("argon2id", end="")
except ImportError:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    n_log2, r, p = 17, 8, 1  # n=2**17 (رفع أعلى من الإصدار السابق 2**15)
    key = Scrypt(salt=salt, length=32, n=2 ** n_log2, r=r, p=p).derive(password)
    kdf_id = 1
    params = struct.pack(">BBB", n_log2, r, p).ljust(8, b"\x00")
    print("scrypt", end="")

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
ct = AESGCM(key).encrypt(nonce, data, AAD)

with open(out_path, "wb") as f:
    f.write(MAGIC + bytes([kdf_id]) + params + salt + nonce + ct)
os.chmod(out_path, 0o600)
PYEOF
    algo_used=$(printf '%s\n' "$pass1" | python3 "$pyscript" "$target" "$out")
    rc=$?
    rm -f "$pyscript"

    if [ "$rc" -eq 0 ]; then
        pass1=""; pass2=""
        if command -v shred >/dev/null 2>&1; then
            shred -u -z -n 3 "$target" 2>/dev/null || rm -f "$target"
        else
            rm -f "$target"
        fi
        echo -e "${GREEN}$(tf c_encrypt_done "${algo_used:-scrypt}" "$out")${NC}"
        return 0
    else
        pass1=""; pass2=""
        echo -e "${RED}$(t c_encrypt_failed)${NC}"
        return 1
    fi
}
export -f raqib_encrypt_file

# raqib_decrypt_file <path.enc> <out_path> — يطلب كلمة المرور ويفك التشفير
# يدعم صيغتي RQBv1 (القديمة، Scrypt ثابت) و RQBv2 (موصوفة ذاتياً)
# يرجع 0 عند النجاح، 1 عند فشل المصادقة/كلمة مرور خاطئة/ملف تالف
raqib_decrypt_file() {
    local target="$1" out="$2"
    [ -f "$target" ] || { echo -e "${RED}$(t c_file_not_found)${NC}"; return 1; }

    if ! python3 -c "import cryptography" >/dev/null 2>&1; then
        echo -e "${RED}$(t c_encrypt_lib_missing)${NC}"
        return 1
    fi

    local pass pyscript rc
    read -rsp "$(t rd_pass_prompt)" pass; echo ""

    pyscript=$(mktemp)
    cat > "$pyscript" << 'PYEOF'
import sys, os, struct, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

in_path, out_path = sys.argv[1], sys.argv[2]
password = sys.stdin.buffer.readline().rstrip(b"\n")

with open(in_path, "rb") as f:
    blob = f.read()

try:
    if blob[:5] == b"RQBv1":
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
        key = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password)
        aad = b"RAQIB-REPORT-v1"
    elif blob[:5] == b"RQBv2":
        kdf_id = blob[5]
        params = blob[6:14]
        salt, nonce, ct = blob[14:30], blob[30:42], blob[42:]
        aad = b"RAQIB-REPORT-v2"
        if kdf_id == 2:
            from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
            time_cost, mem_mib, parallelism = struct.unpack(">BBB", params[:3])
            key = Argon2id(salt=salt, length=32, iterations=time_cost,
                            lanes=parallelism, memory_cost=mem_mib * 1024).derive(password)
        elif kdf_id == 1:
            from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
            n_log2, r, p = struct.unpack(">BBB", params[:3])
            key = Scrypt(salt=salt, length=32, n=2 ** n_log2, r=r, p=p).derive(password)
        else:
            sys.exit(1)
    else:
        sys.exit(1)

    pt = AESGCM(key).decrypt(nonce, ct, aad)
except (InvalidTag, ImportError, ValueError, IndexError):
    # تأخير بسيط ثابت لتقليل فائدة توقيت المحاولات الفاشلة في تخمين كلمة المرور
    time.sleep(0.3)
    sys.exit(1)

with open(out_path, "wb") as f:
    f.write(pt)
os.chmod(out_path, 0o600)
PYEOF
    printf '%s\n' "$pass" | python3 "$pyscript" "$target" "$out"
    rc=$?
    rm -f "$pyscript"
    if [ "$rc" -eq 0 ]; then
        pass=""
        return 0
    else
        pass=""
        return 1
    fi
}
export -f raqib_decrypt_file

# =====================================================
#  نظام تقييم الخطورة + الملخص التنفيذي
#  Severity scoring + Executive Summary
#  الاستخدام داخل أي أداة:
#    finding_reset                 # بداية الأداة
#    finding_add "high" "..."      # عند كل ملاحظة (critical|high|medium|low)
#    print_executive_summary "$(t xxx_title)"   # بنهاية الأداة
# =====================================================
declare -A RAQIB_SEV_COUNTS

finding_reset() {
    RAQIB_SEV_COUNTS=( [critical]=0 [high]=0 [medium]=0 [low]=0 )
}
export -f finding_reset

# finding_add <critical|high|medium|low>
finding_add() {
    local sev="${1,,}"
    case "$sev" in
        critical|high|medium|low) ;;
        *) sev="low" ;;
    esac
    RAQIB_SEV_COUNTS[$sev]=$(( ${RAQIB_SEV_COUNTS[$sev]:-0} + 1 ))
}
export -f finding_add

# يرجع مفتاح الخطورة الكلية (critical|high|medium|low) بناءً على RAQIB_SEV_COUNTS
_raqib_overall_key() {
    local crit="${RAQIB_SEV_COUNTS[critical]:-0}"
    local high="${RAQIB_SEV_COUNTS[high]:-0}"
    local med="${RAQIB_SEV_COUNTS[medium]:-0}"
    if   [ "$crit" -gt 0 ]; then echo critical
    elif [ "$high" -gt 0 ]; then echo high
    elif [ "$med"  -gt 0 ]; then echo medium
    else echo low
    fi
}
export -f _raqib_overall_key

# يطبع بادج ملوّن حسب مفتاح خطورة (critical|high|medium|low) — تدرج 4 مستويات
_raqib_sev_badge() {
    case "${1,,}" in
        critical) echo -e "${CRIMSON}$(t c_sev_critical)${NC}" ;;
        high)     echo -e "${ORANGE}$(t c_sev_high)${NC}" ;;
        medium)   echo -e "${YELLOW}$(t c_sev_medium)${NC}" ;;
        *)        echo -e "${GREEN}$(t c_sev_low)${NC}" ;;
    esac
}
export -f _raqib_sev_badge

# يطبع ملخصاً تنفيذياً ملوّناً + تقييم عام بناءً على أعلى مستوى خطورة رُصد
# الاستخدام: print_executive_summary "عنوان الأداة"
print_executive_summary() {
    local title="$1"
    local crit="${RAQIB_SEV_COUNTS[critical]:-0}"
    local high="${RAQIB_SEV_COUNTS[high]:-0}"
    local med="${RAQIB_SEV_COUNTS[medium]:-0}"
    local low="${RAQIB_SEV_COUNTS[low]:-0}"
    local overall_key overall overall_color
    overall_key=$(_raqib_overall_key)
    case "$overall_key" in
        critical) overall_color="$CRIMSON" ;;
        high)     overall_color="$ORANGE" ;;
        medium)   overall_color="$YELLOW" ;;
        *)        overall_color="$GREEN" ;;
    esac
    overall="$(t "c_sev_${overall_key}")"

    echo ""
    echo -e "${BOLD}────────────────────────────────────────${NC}"
    echo -e "${BOLD}📊 $(t c_summary_title) — ${title}${NC}"
    echo -e "${BOLD}────────────────────────────────────────${NC}"
    if [ "$crit" -eq 0 ] && [ "$high" -eq 0 ] && [ "$med" -eq 0 ] && [ "$low" -eq 0 ]; then
        echo -e "  ${GREEN}$(t c_no_findings)${NC}"
    else
        echo -e "  ${CRIMSON}●${NC} $(t c_sev_critical): ${crit}   ${ORANGE}●${NC} $(t c_sev_high): ${high}   ${YELLOW}●${NC} $(t c_sev_medium): ${med}   ${GREEN}●${NC} $(t c_sev_low): ${low}"
    fi
    echo -e "  ${BOLD}$(t c_overall_label):${NC} ${overall_color}${overall}${NC}"
    echo -e "${BOLD}────────────────────────────────────────${NC}"
}
export -f print_executive_summary

# =====================================================
#  قرنطنة/حذف آمن مشترك — يُستخدم من أدوات malware المختلفة
#  Shared quarantine / secure-delete helpers used by malware tools
# =====================================================
RAQIB_QUARANTINE_DIR="$HOME/.raqib_quarantine"

# raqib_quarantine_file <path> -> ينقل الملف لمجلد الحجر الصحي (700/000)
raqib_quarantine_file() {
    local src="$1"
    mkdir -p "$RAQIB_QUARANTINE_DIR"
    chmod 700 "$RAQIB_QUARANTINE_DIR"
    local dest="$RAQIB_QUARANTINE_DIR/$(basename -- "$src").$(date +%s).quarantined"
    if mv -- "$src" "$dest" 2>/dev/null; then
        chmod 000 "$dest"
        echo -e "${GREEN}$(tf qe_quarantined "$src" "$dest")${NC}"
        return 0
    else
        echo -e "${RED}$(tf qe_quarantine_failed "$src")${NC}"
        return 1
    fi
}
export -f raqib_quarantine_file

# raqib_secure_delete_file <path> -> حذف نهائي آمن (shred إن توفر)
raqib_secure_delete_file() {
    local src="$1"
    if command -v shred >/dev/null 2>&1; then
        shred -u -z -n 3 -- "$src" 2>/dev/null || rm -f -- "$src"
    else
        rm -f -- "$src"
    fi
    echo -e "${GREEN}$(tf qe_deleted "$src")${NC}"
}
export -f raqib_secure_delete_file

# =====================================================
#  معرّف التقرير + سجل آخر 10 فحوصات
#  Report ID + Recent-Scans history log
# =====================================================

# يولّد معرّف فريد بصيغة RAQIB-0007-a1b2c3d4 (تسلسل + بصمة sha256 مختصرة)
_raqib_new_report_id() {
    local fname="$1"
    local seq_file="$SCRIPT_DIR/.raqib_report_seq"
    local seq=1
    if [ -f "$seq_file" ]; then
        seq=$(( $(cat "$seq_file" 2>/dev/null) + 1 ))
    fi
    echo "$seq" > "$seq_file" 2>/dev/null
    local hash="--------"
    if command -v sha256sum >/dev/null 2>&1; then
        hash=$(sha256sum "$fname" 2>/dev/null | cut -c1-8)
    elif command -v shasum >/dev/null 2>&1; then
        hash=$(shasum -a 256 "$fname" 2>/dev/null | cut -c1-8)
    fi
    [ -z "$hash" ] && hash="--------"
    printf "RAQIB-%04d-%s" "$seq" "$hash"
}
export -f _raqib_new_report_id

# يسجّل عملية فحص بملف السجل ويحتفظ بآخر 10 عمليات فقط
_raqib_log_history() {
    local report_id="$1" tool_title="$2" fname="$3"
    local sev_key
    sev_key=$(_raqib_overall_key)
    local hist_file="$SCRIPT_DIR/.raqib_history"
    printf '%s|%s|%s|%s|%s\n' "$report_id" "$(date '+%Y-%m-%d %H:%M')" "$tool_title" "$sev_key" "$fname" >> "$hist_file" 2>/dev/null
    if [ -f "$hist_file" ]; then
        tail -n 10 "$hist_file" > "${hist_file}.tmp" 2>/dev/null && mv "${hist_file}.tmp" "$hist_file"
    fi
}
export -f _raqib_log_history

# يعرض آخر 10 عمليات فحص محفوظة بالسجل
view_scan_history() {
    show_banner
    echo -e "${BOLD}$(t history_title)${NC}"
    echo ""
    local hist_file="$SCRIPT_DIR/.raqib_history"
    if [ ! -s "$hist_file" ]; then
        echo -e "${YELLOW}$(t history_empty)${NC}"
    else
        local id ts title sev fname badge
        while IFS='|' read -r id ts title sev fname; do
            [ -z "$id" ] && continue
            badge="$(_raqib_sev_badge "$sev")"
            echo -e "  ${CYAN}${id}${NC}  ${ts}  ${BOLD}${title}${NC}  ${badge}  (${fname})"
        done < <(tac "$hist_file" 2>/dev/null || tail -r "$hist_file" 2>/dev/null || cat "$hist_file")
    fi
    pause
}
export -f view_scan_history

# =====================================================
#  شريط تقدّم + مؤشر تحميل متحرك (Progress bar + Spinner)
# =====================================================

# يرسم شريط تقدّم على نفس السطر (يُستدعى داخل حلقة for)
# الاستخدام: draw_progress_bar <الحالي> <الإجمالي> "<تسمية>"
draw_progress_bar() {
    local current="$1" total="$2" label="$3"
    [ "$total" -le 0 ] && return
    local width=30
    local filled=$(( current * width / total ))
    [ "$filled" -gt "$width" ] && filled=$width
    local empty=$(( width - filled ))
    local pct=$(( current * 100 / total ))
    printf "\r\033[K${CYAN}%s${NC} [" "$label"
    [ "$filled" -gt 0 ] && printf "%0.s█" $(seq 1 "$filled")
    [ "$empty" -gt 0 ] && printf "%0.s░" $(seq 1 "$empty")
    printf "] ${BOLD}%3d%%${NC} (%d/%d)" "$pct" "$current" "$total"
}
export -f draw_progress_bar

# ينهي سطر شريط التقدّم وينتقل لسطر جديد
finish_progress_bar() {
    printf "\n"
}
export -f finish_progress_bar

# يشغّل أمراً بالخلفية ويعرض نقاطاً متحركة "..." أثناء انتظاره
# مخرجات الأمر (stdout) تبقى قابلة للالتقاط عبر $(...) كالمعتاد
# الاستخدام: result=$(run_with_spinner "الرسالة" -- command args...)
run_with_spinner() {
    local msg="$1"; shift
    [ "$1" = "--" ] && shift
    "$@" &
    local cmd_pid=$!
    local -a frames=("." ".." "...")
    local i=0
    while kill -0 "$cmd_pid" 2>/dev/null; do
        printf "\r\033[K${YELLOW}%s%s${NC}" "$msg" "${frames[$((i % 3))]}" >&2
        sleep 0.3
        ((i++))
    done
    wait "$cmd_pid"
    local rc=$?
    printf "\r\033[K" >&2
    return $rc
}
export -f run_with_spinner
