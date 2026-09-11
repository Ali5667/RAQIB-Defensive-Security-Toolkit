#!/bin/bash
# raqib_watchdog.sh
# دورة فحص خفيفة واحدة، مصممة تنشغّل بشكل متكرر عبر systemd timer (أو cron)
# — مو حلقة "while true" خالدة، لأن الاعتماد على مدير نظام حقيقي (systemd)
# أوثق: يعيد تشغيل الدورة تلقائياً لو طاحت، ويربط عملها بحياة النظام نفسه
# (يبدأ مع الإقلاع، يتوقف بأمان عند الإيقاف).
#
# لا تفتح ولا سؤال تفاعلي (read) بهذا الملف — مصمم يشتغل بدون بشر يراقبه.
# صفر تعديل على أي أداة موجودة — يستخدم نفس finding_add/raqib_intel_*
# الموجودة أصلاً بـcommon.sh.

set -uo pipefail

# --- يحدّد مساره الخاص بنفسه (self-sufficient) عشان يشتغل مستقل عن raqib.sh ---
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
TOOLS_DIR="$(dirname "$(dirname "$SELF")")"
SCRIPT_DIR="$(dirname "$TOOLS_DIR")"
MODULES_DIR="$SCRIPT_DIR/modules"
export SCRIPT_DIR TOOLS_DIR MODULES_DIR

# ألوان فاضية (الإخراج يروح للوج مو لطرفية تفاعلية)
GREEN="" CYAN="" YELLOW="" RED="" ORANGE="" CRIMSON="" WHITE="" GREY="" BOLD="" NC=""
export GREEN CYAN YELLOW RED ORANGE CRIMSON WHITE GREY BOLD NC

# الحارس عملية آلية مو محلل بشري — نعلّمها بوضوح بسجل الأحداث/المحاسبة
export RAQIB_OPERATOR="system-watchdog"

# shellcheck source=/dev/null
source "$MODULES_DIR/lang.sh"
load_lang
# shellcheck source=/dev/null
source "$MODULES_DIR/common.sh"

STATE_FILE="$SCRIPT_DIR/.raqib_watchdog_state.json"
LOG_FILE="$SCRIPT_DIR/.raqib_watchdog.log"

log() { printf '%s [watchdog] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >> "$LOG_FILE"; }

log "cycle start"

# ---------------------------------------------------------------------------
# 1) منافذ استماع جديدة منذ آخر دورة — نقرأها من /proc/net/tcp|tcp6 مباشرة
#    (صفر اعتماد على أوامر خارجية زي ss/netstat، تشتغل بأي بيئة لينكس)
# ---------------------------------------------------------------------------
current_ports=$(python3 -c "
import glob
ports = set()
for path in ['/proc/net/tcp', '/proc/net/tcp6']:
    try:
        with open(path) as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                state = parts[3]
                if state != '0A':  # 0A = TCP_LISTEN
                    continue
                port_hex = parts[1].split(':')[1]
                ports.add(str(int(port_hex, 16)))
    except FileNotFoundError:
        pass
print(','.join(sorted(ports, key=int)))
" 2>/dev/null)
prev_ports=""
if [ -f "$STATE_FILE" ]; then
    prev_ports=$(python3 -c "
import json
try:
    print(','.join(json.load(open('$STATE_FILE')).get('ports', [])))
except Exception:
    pass
" 2>/dev/null)
fi

if [ -n "$prev_ports" ]; then
    new_ports=$(python3 -c "
cur = set('$current_ports'.strip(',').split(',')) if '$current_ports'.strip(',') else set()
prev = set('$prev_ports'.strip(',').split(',')) if '$prev_ports'.strip(',') else set()
print(','.join(sorted(cur - prev)))
")
    if [ -n "$new_ports" ]; then
        finding_add medium "$(tf wd_new_port "$new_ports")"
        log "new listening ports: $new_ports"
    fi
fi

# ---------------------------------------------------------------------------
# 2) الاتصالات الحالية (established) ضد قاعدة الاستخبارات المحلية —
#    نفس أسلوب /proc/net/tcp، بدون أوامر خارجية
# ---------------------------------------------------------------------------
if raqib_intel_available; then
    remote_ips=$(python3 -c "
def hex_to_ip(h):
    b = [h[i:i+2] for i in range(0, 8, 2)]
    return '.'.join(str(int(x, 16)) for x in reversed(b))

ips = set()
for path in ['/proc/net/tcp', '/proc/net/tcp6']:
    try:
        with open(path) as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                state = parts[3]
                if state != '01':  # 01 = TCP_ESTABLISHED
                    continue
                rem = parts[2].split(':')[0]
                if len(rem) == 8:
                    ip = hex_to_ip(rem)
                    if ip not in ('0.0.0.0', '127.0.0.1'):
                        ips.add(ip)
    except FileNotFoundError:
        pass
print('\n'.join(sorted(ips)))
" 2>/dev/null)
    while IFS= read -r rip; do
        [ -z "$rip" ] && continue
        out=$(raqib_intel_analyze "$rip") || continue
        IFS='|' read -r verdict score action reasons <<< "$out"
        sev=$(raqib_intel_severity "$verdict")
        finding_add "$sev" "$(tf wd_intel_hit "$rip" "$verdict")"
        log "intel hit: $rip ($verdict)"
    done <<< "$remote_ips"
fi

# ---------------------------------------------------------------------------
# 3) ملفات تنفيذية جديدة بمسارات غير معتادة (آخر 10 دقايق، عمر الدورة المعتاد)
# ---------------------------------------------------------------------------
for dir in /tmp /var/tmp /dev/shm; do
    [ -d "$dir" ] || continue
    while IFS= read -r -d '' f; do
        finding_add high "$(tf wd_new_exec "$f")"
        log "new executable: $f"
    done < <(find "$dir" -maxdepth 3 -type f -executable -newermt "-10 minutes" -print0 2>/dev/null)
done

# ---------------------------------------------------------------------------
# حفظ الحالة الحالية للمقارنة بالدورة الجاية
# ---------------------------------------------------------------------------
python3 -c "
import json
ports = '$current_ports'.strip(',').split(',') if '$current_ports'.strip(',') else []
json.dump({'ports': ports}, open('$STATE_FILE', 'w'))
" 2>/dev/null

# ---------------------------------------------------------------------------
# ربط الأحداث + تنبيه فوري بس لو فيه حوادث مركّبة جديدة (مو نفس الحادثة
# تتكرر كل دورة — نقارن العدد بآخر مرة نبّهنا فيها)
# ---------------------------------------------------------------------------
CORR_JSON=$(python3 "$TOOLS_DIR/monitoring/raqib_correlate.py" "$RAQIB_EVENTS_FILE" 60 2>/dev/null)
inc_count=$(python3 -c "
import json, sys
try:
    print(json.loads(sys.argv[1]).get('incident_count', 0))
except Exception:
    print(0)
" "$CORR_JSON" 2>/dev/null)

last_alert_count=0
[ -f "$STATE_FILE.alerted" ] && last_alert_count=$(cat "$STATE_FILE.alerted" 2>/dev/null)
[[ "$last_alert_count" =~ ^[0-9]+$ ]] || last_alert_count=0

if [ "${inc_count:-0}" -gt "$last_alert_count" ] && raqib_telegram_configured 2>/dev/null; then
    raqib_telegram_notify "$(tf wd_alert_incidents "$inc_count")" 2>/dev/null
    echo "$inc_count" > "$STATE_FILE.alerted"
    log "telegram alert sent (incident_count=$inc_count)"
fi

log "cycle end"
