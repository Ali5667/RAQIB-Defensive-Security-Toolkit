#!/bin/bash
# =====================================================
#  Login History Report — تقرير سجل تسجيل الدخول
#  يجمع: last + lastb + lastlog + wtmp + utmp
#  يحلل: أنماط تسجيل الدخول المشبوهة، الساعات الغريبة،
#         IPs غير المعتادة، محاولات الفاشلة المتكررة
# =====================================================
finding_reset

TOOL_TITLE="$(t for1_title)"
echo -e "${CYAN}${TOOL_TITLE}${NC}"
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

REPORT=""

_getwin_fail() {
    echo -e "  ${YELLOW}[!] $(raqib_tr "يتطلب صلاحية مسؤول + تفعيل تدقيق Security على ويندوز." "Requires admin rights + Security auditing enabled on Windows.")${NC}"
    return 2
}

# ============================================================================
#  فرع ويندوز الأصلي (Git Bash) — يكافئ آخر 6 فحوص بأنظمة ويندوز:
#   last → Event 4624 · lastb → Event 4625 · lastlog → Get-LocalUser
#   who → quser · sudo/wheel → Administrators group · wtmp → Security.evtx
# ============================================================================
_win_login_history() {
    echo -e "${YELLOW}$(raqib_tr "◉ تسجيلات دخول ناجحة (Event 4624) — آخر 30" "◉ Successful logons (Event 4624) — latest 30")${NC}"
    local ev_out
    ev_out="$(raqib_win_ps '
        $ev = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4624; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 500 -ErrorAction SilentlyContinue
        foreach ($e in $ev) {
            try {
                $x = [xml]$e.ToXml()
                $u  = ($x.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" })."#text"
                $ip = ($x.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"
                if ($u -and $u -notmatch "\$$" -and $u -ne "SYSTEM") {
                    if (-not $ip -or $ip -eq "-") { $ip = "local" }
                    "{0}|{1}|{2}" -f $e.TimeCreated, $u, $ip
                }
            } catch {}
        }
    ')"
    if [ -z "$ev_out" ]; then
        _getwin_fail
        successful=""
    else
        successful="$(printf '%s\n' "$ev_out" | head -30)"
        echo "$successful" | while IFS='|' read -r tstamp uname lip; do
            [ -z "$uname" ] && continue
            hour="$(date -d "$tstamp" +%H 2>/dev/null || echo "")"
            if [ -n "$hour" ] && { [ "$hour" -ge 23 ] || [ "$hour" -le 5 ]; } 2>/dev/null; then
                echo -e "${ORANGE}  [ساعة غريبة] $uname  ($lip)  @  $tstamp${NC}"
                finding_add medium "Login during unusual hours: $uname from $lip at $tstamp"
            else
                echo -e "  ▸ $uname  ${GREY}($lip) @ $tstamp${NC}"
            fi
        done
    fi
    REPORT+="$(t for1_successful)
${successful:-N/A}

"

    echo ""
    echo -e "${YELLOW}$(raqib_tr "◉ محاولات فاشلة (Event 4625) — آخر 20" "◉ Failed logons (Event 4625) — latest 20")${NC}"
    local fail_out fail_rows
    fail_out="$(raqib_win_ps '
        $ev = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4625; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 2000 -ErrorAction SilentlyContinue
        $ips = @{}
        foreach ($e in $ev) {
            try {
                $x = [xml]$e.ToXml()
                $ip = ($x.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"
                if ($ip -and $ip -ne "-") { if ($ips.ContainsKey($ip)) { $ips[$ip] = $ips[$ip] + 1 } else { $ips[$ip] = 1 } }
            } catch {}
        }
        "TOTAL|" + ($ev | Measure-Object).Count
        foreach ($kv in $ips.GetEnumerator()) { "IP|" + $kv.Key + "|" + $kv.Value }
    ')"
    if [ -z "$fail_out" ]; then
        echo -e "  ${GREEN}$(raqib_tr "لا توجد محاولات دخول فاشلة مسجّلة (أو التدقيق معطّل)." "No failed logon records (or auditing disabled).")${NC}"
        failed=""
    else
        total_fail="$(printf '%s\n' "$fail_out" | grep '^TOTAL|' | head -1 | cut -d'|' -f2)"
        echo -e "  $(raqib_tr "إجمالي الفشل خلال أسبوعين:" "Failed events in 2 weeks:") ${BOLD}${total_fail:-0}${NC}"
        echo ""
        echo "$fail_out" | grep '^IP|' | awk -F'|' '{print $3 "|" $2}' | sort -rn | head -10 | \
        while read -r count ip; do
            if [ "$count" -ge 10 ]; then
                echo -e "  ${RED}  🔴 $count محاولة  →  $ip${NC}"
                finding_add high "Multiple failed logins from $ip: $count attempts"
            elif [ "$count" -ge 3 ]; then
                echo -e "  ${ORANGE}  🟠 $count محاولة  →  $ip${NC}"
                finding_add medium "Repeated failed logins from $ip: $count attempts"
            else
                echo -e "  ${YELLOW}  🟡 $count محاولة  →  $ip${NC}"
            fi
        done
        failed="$(echo "$fail_out" | sed 's/^/  /')"
    fi
    REPORT+="$(t for1_failed)
${failed:-N/A}

"

    echo ""
    echo -e "${YELLOW}$(t for1_last_per_user)${NC}"
    local users_out users
    users="$(raqib_win_ps '
        Get-LocalUser | ForEach-Object {
            "USER|" + $_.Name + "|" + $_.Enabled + "|" + $_.LastSignin
        }
    ')"
    if [ -z "$users" ]; then
        echo -e "  ${YELLOW}$(raqib_tr "Get-LocalUser غير متاح." "Get-LocalUser unavailable.")${NC}"
        lastlogins=""
    else
        lastlogins="$(printf '%s\n' "$users" | awk -F'|' '{
            if ($1 != "USER") next
            en = ($3 == "True") ? "enabled " : "disabled"
            printf "  %-18s %s  LastSignin: %s\n", $2, en, $4
        }')"
        echo "$lastlogins" | head -30
    fi
    REPORT+="$(t for1_last_per_user)
${lastlogins:-N/A}

"

    echo ""
    echo -e "${YELLOW}◉ $(raqib_tr "الجلسات النشطة حالياً (quser)" "Active sessions right now (quser)")${NC} "
    local active_sessions
    if command -v quser.exe >/dev/null 2>&1; then
        active_sessions="$(quser.exe 2>/dev/null)"
    else
        active_sessions=""
    fi
    if [ -n "$active_sessions" ]; then
        echo "$active_sessions" | while IFS= read -r line; do
            echo -e "  ${CYAN}▸${NC} $line"
        done
        session_count=$(( $(echo "$active_sessions" | wc -l) > 1 ? $(echo "$active_sessions" | wc -l) - 1 : 0 ))
        if [ "$session_count" -gt 5 ]; then
            finding_add medium "Unusually high number of active sessions: $session_count"
            echo -e "  ${ORANGE}⚠️  $session_count جلسة نشطة — عدد مرتفع${NC}"
        fi
    else
        echo -e "  ${GREEN}$(raqib_tr "لا توجد جلسات نشطة (أو quser يحتاج صلاحية)." "No active sessions (or quser needs permissions).")${NC}"
    fi
    REPORT+="Active Sessions:
${active_sessions:-None}

"

    echo ""
    echo -e "${YELLOW}◉ $(raqib_tr "عضوية مجموعات امتيازات عالية (Administrators)" "High-privilege group memberships (Administrators)")${NC}"
    local admins users_admin
    users_admin="$(raqib_win_ps '
        try {
            Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | ForEach-Object {
                "ADMIN|" + $_.Name + "|" + $_.PrincipalSource
            }
        } catch {}
    ')"
    if [ -n "$users_admin" ]; then
        echo "$users_admin" | while IFS='|' read -r tag a b; do
            [ "$tag" != "ADMIN" ] && continue
            echo -e "  ${YELLOW}⚡ $a${NC}"
        done
    else
        echo -e "  ${GREY}$(raqib_tr "لا توجد بيانات (تحتاج صلاحية كافية)." "No data (needs sufficient privileges).")${NC}"
    fi
    REPORT+="Administrators members:
${users_admin:-N/A}

"

    echo ""
    echo -e "${YELLOW}◉ $(raqib_tr "فحص ملف Security.evtx (حجمة) للرصد المبكر للتخفيف" "Security.evtx size check (early tampering indicator)")${NC}"
    local evtx_out evtx_size evtx_attr
    evtx_out="$(raqib_win_ps '
        $p = "$env:WINDIR\System32\winevt\Logs\Security.evtx"
        try {
            $f = Get-Item $p -ErrorAction Stop
            "EVTX|" + $f.Length + "|" + $f.LastWriteTime
        } catch {
            "EVTX|unavailable|"
        }
    ')"
    evtx_size="$(printf '%s\n' "$evtx_out" | grep '^EVTX|' | cut -d'|' -f2 | head -1)"
    evtx_attr="$(printf '%s\n' "$evtx_out" | grep '^EVTX|' | cut -d'|' -f3 | head -1)"
    if [ "$evtx_size" = "unavailable" ] || [ -z "$evtx_size" ]; then
        echo -e "  ${YELLOW}[!] $(raqib_tr "الملف غير قابل للوصول (صلاحيات أو طرف ثالث تسجيل)." "File not accessible (permissions or 3rd-party logging).")${NC}"
    else
        echo -e "  ${CYAN}Security.evtx${NC}  $(raqib_tr "الحجم:" "size:") ${evtx_size} bytes   $(raqib_tr "آخر كتابة:" "last write:") ${evtx_attr}"
        finding_add low "Security.evtx last write: $evtx_attr"
    fi
}

# ============================================================================
#  تفرّع المنصة: على ويندوز أصلي (Git Bash/Cygwin) ننفّذ الفرع الخاص بويندوز
#  ثم نحفظ التقرير ونخرج — لن ننفّذ فحوص لينكس (last/lastb/lastlog وغيرها).
#  WSL يعدل لفرع لينكس الطبيعي (كل أدوات لينكس متاحة هناك).
# ============================================================================
if raqib_is_windows; then
    _win_login_history
    echo ""
    echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    print_executive_summary "$TOOL_TITLE"
    save_report "$(tf for1_report_title "$(date)"). Windows-native branch.

$REPORT" "login_history_report.txt" "$TOOL_TITLE"
    return 0 2>/dev/null || exit 0
fi


# ─── 1. آخر 30 تسجيل دخول ناجح ─────────────────────────────
echo -e "${YELLOW}$(t for1_successful)${NC}"
if command -v last >/dev/null 2>&1; then
    successful=$(last -n 30 -w 2>/dev/null | grep -v "^$\|^wtmp\|^btmp" | head -30)
    if [ -n "$successful" ]; then
        echo "$successful" | while IFS= read -r line; do
            # تحليل: تسجيل دخول في ساعات غريبة (23:00 - 05:00)
            hour=$(echo "$line" | grep -oE '[0-9]{2}:[0-9]{2}' | head -1 | cut -d: -f1)
            if [ -n "$hour" ] && [ "$hour" -ge 23 -o "$hour" -le 5 ] 2>/dev/null; then
                echo -e "${ORANGE}  [ساعة غريبة] $line${NC}"
                finding_add medium "Login during unusual hours: $line"
            else
                echo "  $line"
            fi
        done
    else
        echo -e "  ${GREY}(لا توجد بيانات)${NC}"
    fi
else
    echo -e "  ${YELLOW}أمر 'last' غير متوفر${NC}"
    successful=""
fi

REPORT+="$(t for1_successful)
${successful:-N/A}

"

# ─── 2. محاولات الدخول الفاشلة (lastb) ──────────────────────
echo ""
echo -e "${YELLOW}$(t for1_failed)${NC}"
if command -v lastb >/dev/null 2>&1; then
    failed=$(lastb -n 20 -w 2>/dev/null | grep -v "^$\|^btmp" | head -20)
    if [ -n "$failed" ]; then
        # حساب عدد المحاولات لكل IP
        echo ""
        echo -e "  ${BOLD}● أعلى IPs بعدد محاولات فاشلة:${NC}"
        echo "$failed" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -10 | \
        while read -r count ip; do
            if [ "$count" -ge 10 ]; then
                echo -e "  ${RED}  🔴 $count محاولة  →  $ip${NC}"
                finding_add high "Multiple failed logins from $ip: $count attempts"
            elif [ "$count" -ge 3 ]; then
                echo -e "  ${ORANGE}  🟠 $count محاولة  →  $ip${NC}"
                finding_add medium "Repeated failed logins from $ip: $count attempts"
            else
                echo -e "  ${YELLOW}  🟡 $count محاولة  →  $ip${NC}"
            fi
        done
        echo ""
        echo "$failed"
    else
        echo -e "  ${GREEN}لا توجد محاولات دخول فاشلة مسجّلة${NC}"
    fi
else
    echo -e "  ${YELLOW}$(t for1_needs_root) (يحتاج صلاحية root لأمر lastb)${NC}"
    failed=""
fi

REPORT+="$(t for1_failed)
${failed:-N/A}

"

# ─── 3. آخر تسجيل دخول لكل مستخدم ──────────────────────────
echo ""
echo -e "${YELLOW}$(t for1_last_per_user)${NC}"
if command -v lastlog >/dev/null 2>&1; then
    lastlogins=$(lastlog 2>/dev/null | grep -v "Never logged in" | head -30)
    echo "$lastlogins"
else
    # بديل: قراءة /etc/passwd + wtmp
    echo -e "  ${YELLOW}أمر lastlog غير متوفر — فحص /etc/passwd${NC}"
    lastlogins=$(awk -F: '$3>=1000 && $3<65534{print $1}' /etc/passwd 2>/dev/null | head -20)
    echo "$lastlogins"
fi

REPORT+="$(t for1_last_per_user)
${lastlogins:-N/A}

"

# ─── 4. جلسات SSH النشطة حالياً ───────────────────────────
echo ""
echo -e "${YELLOW}◉ الجلسات النشطة حالياً${NC}"
active_sessions=$(who 2>/dev/null)
if [ -n "$active_sessions" ]; then
    echo "$active_sessions" | while IFS= read -r line; do
        echo -e "  ${CYAN}▸${NC} $line"
    done
    session_count=$(echo "$active_sessions" | wc -l)
    if [ "$session_count" -gt 5 ]; then
        finding_add medium "Unusually high number of active sessions: $session_count"
        echo -e "  ${ORANGE}⚠️  $session_count جلسة نشطة — عدد مرتفع${NC}"
    fi
else
    echo -e "  ${GREEN}لا توجد جلسات نشطة${NC}"
fi

REPORT+="Active Sessions:
${active_sessions:-None}

"

# ─── 5. مستخدمون في مجموعة sudo/wheel ─────────────────────
echo ""
echo -e "${YELLOW}◉ المستخدمون بصلاحية sudo/wheel${NC}"
sudo_users=""
if command -v getent >/dev/null 2>&1; then
    sudo_users=$(getent group sudo wheel 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | grep -v '^$')
fi
if [ -z "$sudo_users" ]; then
    sudo_users=$(grep -E "^sudo:|^wheel:" /etc/group 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sort -u | grep -v '^$')
fi
if [ -n "$sudo_users" ]; then
    echo "$sudo_users" | while IFS= read -r u; do
        echo -e "  ${YELLOW}⚡ $u${NC}"
    done
else
    echo -e "  ${GREY}لا توجد بيانات (تحتاج صلاحية كافية)${NC}"
fi

REPORT+="Sudo/Wheel users:
${sudo_users:-N/A}

"

# ─── 6. UTmp/WTmp لفحص تعديلات ──────────────────────────
echo ""
echo -e "${YELLOW}◉ فحص سجلات wtmp/btmp${NC}"
for wfile in /var/log/wtmp /var/log/btmp; do
    if [ -f "$wfile" ]; then
        perm=$(raqib_stat_perm "$wfile" 2>/dev/null)
        size=$(raqib_stat_size "$wfile" 2>/dev/null)
        echo -e "  ${CYAN}$wfile${NC}  perms: $perm  size: ${size} bytes"
        # فحص: ملف فارغ أو محذوف = tamper مشبوه
        if [ "$size" -eq 0 ] 2>/dev/null; then
            echo -e "  ${RED}  ⚠️ الملف فارغ — ربما تم مسحه للتغطية على آثار الاختراق!${NC}"
            finding_add critical "$(basename "$wfile") is empty — possible log tampering"
        fi
    fi
done

echo ""
echo -e "${GREY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
print_executive_summary "$TOOL_TITLE"

save_report "$(tf for1_report_title "$(date)")

$REPORT

=== Active Sessions ===
$(who 2>/dev/null)

=== Sudo/Wheel Users ===
$sudo_users" "login_history_report.txt" "$TOOL_TITLE"
