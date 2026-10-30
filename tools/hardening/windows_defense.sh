#!/bin/bash
# =====================================================
#  RAQIB Windows Defense Suite — حزمة الدفاع الأصلية لويندوز
#  كل الفحوص تعتمد على أدوات ويندوز الأصلية (PowerShell / Windows Defender /
#  سجل الأحداث Event Log / مجدول المهام Scheduled Tasks) — بدون أدوات خارجية.
#  الأحداث تُدفع عبر finding_add → .raqib_events.jsonl (خطوة SIEM الموحدة).
# =====================================================

source "$MODULES_DIR/common.sh" 2>/dev/null || true

# يتطلب جسر ويندوز الأصلي — على لينكس/ماك الحقيقيين تُعرض رسالة واضحة بدل الانهيار
if ! raqib_has_windows_bridge; then
    raqib_windows_only "$(raqib_tr "حزمة دفاع ويندوز" "Windows Defense Suite")"
    return 2 2>/dev/null || exit 2
fi

wd_title() {
    echo -e "${BOLD}${CYAN}$(raqib_tr "🪟 حزمة دفاع ويندوز الأصلية" "🪟 Windows Native Defense Suite")${NC}"
    echo -e "${GREY}$(raqib_tr "فحوص مبنية على أدوات ويندوز الأصلية حصراً" "Built exclusively on native Windows tooling")${NC}"
    echo ""
}

# helper — هل العنوان IP ضمن النطاقات الخاصة (LAN/loopback/link-local/ULA)؟
_is_private_ip() {
    local ip="$1"
    [[ "$ip" =~ ^(10\.|192\.168\.|169\.254\.|127\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]] && return 0
    [[ "$ip" =~ ^(fe80|fc|fd) ]] && return 0     # IPv6 link-local + ULA
    [ "$ip" = "::1" ] && return 0
    return 1
}

# =====================================================
#  1) حالة جدار ويندوز (الملفات الشخصية: Domain/Private/Public)
# =====================================================
wd_firewall() {
    echo -e "${BOLD}${CYAN}$(raqib_tr "🔥 جدار ويندوز — حالة الملفات الشخصية" "🔥 Windows Firewall profile status")${NC}"
    echo ""
    local out
    out="$(raqib_win_ps '
        Get-NetFirewallProfile | ForEach-Object {
            "{0}|{1}|{2}|{3}" -f $_.Name, $_.Enabled, $_.DefaultInboundAction, $_.DefaultOutboundAction
        }
    ')"
    if [ -z "$out" ]; then
        echo -e "  ${RED}[!] $(raqib_tr "لم نستطع قراءة حالة جدار الحماية." "Could not read firewall profile status.")${NC}"
        return 2
    fi
    local line pname penabled pin pout
    while IFS='|' read -r pname penabled pin pout; do
        [ -z "$pname" ] && continue
        if [ "$penabled" = "True" ]; then
            printf "  ${GREEN}[OK]${NC} %-8s ${GREEN}%s${NC}   $(raqib_tr "داخل:" "inbound:") %s / $(raqib_tr "خارج:" "outbound:") %s\n" \
                "$pname" "$(raqib_tr "مفعّل" "Enabled")" "$pin" "$pout"
        else
            printf "  ${CRIMSON}[X]${NC} %-8s ${RED}%s${NC}\n" "$pname" "$(raqib_tr "معطّل!!" "DISABLED !!")"
            finding_add critical "Windows Firewall profile '$pname' is DISABLED"
        fi
        if [ "$penabled" = "True" ] && [ "${pin,,}" = "allow" ]; then
            echo -e "      ${RED}[CRITICAL] $(raqib_tr "سياسة الدخول = Allow (كل الاتجاه مسموح!)" "inbound policy = ALLOW (everything permitted!)")${NC}"
            finding_add critical "Windows Firewall profile '$pname' default inbound policy is ALLOW"
        fi
        REPORT+="* $(raqib_tr 'Profile:' 'Profile:') $pname | $(raqib_tr 'Enabled:' 'Enabled:') $penabled | inbound=$pin | outbound=$pout
"
    done <<< "$out"
}

# =====================================================
#  2) الاتصالات النشطة ↔ العملية + رصد remote خارجي مشبوه
# =====================================================
wd_connections() {
    echo -e "${BOLD}${CYAN}$(raqib_tr "🔗 الاتصالات النشطة ↔ العملية (Get-NetTCPConnection)" "🔗 Active connections <-> process (Get-NetTCPConnection)")${NC}"
    echo ""
    local out
    out="$(raqib_win_ps '
        $procs = @{}
        try { Get-Process | ForEach-Object { $procs[[int]$_.Id] = $_.ProcessName } } catch {}
        Get-NetTCPConnection | ForEach-Object {
            $pname = $procs[[int]$_.OwningProcess]
            if (-not $pname) { $pname = "?" }
            "{0}|{1}:{2}|{3}:{4}|{5}|{6}" -f $_.State, $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $_.OwningProcess, $pname
        }
    ')"
    if [ -z "$out" ]; then
        echo -e "  ${RED}[!] $(raqib_tr "لم نستطع قراءة اتصالات الشبكة." "Could not read network connections.")${NC}"
        return 2
    fi

    local estab=0 listen=0 total=0
    local -a remote_pub=()
    local st l rem pid pname rip
    while IFS='|' read -r st l rem pid pname; do
        [ -z "$st" ] && continue
        total=$((total + 1))
        case "$st" in
            Established) estab=$((estab + 1)) ;;
            Listen)      listen=$((listen + 1)) ;;
        esac
        rip="${rem%%:*}"
        case "$st" in
            Established)
                if ! _is_private_ip "$rip" && [ "$rip" != "0.0.0.0" ] && [ -n "$rip" ]; then
                    remote_pub+=("$rip|$pname|$rem")
                fi
                ;;
        esac
    done <<< "$out"

    echo -e "  $(raqib_tr "إجمالي:" "Total:") ${BOLD}${total}${NC}  |  ESTABLISHED: ${CYAN}${estab}${NC}  |  LISTEN: ${YELLOW}${listen}${NC}"
    echo ""
    if [ "${#remote_pub[@]}" -gt 0 ]; then
        echo -e "  ${YELLOW}$(raqib_tr "عناوين خارجية متصلة (خارج نطاقات LAN/loopback):" "External remote endpoints (non-LAN/loopback):")${NC}"
        local idx=1
        for entry in "${remote_pub[@]:0:20}"; do
            IFS='|' read -r rip pname rem <<< "$entry"
            echo -e "   ${ORANGE}➤${NC} ${BOLD}${rip}${NC}  (${pname})  →  ${rem}"
            idx=$((idx + 1))
        done
        echo ""
        echo -e "  ${GREY}$(raqib_tr "راجِع كل IP عبر أداة استخبارات التهديدات (Threat Intel Lookup)." "Cross-check each IP with the Threat Intel Lookup tool.")${NC}"
        finding_add medium "Windows host has ${#remote_pub[@]} established connections to external IPs (review with Threat Intel)"
        REPORT+="
* $(raqib_tr 'External remote endpoints:' 'External remote endpoints:') ${#remote_pub[@]}
$(for entry in "${remote_pub[@]:0:20}"; do IFS='|' read -r rip pname rem <<< "$entry"; echo "  - $rip ($pname) -> $rem"; done)
"
    else
        echo -e "  ${GREEN}[✓] $(raqib_tr "لا توجد اتصالات رُصدت بعناوين خارجية." "No established external endpoints detected.")${NC}"
    fi
}

# =====================================================
#  3) تحليل فشل تسجيل الدخول (Event Log 4625)
# =====================================================
wd_failed_logins() {
    echo -e "${BOLD}${CYAN}$(raqib_tr "🚨 تحليل محاولات تسجيل الدخول الفاشلة (4625)" "🚨 Failed logon analysis (Event 4625)")${NC}"
    echo ""
    local out
    out="$(raqib_win_ps '
        $ev = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4625; StartTime = (Get-Date).AddHours(-48) } -MaxEvents 8000 -ErrorAction SilentlyContinue
        $ips = @{}
        $users = @{}
        foreach ($e in $ev) {
            try {
                $x = [xml]$e.ToXml()
                $ip = ($x.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" })."#text"
                $u  = ($x.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" })."#text"
                if ($ip -and $ip -ne "-" -and $ip -ne "::1") {
                    if ($ips.ContainsKey($ip)) { $ips[$ip] = $ips[$ip] + 1 } else { $ips[$ip] = 1 }
                }
                if ($u) {
                    if ($users.ContainsKey($u)) { $users[$u] = $users[$u] + 1 } else { $users[$u] = 1 }
                }
            } catch {}
        }
        "TOTAL|" + ($ev | Measure-Object).Count
        foreach ($kv in $ips.GetEnumerator()) { "IP|" + $kv.Key + "|" + $kv.Value }
        foreach ($kv in $users.GetEnumerator()) { "USER|" + $kv.Key + "|" + $kv.Value }
    ')"
    if [ -z "$out" ]; then
        echo -e "  ${YELLOW}[!] $(raqib_tr "غير متاح: يحتاج صلاحية مسؤول وقناة Security مفعّلة، أو Windows لا يسجّل 4625." "Unavailable: needs admin rights + Security auditing enabled (4625 logging).")${NC}"
        return 2
    fi

    local total=0 line
    local -a ip_rows=() user_rows=()
    while IFS='|' read -r tag a b; do
        case "$tag" in
            TOTAL) total="$a" ;;
            IP)    ip_rows+=("$a|$b") ;;
            USER)  user_rows+=("$a|$b") ;;
        esac
    done <<< "$out"

    echo -e "  $(raqib_tr "نافذة" "Window"): $(raqib_tr "آخر 48 ساعة" "last 48 hours")   |   $(raqib_tr "إجمالي الأحداث" "total events"): ${BOLD}${total}${NC}"
    echo ""
    if [ "$total" -eq 0 ]; then
        echo -e "  ${GREEN}[✓] $(raqib_tr "لا توجد محاولات فاشلة مسجّلة." "No failed logon records found.")${NC}"
        return 0
    fi
    if [ "$total" -ge 500 ]; then
        finding_add critical "Windows host logged $total failed logon attempts in the last 48h"
    elif [ "$total" -ge 100 ]; then
        finding_add high "Windows host logged $total failed logon attempts in the last 48h"
    elif [ "$total" -ge 20 ]; then
        finding_add medium "Windows host logged $total failed logon attempts in the last 48h"
    fi

    if [ "${#ip_rows[@]}" -gt 0 ]; then
        echo -e "  ${YELLOW}$(raqib_tr "IP المهاجم — من الأكثر إلى الأقل:" "Attacker IPs (top offender map):")${NC}"
        printf '%s\n' "${ip_rows[@]}" | sort -t'|' -k2 -nr | head -15 | while IFS='|' read -r ip cnt; do
            local bar="" i
            for ((i=0; i<cnt && i<40; i++)); do bar+="▓"; done
            printf "    %-16b ${RED}%5s${NC}  ${ORANGE}%s${NC}\n" "$ip" "$cnt" "$bar"
        done
    fi
    if [ "${#user_rows[@]}" -gt 0 ]; then
        echo ""
        echo -e "  ${YELLOW}$(raqib_tr "الحسابات التي استُهدف أسماؤها:" "Targeted account names:")${NC}"
        printf '%s\n' "${user_rows[@]}" | sort -t'|' -k2 -nr | head -10 | while IFS='|' read -r user cnt; do
            printf "    %-18b ${YELLOW}%5s${NC}\n" "$user" "$cnt"
        done
    fi
    REPORT+="
* $(raqib_tr 'Failed logons (4625) last 48h:' 'Failed logons (4625) last 48h:') $total
$(printf '%s\n' "${ip_rows[@]}" | sort -t'|' -k2 -nr | head -10 | sed 's/^/  - IP /')
"
}

# =====================================================
#  4) المجدول Scheduled Tasks — فحص الاستمرارية Persistence
# =====================================================
wd_scheduled_tasks() {
    echo -e "${BOLD}${CYAN}$(raqib_tr "⏰ فحص استمرارية المهام المجدولة (Scheduled Tasks)" "⏰ Scheduled Tasks persistence scan")${NC}"
    echo ""
    local out
    out="$(raqib_win_ps '
        foreach ($t in Get-ScheduledTask) {
            try {
                foreach ($a in $t.Actions) {
                    $ex = "" + $a.Execute
                    if (-not $ex) { continue }
                    $arg = "" + $a.Arguments
                    $low = ($ex + " " + $arg).ToLower()
                    $flag = ""
                    if ($low -match "temp") { $flag = "TEMP-PATH" }
                    if ($low -match "downloads|appdata\\local\\|public") { $flag = "USER-WRITABLE" }
                    if ($low -match "-enc |wscript|cscript|mshta|rundll32|regsvr32|\.vbs|\.js |\.jse|\.wsf") { $flag = "LOLBIN-SUSPICIOUS" }
                    if ($flag -ne "") {
                        "TASK|" + $t.TaskName + "|" + $ex + "|" + $arg + "|" + $flag
                    }
                }
            } catch {}
        }
    ')"
    if [ -z "$out" ]; then
        echo -e "  ${GREEN}[✓] $(raqib_tr "لا توجد مهام مجدولة مشبوهة." "No suspicious scheduled task actions detected.")${NC}"
        return 0
    fi
    local -a flagged=()
    local line flag _task _ex _arg
    while IFS='|' read -r tag _task _ex _arg flag; do
        [ "$tag" = "TASK" ] && flagged+=("$flag|$_task|$_ex|$_arg")
    done <<< "$out"

    if [ "${#flagged[@]}" -eq 0 ]; then
        echo -e "  ${GREEN}[✓] $(raqib_tr "لا توجد مهام مجدولة مشبوهة." "No suspicious scheduled task actions detected.")${NC}"
        return 0
    fi
    echo -e "  ${YELLOW}$(raqib_tr "مهام مشبوهة (تظهر عادةً لأسباب مشروعية — راجِعها):" "Suspicious tasks (legit software triggers these too - review each):")${NC}"
    for row in "${flagged[@]:0:20}"; do
        IFS='|' read -r flag _task _ex _arg <<< "$row"
        echo -e "    ${ORANGE}➤${NC} ${BOLD}${_task}${NC}  ${GREY}[${flag}]${NC}"
        echo -e "        ${GREY}${_ex} ${_arg}${NC}"
    done
    finding_add high "Windows scheduled tasks include ${#flagged[@]} suspicious action(s) (temp/user-writable/LOLBin)"
    REPORT+="
* $(raqib_tr 'Suspicious scheduled task actions:' 'Suspicious scheduled task actions:') ${#flagged[@]}
$(for row in "${flagged[@]:0:10}"; do IFS='|' read -r flag _task _ex _arg <<< "$row"; echo "  - $_task [$flag]: $_ex $_arg"; done)
"
}

# =====================================================
#  5) Windows Defender — الحالة + آخر التهديدات
# =====================================================
wd_defender() {
    echo -e "${BOLD}${CYAN}$(raqib_tr "🛡️ حالة Windows Defender + آخر التهديدات" "🛡️ Windows Defender status + recent threats")${NC}"
    echo ""
    local out
    out="$(raqib_win_ps '
        try {
            $s = Get-MpComputerStatus -ErrorAction Stop
            "DEF|" + $s.AntivirusEnabled + "|" + $s.RealTimeProtectionEnabled + "|" + $s.AntivirusSignatureLastUpdated + "|" + $s.AMRunningMalwareScan
            $th = Get-MpThreatDetection -ErrorAction SilentlyContinue | Sort-Object InitialDetectionTime -Descending | Select-Object -First 10
            foreach ($t in $th) {
                "THREAT|" + $t.InitialDetectionTime + "|" + ($t.Resources -join ";")
            }
        } catch {
            "DEF|unavailable"
        }
    ')"
    local first
    first="$(printf '%s\n' "$out" | head -1)"
    local def_status
    def_status="${first#DEF|}"
    if [ "$def_status" = "unavailable" ] || [ -z "$def_status" ]; then
        echo -e "  ${YELLOW}[!] $(raqib_tr "Defender غير متاح على هذا النظام (سيرفر بدون رول أو بديل طرف ثالث)." "Defender not available here (server role or a third-party AV).")${NC}"
        return 2
    fi
    local av_enabled rtp_enabled sig_time scanning
    IFS='|' read -r av_enabled rtp_enabled sig_time scanning <<< "$def_status"
    if [ "$av_enabled" != "True" ]; then
        echo -e "  ${CRIMSON}[CRITICAL] $(raqib_tr "مضاد الفيروسات معطّل إجمالاً!" "Antivirus DISABLED globally!")${NC}"
        finding_add critical "Windows Defender is DISABLED"
    else
        echo -e "  ${GREEN}[OK] $(raqib_tr "مضاد الفيروسات مفعّل." "Antivirus enabled.")${NC}"
    fi
    if [ "$rtp_enabled" != "True" ]; then
        echo -e "  ${CRIMSON}[CRITICAL] $(raqib_tr "الحماية اللحظية (وقت الفحص الفوري) معطّلة!" "Real-time protection DISABLED!")${NC}"
        finding_add critical "Windows Defender real-time protection is DISABLED"
    else
        echo -e "  ${GREEN}[OK] $(raqib_tr "الحماية اللحظية مفعّلة." "Real-time protection enabled.")${NC}"
    fi
    echo -e "  $(raqib_tr "آخر تحديث توقيعات:" "Last signature update:") ${sig_time}"
    echo -e "  $(raqib_tr "فحص خبيث جارٍ:" "Malware scan in progress:") ${scanning}"

    local threat line first_threat=1
    while IFS='|' read -r tag tstamp resources; do
        [ "$tag" != "THREAT" ] && continue
        if [ "$first_threat" -eq 1 ]; then
            echo ""
            echo -e "  ${ORANGE}$(raqib_tr "آخر تهديدات رُصدت (10 الأحدث):" "Recent threat detections (latest 10):")${NC}"
            first_threat=0
        fi
        echo -e "    ${RED}➤${NC} ${tstamp}  ${GREY}${resources}${NC}"
    done <<< "$out"
    if [ "$first_threat" -eq 0 ]; then
        finding_add high "Windows Defender has recorded threat detections (see report)"
        REPORT+="
* $(raqib_tr 'Defender threat detections:' 'Defender threat detections:')
$(printf '%s\n' "$out" | grep '^THREAT|' | head -10 | sed 's/^THREAT|/  - /')
"
    fi
}

# =====================================================
#  6) Autoruns مصنوعة من مفاتيح Run / RunOnce / Startup / Services
# =====================================================
wd_autoruns() {
    echo -e "${BOLD}${CYAN}$(raqib_tr "🚀 نقاط بدء التشغيل — Run/RunOnce + Startup + الخدمات" "🚀 Startup persistence — Run/RunOnce + Startup folders + services")${NC}"
    echo ""
    local out
    out="$(raqib_win_ps '
        $keys = @(
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        foreach ($k in $keys) {
            try {
                if (Test-Path $k) {
                    $props = Get-ItemProperty -Path $k -ErrorAction Stop
                    foreach ($p in $props.PSObject.Properties) {
                        if ($p.Name -like "PS*") { continue }
                        "RUNKEY|" + $k + "|" + $p.Name + "|" + $p.Value
                    }
                }
            } catch {}
        }
        $dirs = @(
            ($env:APPDATA + "\Microsoft\Windows\Start Menu\Programs\Startup"),
            ($env:ProgramData + "\Microsoft\Windows\Start Menu\Programs\Startup")
        )
        foreach ($d in $dirs) {
            try {
                if (Test-Path $d) {
                    Get-ChildItem $d | ForEach-Object { "STARTUP|" + $_.FullName }
                }
            } catch {}
        }
        try {
            Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq "Auto" } | ForEach-Object {
                "SVC|" + $_.Name + "|" + $_.State + "|" + $_.PathName
            }
        } catch {}
    ')"
    if [ -z "$out" ]; then
        echo -e "  ${YELLOW}[!] $(raqib_tr "تعذّر قراءة عناصر بدء التشغيل." "Could not enumerate startup persistence entries.")${NC}"
        return 2
    fi

    local line runs=0 startups=0 autos=0 suspicious=0
    local -a sus_rows=()
    while IFS='|' read -r tag a b c; do
        [ -z "$tag" ] && continue
        case "$tag" in
            RUNKEY)
                runs=$((runs + 1))
                local lowall="${b,,} ${c,,}"
                local flag=""
                if [[ "$lowall" == *temp* || "$lowall" == *downloads* || "$lowall" == *"-enc"* || "$lowall" == *wscript* || "$lowall" == *mshta* ]]; then
                    flag="[${ORANGE}SUSPICIOUS${NC}]"
                    suspicious=$((suspicious + 1))
                    sus_rows+=("RUNKEY|$a|$b|$c")
                fi
                if [ $runs -le 25 ]; then
                    echo -e "  ${CYAN}[Run]${NC} $b  →  ${GREY}$c${NC} $flag"
                fi
                ;;
            STARTUP)
                startups=$((startups + 1))
                if [ $startups -le 15 ]; then
                    echo -e "  ${CYAN}[Startup folder]${NC} ${GREY}$a${NC}"
                fi
                ;;
            SVC)
                autos=$((autos + 1))
                local lowsvc="${c,,}"
                if [[ "$lowsvc" == *temp* || "$lowsvc" == *appdata* || "$lowsvc" == *downloads* ]]; then
                    suspicious=$((suspicious + 1))
                    sus_rows+=("SERVICE|$a|$b|$c")
                    echo -e "  ${RED}[SVC SUSPICIOUS]${NC} $a  ${GREY}$c${NC}"
                fi
                ;;
        esac
    done <<< "$out"

    echo ""
    echo -e "  $(raqib_tr "الإجمالي:" "Totals:") Run/RunOnce: ${BOLD}${runs}${NC}  |  Startup folder: ${BOLD}${startups}${NC}  |  $(raqib_tr "خدمات أوتوماتيك:" "auto services:") ${BOLD}${autos}${NC}${suspicious:+  |  ${RED}$(raqib_tr "مشبوهة:" "suspicious:") ${suspicious}${NC}}"
    REPORT+="$(raqib_tr '* Startups — Run/RunOnce:' '* Startups — Run/RunOnce:') $runs | $(raqib_tr 'Startup folder:' 'Startup folder:') $startups | $(raqib_tr 'auto services:' 'auto services:') $autos | suspicious: $suspicious
"
    if [ "$suspicious" -gt 0 ]; then
        finding_add high "Windows startup persistence includes $suspicious suspicious entry(ies) (temp/user-writable/LOLBin)"
        REPORT+="
* $(raqib_tr 'Suspicious startup persistence entries:' 'Suspicious startup persistence entries:') $suspicious
$(for row in "${sus_rows[@]:0:10}"; do IFS='|' read -r tag a b c <<< "$row"; echo "  - [$tag] $b: $c"; done)
"
    fi
}

# =====================================================
#  7) ملف hosts — من يكتب أي إدخالات ثابتة
# =====================================================
wd_hosts() {
    echo -e "${BOLD}${CYAN}$(raqib_tr "📥 ملف hosts — الأدخالات غير الافتراضية" "📥 hosts file — non-default entries")${NC}"
    echo ""
    local out
    out="$(raqib_win_ps '
        $p = $env:WINDIR + "\System32\drivers\etc\hosts"
        try {
            Get-Content $p -ErrorAction Stop | Where-Object { $_ -and (-not $_.Trim().StartsWith("#")) } | ForEach-Object { "HOSTLINE|" + $_ }
        } catch {
            "HOSTERR"
        }
    ')"
    local line cnt=0
    while IFS='|' read -r tag line; do
        [ "$tag" != "HOSTLINE" ] && continue
        cnt=$((cnt + 1))
        echo -e "    ${GREY}>${NC} $line"
    done <<< "$out"
    if [ "$cnt" -eq 0 ]; then
        echo -e "  ${GREEN}[✓] $(raqib_tr "لا توجد إدخالات ثابتة (كل الأسطر تعليقات افتراضية)." "No static hosts entries beyond default comments.")${NC}"
        return 0
    fi
    echo ""
    echo -e "  ${YELLOW}$(raqib_tr "البرمجيات الخبيثة عادةً تضيف أكثر من سطرين؛ راجِع الغرض من كل إدخال." "Adversaries usually add more than two lines; check each entrys purpose.")${NC}"
    if [ "$cnt" -gt 3 ]; then
        finding_add medium "hosts file contains $cnt non-comment static DNS entries (review each)"
    fi
    REPORT+="
* $(raqib_tr 'hosts static entries:' 'hosts static entries:') $cnt
$(printf '%s\n' "$out" | grep '^HOSTLINE|' | sed 's/^HOSTLINE|/  - /')
"
}

# =====================================================
#  القائمة الرئيسية للحزمة
# =====================================================
wd_menu() {
    while true; do
        show_banner
        wd_title
        echo -e "  ${CYAN} 1)${NC} 🔥 $(raqib_tr "حالة جدار الحماية" "Firewall profile status")"
        echo -e "  ${CYAN} 2)${NC} 🔗 $(raqib_tr "الاتصالات + عناوين Remote" "Active connections + remote endpoints")"
        echo -e "  ${CYAN} 3)${NC} 🚨 $(raqib_tr "محاولات فشل تسجيل الدخول (Event 4625)" "Failed logon triage (Event 4625)")"
        echo -e "  ${CYAN} 4)${NC} ⏰ $(raqib_tr "فحص استمرارية المهام المجدولة" "Scheduled tasks persistence scan")"
        echo -e "  ${CYAN} 5)${NC} 🛡️ $(raqib_tr "Windows Defender + آخر التهديدات" "Windows Defender + recent threats")"
        echo -e "  ${CYAN} 6)${NC} 🚀 $(raqib_tr "فحص بدء التشغيل (Run/RunOnce/Startup/Svc)" "Startup persistence (Run/RunOnce/Startup/Svc)")"
        echo -e "  ${CYAN} 7)${NC} 📥 $(raqib_tr "تدقيق ملف hosts" "hosts file audit")"
        echo -e "  ${RED} 0)${NC} $(t back)"
        echo ""
        read -rp "  $(raqib_tr "اختر [0-7]: " "Choice [0-7]: ")" c
        case "$c" in
            1)
                REPORT=""
                finding_reset
                wd_firewall
                print_executive_summary "$(raqib_tr 'جدار ويندوز' 'Windows Firewall')"
                ;;
            2)
                REPORT=""
                finding_reset
                wd_connections
                print_executive_summary "$(raqib_tr 'الاتصالات النشطة' 'Active connections')"
                ;;
            3)
                REPORT=""
                finding_reset
                wd_failed_logins
                print_executive_summary "$(raqib_tr 'تحليل الفشل 4625' '4625 failed logon triage')"
                ;;
            4)
                REPORT=""
                finding_reset
                wd_scheduled_tasks
                print_executive_summary "$(raqib_tr 'المهام المجدولة' 'Scheduled tasks')"
                ;;
            5)
                REPORT=""
                finding_reset
                wd_defender
                print_executive_summary "$(raqib_tr 'Windows Defender' 'Windows Defender')"
                ;;
            6)
                REPORT=""
                finding_reset
                wd_autoruns
                print_executive_summary "$(raqib_tr 'بدء التشغيل' 'Startup persistence')"
                ;;
            7)
                REPORT=""
                finding_reset
                wd_hosts
                print_executive_summary "$(raqib_tr 'ملف hosts' 'hosts file')"
                ;;
            0)
                return
                ;;
            *)
                echo -e "${RED}$(t invalid_choice)${NC}"
                sleep 1
                continue
                ;;
        esac
        [ -n "$REPORT" ] && save_report "$REPORT" "windows_defense_scan.txt" "Windows Defense Suite"
        pause
    done
}

wd_menu
