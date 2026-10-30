#!/bin/bash
echo -e "${CYAN}$(t mon6_title)${NC}"
read -rp "$(t mon6_prompt_subnet)" subnet
if ! [[ "$subnet" =~ ^([0-9]{1,3}\.){2}[0-9]{1,3}$ ]]; then
    echo -e "${RED}$(t mon6_invalid_format)${NC}"; exit 1
fi
IFS='.' read -ra _subnet_octets <<< "$subnet"
for _o in "${_subnet_octets[@]}"; do
    if [ "$_o" -gt 255 ]; then
        echo -e "${RED}$(t mon6_invalid_format)${NC}"; exit 1
    fi
done
read -rp "$(t mon6_prompt_last)" last
last=${last:-254}
if ! [[ "$last" =~ ^[0-9]+$ ]] || [ "$last" -lt 1 ] || [ "$last" -gt 254 ]; then
    echo -e "${RED}$(t mon6_value_1_254)${NC}"; exit 1
fi

echo -e "${YELLOW}$(tf mon6_scanning "$subnet" "$subnet" "$last")${NC}"

# ─── أمر ping حسب المنصة ─────────────────────────────────────
#  Linux   : ping -c 1 -W 1            (timeout بالثواني)
#  macOS   : ping -c 1 -t 1            (-t مهلة بالثواني، -W بوحدة ms)
#  Windows : ping -n 1 -w 1000         (ping.exe الأصلي؛ نتحقق بوجود TTL=
#            لأن ping.exe يرجع 0 حتى لو "Destination host unreachable")
sweep_ping() {
    if raqib_is_macos; then
        ping -c 1 -t 1 "$1" >/dev/null 2>&1
    elif raqib_is_windows && command -v ping.exe >/dev/null 2>&1; then
        ping.exe -n 1 -w 1000 "$1" 2>/dev/null | grep -q "TTL="
    else
        ping -c 1 -W 1 "$1" >/dev/null 2>&1
    fi
}

alive=0
alive_hosts=()
for i in $(seq 1 "$last"); do
    ip="$subnet.$i"
    if sweep_ping "$ip"; then
        printf "\r\033[K"
        echo -e "${GREEN}$(tf mon6_host_alive "$ip")${NC}"
        alive_hosts+=("$ip")
        ((alive++))
    fi
    draw_progress_bar "$i" "$last" "$(t mon6_title)"
done
finish_progress_bar
echo -e "${CYAN}$(tf mon6_scan_done "$alive")${NC}"

if [ "$alive" -gt 0 ]; then
    report="$(tf mon6_report_title "$subnet")
$(tf mon1_scan_date "$(date)")
$(t mon6_active_hosts)
$(printf '%s\n' "${alive_hosts[@]}")
$(tf mon1_total "$alive")"
    save_report "$report" "ping_sweep_${subnet//./_}.txt"
fi
