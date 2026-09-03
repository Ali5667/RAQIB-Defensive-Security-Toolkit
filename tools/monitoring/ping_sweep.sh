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
alive=0
alive_hosts=()
for i in $(seq 1 "$last"); do
    ip="$subnet.$i"
    if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
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
