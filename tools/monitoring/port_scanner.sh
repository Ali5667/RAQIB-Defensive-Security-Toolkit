#!/bin/bash
# port_scanner.sh — TCP port scanner for a given host
echo -e "${CYAN}$(t mon1_title)${NC}"
read -rp "$(t mon1_prompt_host)" host
[ -z "$host" ] && { echo -e "${RED}$(t mon1_need_addr)${NC}"; exit 1; }

read -rp "$(t mon1_prompt_from_port)" start_port
read -rp "$(t mon1_prompt_to_port)" end_port
start_port=${start_port:-1}
end_port=${end_port:-1024}

if ! is_valid_port "$start_port" || ! is_valid_port "$end_port"; then
    echo -e "${RED}$(t mon1_invalid_port_range)${NC}"; exit 1
fi
if [ "$start_port" -gt "$end_port" ]; then
    echo -e "${RED}$(t mon1_start_gt_end)${NC}"; exit 1
fi
if [ $((end_port - start_port)) -gt 20000 ]; then
    read -rp "$(t mon1_range_too_large)" confirm
    [ "$confirm" != "y" ] && exit 0
fi

echo -e "${YELLOW}$(tf mon1_scanning "$host" "$start_port" "$end_port")${NC}"
open_count=0
open_ports=()
total=$(( end_port - start_port + 1 ))
i=0
for ((port=start_port; port<=end_port; port++)); do
    ((i++))
    if (echo > /dev/tcp/"$host"/"$port") >/dev/null 2>&1; then
        printf "\r\033[K"
        echo -e "${GREEN}$(tf mon1_port_open "$port")${NC}"
        open_ports+=("$port")
        ((open_count++))
    fi
    draw_progress_bar "$i" "$total" "$(t mon1_title)"
done
finish_progress_bar
echo -e "${CYAN}$(tf mon1_scan_done "$open_count")${NC}"

if [ "$open_count" -gt 0 ]; then
    report="$(tf mon1_report_title "$host" "$start_port" "$end_port")
$(tf mon1_scan_date "$(date)")
$(tf mon1_open_ports_list "${open_ports[*]}")
$(tf mon1_total "$open_count")"
    save_report "$report" "port_scan_${host//[.:]/_}.txt"
fi
