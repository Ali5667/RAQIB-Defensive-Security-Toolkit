#!/bin/bash
echo -e "${CYAN}$(t mon3_title)${NC}"
if [ ! -d /sys/class/net ]; then
    echo -e "${RED}$(t mon3_no_sysfs)${NC}"
    exit 1
fi

read -rp "$(t mon3_prompt_iface)" iface
if [ -z "$iface" ]; then
    iface=$(raqib_default_iface)
fi
if [ -z "$iface" ] || [ ! -d "/sys/class/net/$iface" ]; then
    echo -e "${RED}$(t mon3_iface_not_found)${NC}"
    ls /sys/class/net/
    exit 1
fi

echo -e "${YELLOW}$(tf mon3_monitoring "$iface")${NC}"
rx1=$(cat /sys/class/net/"$iface"/statistics/rx_bytes)
tx1=$(cat /sys/class/net/"$iface"/statistics/tx_bytes)
for i in $(seq 1 10); do
    sleep 1
    rx2=$(cat /sys/class/net/"$iface"/statistics/rx_bytes)
    tx2=$(cat /sys/class/net/"$iface"/statistics/tx_bytes)
    rx_rate=$(( (rx2 - rx1) / 1024 ))
    tx_rate=$(( (tx2 - tx1) / 1024 ))
    printf "\r\033[K"
    echo -e "${GREEN}$(tf mon3_download_upload "$i" "$rx_rate" "$tx_rate")${NC}"
    rx1=$rx2; tx1=$tx2
    draw_progress_bar "$i" 10 "$iface"
done
finish_progress_bar
