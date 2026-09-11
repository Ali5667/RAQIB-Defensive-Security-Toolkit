#!/bin/bash
# watchdog_setup.sh
# يولّد ملفي systemd (service + timer) بمسارات مشروعك الفعلية جاهزين
# للتثبيت مباشرة — يخلي دورة raqib_watchdog.sh تشتغل تلقائياً كل فترة
# محددة، تبدأ مع إقلاع النظام، ويعيد تشغيلها systemd تلقائياً لو طاحت.

echo -e "${CYAN}$(t wds_title)${NC}"
echo -e "${GREY}$(t wds_disclaimer)${NC}"
echo ""

read -rp "$(t wds_interval_prompt)" interval_min
[[ "$interval_min" =~ ^[0-9]+$ ]] || interval_min=5

watchdog_script="$TOOLS_DIR/monitoring/raqib_watchdog.sh"
chmod +x "$watchdog_script" 2>/dev/null

out_dir="/tmp/raqib_systemd_units"
mkdir -p "$out_dir"

service_file="$out_dir/raqib-watchdog.service"
timer_file="$out_dir/raqib-watchdog.timer"

cat > "$service_file" << EOF
[Unit]
Description=RAQIB Watchdog — دورة فحص خفيفة (منافذ/اتصالات/ملفات مشبوهة)

[Service]
Type=oneshot
ExecStart=/bin/bash ${watchdog_script}
EOF

cat > "$timer_file" << EOF
[Unit]
Description=يشغّل RAQIB Watchdog كل ${interval_min} دقيقة

[Timer]
OnBootSec=1min
OnUnitActiveSec=${interval_min}min
Unit=raqib-watchdog.service

[Install]
WantedBy=timers.target
EOF

echo -e "${GREEN}$(tf wds_files_generated "$out_dir")${NC}"
echo ""
echo -e "${YELLOW}$(t wds_install_header)${NC}"
echo ""
echo "sudo cp \"$service_file\" \"$timer_file\" /etc/systemd/system/"
echo "sudo systemctl daemon-reload"
echo "sudo systemctl enable --now raqib-watchdog.timer"
echo ""
echo -e "${YELLOW}$(t wds_verify_header)${NC}"
echo ""
echo "systemctl status raqib-watchdog.timer"
echo "journalctl -u raqib-watchdog.service -f"
echo "tail -f \"$SCRIPT_DIR/.raqib_watchdog.log\""
echo ""
echo -e "${YELLOW}$(t wds_stop_header)${NC}"
echo ""
echo "sudo systemctl disable --now raqib-watchdog.timer"
echo ""
echo -e "${GREY}$(t wds_note_sudo)${NC}"
