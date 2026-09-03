#!/bin/bash
source "$MODULES_DIR/common.sh"

menu_ids_ips() {
    while true; do
        show_banner
        show_tool_list "$(t cat3)" \
            "$(t i1)" \
            "$(t i2)" \
            "$(t i3)" \
            "$(t i4)" \
            "$(t i5)" \
            "$(t i6)"
        read -rp "  $(t choice_label)" c
        case $c in
            1) run_tool "$TOOLS_DIR/ids_ips/bruteforce_detector.sh" ;;
            2) run_tool "$TOOLS_DIR/ids_ips/listening_ports_auditor.sh" ;;
            3) run_tool "$TOOLS_DIR/ids_ips/file_integrity_monitor.sh" ;;
            4) run_tool "$TOOLS_DIR/ids_ips/cron_auditor.sh" ;;
            5) run_tool "$TOOLS_DIR/ids_ips/connection_rate_watcher.sh" ;;
            6) run_tool "$TOOLS_DIR/ids_ips/ip_blocker.sh" ;;
            0) return ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1; continue ;;
        esac
        pause
    done
}
