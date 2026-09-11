#!/bin/bash
source "$MODULES_DIR/common.sh"

menu_monitoring() {
    while true; do
        show_banner
        show_tool_list "$(t cat1)" \
            "$(t m1)" \
            "$(t m2)" \
            "$(t m3)" \
            "$(t m4)" \
            "$(t m5)" \
            "$(t m6)" \
            "$(t m7)" \
            "$(t m8)" \
            "$(t m9)" \
            "$(t m10)" \
            "$(t m11)" \
            "$(t m12)"
        read -rp "  $(t choice_label)" c
        case $c in
            1) run_tool "$TOOLS_DIR/monitoring/port_scanner.sh" ;;
            2) run_tool "$TOOLS_DIR/monitoring/active_connections.sh" ;;
            3) run_tool "$TOOLS_DIR/monitoring/bandwidth_monitor.sh" ;;
            4) run_tool "$TOOLS_DIR/monitoring/arp_watch.sh" ;;
            5) run_tool "$TOOLS_DIR/monitoring/dns_lookup_tool.sh" ;;
            6) run_tool "$TOOLS_DIR/monitoring/ping_sweep.sh" ;;
            7) run_tool "$TOOLS_DIR/monitoring/siem_correlator.sh" ;;
            8) run_tool "$TOOLS_DIR/monitoring/telegram_setup.sh" ;;
            9) run_tool "$TOOLS_DIR/monitoring/dashboard_generator.sh" ;;
            10) run_tool "$TOOLS_DIR/monitoring/watchdog_setup.sh" ;;
            11) run_tool "$TOOLS_DIR/monitoring/raqib_collector_server.sh" ;;
            12) run_tool "$TOOLS_DIR/monitoring/collector_client_setup.sh" ;;
            0) return ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1; continue ;;
        esac
        pause
    done
}
