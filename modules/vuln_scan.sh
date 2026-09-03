#!/bin/bash
source "$MODULES_DIR/common.sh"

menu_vuln_scan() {
    while true; do
        show_banner
        show_tool_list "$(t cat7)" \
            "$(t v1)" \
            "$(t v2)" \
            "$(t v3)" \
            "$(t v4)" \
            "$(t v5)"
        read -rp "  $(t choice_label)" c
        case $c in
            1) run_tool "$TOOLS_DIR/vuln_scan/open_ports_vs_services.sh" ;;
            2) run_tool "$TOOLS_DIR/vuln_scan/outdated_packages_checker.sh" ;;
            3) run_tool "$TOOLS_DIR/vuln_scan/weak_permission_scanner.sh" ;;
            4) run_tool "$TOOLS_DIR/vuln_scan/ssl_cert_checker.sh" ;;
            5) run_tool "$TOOLS_DIR/vuln_scan/default_credentials_scanner.sh" ;;
            0) return ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1; continue ;;
        esac
        pause
    done
}
