#!/bin/bash
source "$MODULES_DIR/common.sh"

menu_hardening() {
    while true; do
        show_banner
        show_tool_list "$(t cat6)" \
            "$(t h1)" \
            "$(t h2)" \
            "$(t h3)" \
            "$(t h4)" \
            "$(t h5)" \
            "$(t h6)"
        read -rp "  $(t choice_label)" c
        case $c in
            1) run_tool "$TOOLS_DIR/hardening/permission_auditor.sh" ;;
            2) run_tool "$TOOLS_DIR/hardening/ssh_config_auditor.sh" ;;
            3) run_tool "$TOOLS_DIR/hardening/service_lister.sh" ;;
            4) run_tool "$TOOLS_DIR/hardening/password_policy_checker.sh" ;;
            5) run_tool "$TOOLS_DIR/hardening/firewall_status_checker.sh" ;;
            6) run_tool "$TOOLS_DIR/hardening/report_decryptor.sh" ;;
            0) return ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1; continue ;;
        esac
        pause
    done
}
