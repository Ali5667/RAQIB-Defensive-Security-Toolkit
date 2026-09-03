#!/bin/bash
source "$MODULES_DIR/common.sh"

menu_forensics() {
    while true; do
        show_banner
        show_tool_list "$(t cat5)" \
            "$(t f1)" \
            "$(t f2)" \
            "$(t f3)" \
            "$(t f4)" \
            "$(t f5)"
        read -rp "  $(t choice_label)" c
        case $c in
            1) run_tool "$TOOLS_DIR/forensics/login_history_report.sh" ;;
            2) run_tool "$TOOLS_DIR/forensics/bash_history_reviewer.sh" ;;
            3) run_tool "$TOOLS_DIR/forensics/filesystem_timeline.sh" ;;
            4) run_tool "$TOOLS_DIR/forensics/disk_usage_snapshot.sh" ;;
            5) run_tool "$TOOLS_DIR/forensics/sudo_log_reviewer.sh" ;;
            0) return ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1; continue ;;
        esac
        pause
    done
}
