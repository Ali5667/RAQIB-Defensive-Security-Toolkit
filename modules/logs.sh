#!/bin/bash
source "$MODULES_DIR/common.sh"

menu_logs() {
    while true; do
        show_banner
        show_tool_list "$(t cat2)" \
            "$(t l1)" \
            "$(t l2)" \
            "$(t l3)" \
            "$(t l4)" \
            "$(t l5)"
        read -rp "  $(t choice_label)" c
        case $c in
            1) run_tool "$TOOLS_DIR/logs/failed_ssh_report.sh" ;;
            2) run_tool "$TOOLS_DIR/logs/log_keyword_search.sh" ;;
            3) run_tool "$TOOLS_DIR/logs/top_error_lines.sh" ;;
            4) run_tool "$TOOLS_DIR/logs/log_timeline.sh" ;;
            5) run_tool "$TOOLS_DIR/logs/web_access_analyzer.sh" ;;
            0) return ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1; continue ;;
        esac
        pause
    done
}
