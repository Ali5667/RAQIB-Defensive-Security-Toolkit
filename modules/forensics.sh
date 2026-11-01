#!/bin/bash
source "$MODULES_DIR/common.sh"

# محلل ترويسات البريد أداة بايثون تحتاج مسار ملف — نسأل عنه ثم نمرّره.
# The email analyzer is a Python CLI that needs a file path — prompt, then pass it.
run_email_header_analyzer() {
    local eml
    echo ""
    read -rp "  $(raqib_tr "مسار ملف البريد (.eml): " "Email file path (.eml): ")" eml
    eml="${eml%\"}"; eml="${eml#\"}"
    if [ ! -f "$eml" ]; then
        echo -e "${RED}$(raqib_tr "الملف غير موجود: $eml" "File not found: $eml")${NC}"
        return 1
    fi
    run_tool "$TOOLS_DIR/forensics/email_header_analyzer.py" "$eml"
}

menu_forensics() {
    while true; do
        show_banner
        show_tool_list "$(t cat5)" \
            "$(t f1)" \
            "$(t f2)" \
            "$(t f3)" \
            "$(t f4)" \
            "$(t f5)" \
            "$(raqib_tr "الطب الشرعي المتقدم (ذاكرة/سلالة العمليات/التحقق من الثنائيات)" "Advanced Forensics (memory/process lineage/binary verification)")" \
            "$(raqib_tr "محلل ترويسات البريد (تزييف/تصيد/SPF-DKIM-DMARC)" "Email Header Analyzer (spoofing/phishing/SPF-DKIM-DMARC)")"
        read -rp "  $(t choice_label)" c
        case $c in
            1) run_tool "$TOOLS_DIR/forensics/login_history_report.sh" ;;
            2) run_tool "$TOOLS_DIR/forensics/bash_history_reviewer.sh" ;;
            3) run_tool "$TOOLS_DIR/forensics/filesystem_timeline.sh" ;;
            4) run_tool "$TOOLS_DIR/forensics/disk_usage_snapshot.sh" ;;
            5) run_tool "$TOOLS_DIR/forensics/sudo_log_reviewer.sh" ;;
            6) run_tool "$TOOLS_DIR/forensics/advanced_forensics.sh" ;;
            7) run_email_header_analyzer ;;
            0) return ;;
            *) echo -e "${RED}$(t invalid_choice)${NC}"; sleep 1; continue ;;
        esac
        pause
    done
}
