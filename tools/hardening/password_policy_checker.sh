#!/bin/bash
finding_reset
echo -e "${CYAN}$(t har4_title)${NC}"

FILE="/etc/login.defs"
if [ -f "$FILE" ]; then
    echo -e "${YELLOW}$(tf har4_from_file "$FILE")${NC}"
    not_specified="$(t har4_not_specified)"
    for key in PASS_MAX_DAYS PASS_MIN_DAYS PASS_MIN_LEN PASS_WARN_AGE; do
        val=$(grep -E "^${key}" "$FILE" | awk '{print $2}')
        echo -e "  $key = ${val:-$not_specified}"
        [ -z "$val" ] && finding_add low
    done
else
    echo -e "${RED}$(tf har4_file_missing "$FILE")${NC}"
    finding_add medium
fi

echo ""
PAM_FILE="/etc/pam.d/common-password"
[ -f "$PAM_FILE" ] || PAM_FILE="/etc/pam.d/system-auth"
if [ -f "$PAM_FILE" ]; then
    echo -e "${YELLOW}$(tf har4_pam_settings "$PAM_FILE")${NC}"
    pam_line=$(grep -i "pam_pwquality\|pam_cracklib" "$PAM_FILE" 2>/dev/null)
    echo "$pam_line"
    [ -z "$pam_line" ] && finding_add medium
else
    echo -e "${YELLOW}$(t har4_pam_not_found)${NC}"
    finding_add medium
fi

echo ""
echo -e "${YELLOW}$(t har4_no_pw_accounts)${NC}"
no_pw=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
if [ -n "$no_pw" ]; then
    echo "$no_pw"
    while read -r _; do finding_add critical; done <<< "$no_pw"
elif [ -r /etc/shadow ]; then
    echo ""
else
    echo "$(t c_needs_root)"
fi

print_executive_summary "$(t har4_title)"
