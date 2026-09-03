#!/bin/bash
finding_reset
echo -e "${CYAN}$(t har2_title)${NC}"
CONFIG="/etc/ssh/sshd_config"
[ -n "$1" ] && CONFIG="$1"
if [ ! -f "$CONFIG" ]; then
    read -rp "$(t har2_prompt_config)" CONFIG
fi
[ ! -f "$CONFIG" ] && { echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1; }

REPORT_LINES=""
check() {
    local key="$1" expected="$2" desc="$3"
    local value
    value=$(grep -iE "^\s*${key}\s+" "$CONFIG" | tail -1 | awk '{print $2}')
    local not_defined="$(t har2_not_defined)"
    local good="$(t har2_good)"
    local preferred
    preferred="$(tf har2_preferred "$expected")"
    local line
    if [ -z "$value" ]; then
        line="[?] $key $not_defined - $desc"
        echo -e "${YELLOW}${line}${NC}"
        finding_add medium
    elif [[ "${value,,}" == "${expected,,}" ]]; then
        line="[+] $key = $value  $good - $desc"
        echo -e "${GREEN}${line}${NC}"
    else
        line="[!] $key = $value  $preferred - $desc"
        echo -e "${RED}${line}${NC}"
        finding_add high
    fi
    REPORT_LINES+="${line}"$'\n'
}

check "PermitRootLogin" "no" "$(t har2_desc_root_login)"
check "PasswordAuthentication" "no" "$(t har2_desc_password_auth)"
check "PermitEmptyPasswords" "no" "$(t har2_desc_empty_pw)"
check "X11Forwarding" "no" "$(t har2_desc_x11)"
check "Protocol" "2" "$(t har2_desc_protocol)"
check "MaxAuthTries" "3" "$(t har2_desc_maxauth)"

print_executive_summary "$(t har2_title)"
save_report "$(tf har2_report_title "$CONFIG" "$(date)")

$REPORT_LINES" "ssh_config_audit.txt" "$(t har2_title)"
