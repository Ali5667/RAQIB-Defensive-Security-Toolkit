#!/bin/bash
finding_reset
echo -e "${CYAN}$(t vul3_title)${NC}"
read -rp "$(t vul3_prompt_dir)" dir
[ ! -d "$dir" ] && { echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1; }

echo -e "${YELLOW}$(t vul3_wide_open)${NC}"
wide_open=$(find "$dir" -type f \( -perm 0777 -o -perm 0666 \) 2>/dev/null | head -30)
echo "$wide_open"
[ -n "$wide_open" ] && while read -r _; do finding_add critical; done <<< "$wide_open"

echo ""
echo -e "${YELLOW}$(t vul3_ssh_keys)${NC}"
find "$dir" -type f \( -name "id_rsa" -o -name "*.pem" -o -name "*.key" \) 2>/dev/null | while read -r f; do
    perm=$(raqib_stat_perm "$f")
    if [ "$perm" != "600" ] && [ "$perm" != "400" ]; then
        echo -e "${RED}$(tf vul3_key_perm_warn "$f" "$perm")${NC}"
    fi
done
key_warnings=$(find "$dir" -type f \( -name "id_rsa" -o -name "*.pem" -o -name "*.key" \) 2>/dev/null | while read -r f; do
    perm=$(raqib_stat_perm "$f")
    [ "$perm" != "600" ] && [ "$perm" != "400" ] && echo "$f"
done)
[ -n "$key_warnings" ] && while read -r _; do finding_add high; done <<< "$key_warnings"

echo ""
echo -e "${YELLOW}$(t vul3_config_secrets)${NC}"
exposed_conf=$(find "$dir" -type f \( -name "*.env" -o -name "config.php" -o -name "*.conf" \) -perm -0004 2>/dev/null | head -30)
echo "$exposed_conf"
[ -n "$exposed_conf" ] && while read -r _; do finding_add medium; done <<< "$exposed_conf"

print_executive_summary "$(t vul3_title)"
