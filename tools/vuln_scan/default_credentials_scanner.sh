#!/bin/bash
finding_reset
echo -e "${CYAN}$(t vul5_title)${NC}"
read -rp "$(t vul5_prompt_dir)" dir
[ ! -d "$dir" ] && { echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1; }

PATTERNS='password\s*=\s*["'"'"']?(admin|password|123456|root|changeme|test)["'"'"']?'
echo -e "${YELLOW}$(t vul5_weak_pw)${NC}"
weak_pw=$(grep -riInE "$PATTERNS" "$dir" --include="*.env" --include="*.conf" --include="*.config" \
    --include="*.php" --include="*.yml" --include="*.yaml" --include="*.json" 2>/dev/null | head -30)
echo "$weak_pw"
[ -n "$weak_pw" ] && while read -r _; do finding_add critical; done <<< "$weak_pw"

echo ""
echo -e "${YELLOW}$(t vul5_hardcoded_secrets)${NC}"
secrets=$(grep -riInE '(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*["'"'"'][A-Za-z0-9_\-]{10,}["'"'"']' \
    "$dir" 2>/dev/null | head -30)
echo "$secrets"
[ -n "$secrets" ] && while read -r _; do finding_add high; done <<< "$secrets"

echo ""
echo -e "${GREEN}$(t vul5_review_now)${NC}"

print_executive_summary "$(t vul5_title)"

if [ -n "$weak_pw" ] || [ -n "$secrets" ]; then
    save_report "$(tf vul5_report_title "$dir" "$(date)")

$(t vul5_weak_pw)
$weak_pw

$(t vul5_hardcoded_secrets)
$secrets" "default_credentials_scan.txt" "$(t vul5_title)"
fi
