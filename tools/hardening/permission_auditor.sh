#!/bin/bash
finding_reset
echo -e "${CYAN}$(t har1_title)${NC}"
read -rp "$(t har1_prompt_dir)" dir
dir=${dir:-/}

echo -e "${YELLOW}$(t har1_s1)${NC}"
ww_files=$(find "$dir" -xdev -type f -perm -0002 2>/dev/null | head -30)
echo "$ww_files"
[ -n "$ww_files" ] && while read -r _; do finding_add high; done <<< "$ww_files"

echo ""
echo -e "${YELLOW}$(t har1_s2)${NC}"
suid_files=$(find "$dir" -xdev -type f -perm -4000 2>/dev/null | head -30)
echo "$suid_files"
[ -n "$suid_files" ] && while read -r _; do finding_add medium; done <<< "$suid_files"

echo ""
echo -e "${YELLOW}$(t har1_s3)${NC}"
sgid_files=$(find "$dir" -xdev -type f -perm -2000 2>/dev/null | head -30)
echo "$sgid_files"
[ -n "$sgid_files" ] && while read -r _; do finding_add medium; done <<< "$sgid_files"

echo ""
echo -e "${YELLOW}$(t har1_s4)${NC}"
ww_dirs=$(find "$dir" -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -30)
echo "$ww_dirs"
[ -n "$ww_dirs" ] && while read -r _; do finding_add high; done <<< "$ww_dirs"

echo ""
echo -e "${GREEN}$(t har1_review_tip)${NC}"

print_executive_summary "$(t har1_title)"
save_report "$(tf har1_report_title "$dir" "$(date)")

$(t har1_s1)
$(find "$dir" -xdev -type f -perm -0002 2>/dev/null | head -30)

$(t har1_s2)
$(find "$dir" -xdev -type f -perm -4000 2>/dev/null | head -30)

$(t har1_s3)
$(find "$dir" -xdev -type f -perm -2000 2>/dev/null | head -30)

$(t har1_s4)
$ww_dirs" "permission_audit_${dir//\//_}.txt" "$(t har1_title)"
