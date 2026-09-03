#!/bin/bash
echo -e "${CYAN}$(t for3_title)${NC}"
read -rp "$(t for3_prompt_dir)" dir
[ ! -d "$dir" ] && { echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1; }
read -rp "$(t for3_prompt_days)" days
days=${days:-1}
if ! [[ "$days" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}$(t c_value_must_be_number)${NC}"; exit 1
fi

echo -e "${YELLOW}$(tf for3_modified_files "$days")${NC}"
mtime_list=$(find "$dir" -type f -mtime -"$days" -printf '%T@ %TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | \
    sort -rn | cut -d' ' -f2- | head -50)
echo "$mtime_list"

echo ""
echo -e "${YELLOW}$(t for3_perm_changed)${NC}"
ctime_list=$(find "$dir" -type f -ctime -"$days" -printf '%C@ %CY-%Cm-%Cd %CH:%CM  %p\n' 2>/dev/null | \
    sort -rn | cut -d' ' -f2- | head -50)
echo "$ctime_list"

save_report "$(tf for3_report_title "$dir" "$days")

$(t for3_content_mod)
$mtime_list

$(t for3_perm_own_change)
$ctime_list" "filesystem_timeline.txt"
