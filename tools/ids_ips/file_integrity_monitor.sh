#!/bin/bash
echo -e "${CYAN}$(t ids3_title)${NC}"
read -rp "$(t ids3_prompt_dir)" dir
[ ! -d "$dir" ] && { echo -e "${RED}$(t c_dir_not_found)${NC}"; exit 1; }

DB_DIR="$HOME/.raqib_fim"
mkdir -p "$DB_DIR"
safe_name=$(echo "$dir" | tr '/' '_')
BASELINE="$DB_DIR/baseline_${safe_name}.txt"

capture_hashes() {
    find "$dir" -type f -print0 2>/dev/null | while IFS= read -r -d '' f; do
        h=$(raqib_hash sha256 "$f")
        [ -n "$h" ] && printf '%s  %s\n' "$h" "$f"
    done | sort
}

if [ ! -f "$BASELINE" ]; then
    capture_hashes > "$BASELINE"
    echo -e "${GREEN}$(tf ids3_baseline_created "$dir")${NC}"
    echo -e "${YELLOW}$(tf ids3_files_recorded "$(wc -l < "$BASELINE")")${NC}"
    exit 0
fi

current=$(capture_hashes)
echo -e "${YELLOW}$(t ids3_comparing)${NC}"
diff_out=$(diff <(cat "$BASELINE") <(echo "$current"))

if [ -z "$diff_out" ]; then
    echo -e "${GREEN}$(t ids3_no_change)${NC}"
else
    echo -e "${RED}$(t ids3_changes_detected)${NC}"
    echo "$diff_out"
fi

read -rp "$(t c_confirm_update_baseline)" ans
[ "$ans" = "y" ] && echo "$current" > "$BASELINE" && echo -e "${GREEN}$(t c_updated)${NC}"
