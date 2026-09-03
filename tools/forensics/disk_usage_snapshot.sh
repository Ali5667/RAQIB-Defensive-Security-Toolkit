#!/bin/bash
echo -e "${CYAN}$(t for4_title)${NC}"
read -rp "$(t for4_prompt_dir)" dir
dir=${dir:-/}

SNAP_DIR="$HOME/.raqib_disk_snapshots"
mkdir -p "$SNAP_DIR"
safe_name=$(echo "$dir" | tr '/' '_')
SNAPFILE="$SNAP_DIR/snap_${safe_name}.txt"

current=$(du -ah --max-depth=2 "$dir" 2>/dev/null | sort -rh | head -30)

if [ ! -f "$SNAPFILE" ]; then
    echo "$current" > "$SNAPFILE"
    echo -e "${GREEN}$(tf for4_baseline_saved "$dir")${NC}"
    echo "$current"
    exit 0
fi

echo -e "${YELLOW}$(t for4_prev_vs_current)${NC}"
echo -e "${CYAN}$(t for4_previous)${NC}"
cat "$SNAPFILE"
echo ""
echo -e "${CYAN}$(t for4_current)${NC}"
echo "$current"

read -rp "$(t c_confirm_update_baseline)" ans
[ "$ans" = "y" ] && echo "$current" > "$SNAPFILE" && echo -e "${GREEN}$(t c_updated)${NC}"
