#!/bin/bash
echo -e "${CYAN}$(t rd_title)${NC}"
read -rp "$(t rd_prompt_file)" enc_file
[ ! -f "$enc_file" ] && { echo -e "${RED}$(t c_file_not_found)${NC}"; exit 1; }

default_out="${enc_file%.enc}"
[ "$default_out" = "$enc_file" ] && default_out="${enc_file}.decrypted"

tmp_out=$(mktemp)
if raqib_decrypt_file "$enc_file" "$tmp_out"; then
    echo -e "${GREEN}$(t rd_decrypt_success)${NC}"

    read -rp "$(t rd_view_prompt)" view_ans
    if [ "$view_ans" = "y" ]; then
        echo ""
        cat "$tmp_out"
        echo ""
    fi

    read -rp "$(tf rd_save_prompt "$default_out")" out_name
    out_name=${out_name:-$default_out}
    cp "$tmp_out" "$out_name"
    echo -e "${GREEN}$(tf c_report_saved "$out_name")${NC}"
else
    echo -e "${RED}$(t rd_decrypt_failed)${NC}"
fi
rm -f "$tmp_out"
