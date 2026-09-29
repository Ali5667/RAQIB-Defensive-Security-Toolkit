#!/bin/bash
echo -e "${CYAN}$(t mon5_title)${NC}"
echo "$(t mon5_opt_forward)"
echo "$(t mon5_opt_reverse)"
read -rp "$(t choice_label)" opt

case $opt in
    1)
        read -rp "$(t mon5_prompt_domain)" domain
        [ -z "$domain" ] && { echo -e "${RED}$(t mon5_need_domain)${NC}"; exit 1; }
        if command -v getent >/dev/null 2>&1; then
            getent hosts "$domain" || echo -e "${RED}$(t mon5_addr_not_found)${NC}"
        elif command -v python3 >/dev/null 2>&1; then
            python3 -c "import socket,sys;print(socket.gethostbyname(sys.argv[1]))" -- "$domain" 2>/dev/null || \
                echo -e "${RED}$(t mon5_addr_not_found)${NC}"
        else
            echo -e "${RED}$(t mon5_no_tool_available)${NC}"
        fi
        ;;
    2)
        read -rp "$(t mon5_prompt_ip)" ip
        if ! is_valid_ip "$ip"; then
            echo -e "${RED}$(t mon5_invalid_ip)${NC}"; exit 1
        fi
        if command -v python3 >/dev/null 2>&1; then
            # SECURITY FIX: pass $ip and message via sys.argv — never interpolate
            # user-supplied input directly into python3 -c "..." string (code injection).
            no_host_msg="$(t mon5_no_hostname_found)"
            python3 - "$ip" "$no_host_msg" <<'PYEOF'
import socket, sys
ip_addr = sys.argv[1]
no_host = sys.argv[2]
try:
    print(socket.gethostbyaddr(ip_addr))
except Exception as e:
    print(no_host, e)
PYEOF
        else
            echo -e "${RED}$(t mon5_no_python3)${NC}"
        fi
        ;;
    *) echo -e "${RED}$(t invalid_choice)${NC}" ;;
esac
