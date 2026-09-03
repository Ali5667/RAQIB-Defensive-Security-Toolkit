#!/bin/bash
echo -e "${CYAN}$(t ids4_title)${NC}"

echo -e "${YELLOW}$(t ids4_user_cron)${NC}"
crontab -l 2>/dev/null || echo "$(t ids4_none)"

echo ""
echo -e "${YELLOW}$(t ids4_system_cron)${NC}"
for f in /etc/crontab /etc/cron.d/*; do
    [ -f "$f" ] && echo -e "${CYAN}--- $f ---${NC}" && grep -vE '^\s*#|^\s*$' "$f" 2>/dev/null
done

echo ""
echo -e "${YELLOW}$(t ids4_all_users_cron)${NC}"
if [ -d /var/spool/cron/crontabs ]; then
    for userfile in /var/spool/cron/crontabs/*; do
        [ -f "$userfile" ] && echo -e "${CYAN}--- $(basename "$userfile") ---${NC}" && cat "$userfile" 2>/dev/null
    done
fi

echo ""
echo -e "${YELLOW}$(t ids4_recent_files)${NC}"
recent=$(find /etc/cron* /var/spool/cron -type f -mtime -7 2>/dev/null)
echo "$recent"

if [ -n "$recent" ]; then
    save_report "$(t ids4_recent_files)
$recent" "cron_audit_recent.txt"
fi
