#!/bin/bash
# telegram_setup.sh
# يضبط بوت تيليجرام لتنبيهات فورية — الخطوات مع @BotFather خارجية (المستخدم
# يسويها بنفسه بتطبيق تيليجرام)، هذي الأداة بس تحفظ التوكن والـchat id
# وتختبر الاتصال فعلياً قبل ما تأكد الإعداد نجح.

echo -e "${CYAN}$(t tgs_title)${NC}"
echo -e "${GREY}$(t tgs_disclaimer)${NC}"
echo ""

if raqib_telegram_configured; then
    echo -e "${GREEN}$(t tgs_already_configured)${NC}"
    read -rp "$(t tgs_reconfigure_prompt)" reconf
    [ "$reconf" != "y" ] && exit 0
    echo ""
fi

echo -e "${YELLOW}$(t tgs_step1)${NC}"
echo -e "${YELLOW}$(t tgs_step2)${NC}"
echo -e "${YELLOW}$(t tgs_step3)${NC}"
echo ""

read -rp "$(t tgs_prompt_token)" bot_token
[ -z "$bot_token" ] && { echo -e "${RED}$(t tgs_cancelled)${NC}"; exit 1; }
read -rp "$(t tgs_prompt_chatid)" chat_id
[ -z "$chat_id" ] && { echo -e "${RED}$(t tgs_cancelled)${NC}"; exit 1; }

printf 'BOT_TOKEN=%s\nCHAT_ID=%s\n' "$bot_token" "$chat_id" > "$RAQIB_TELEGRAM_CONF"
chmod 600 "$RAQIB_TELEGRAM_CONF" 2>/dev/null

echo ""
echo -e "${CYAN}$(t tgs_testing)${NC}"
if raqib_telegram_notify "$(t tgs_test_message)"; then
    sleep 1
    echo -e "${GREEN}$(t tgs_test_sent)${NC}"
else
    echo -e "${RED}$(t tgs_test_failed)${NC}"
fi
