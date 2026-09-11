#!/bin/bash
# audit_log_viewer.sh
# يعرض سجل الأحداث مرتّب حسب المشغّل (operator) — أساس المحاسبة: "مين سوى
# شنو ومتى". يقرأ نفس سجل الأحداث المنظّم (.raqib_events.jsonl) اللي
# تولّده كل الأدوات تلقائياً عبر finding_add، بدون أي تعديل عليها.

echo -e "${CYAN}$(t alv_title)${NC}"
echo -e "${GREY}$(t alv_disclaimer)${NC}"
echo ""

if [ ! -s "$RAQIB_EVENTS_FILE" ]; then
    echo -e "${YELLOW}$(t sc_no_events)${NC}"
    exit 0
fi

echo "1) $(t alv_opt_by_operator)"
echo "2) $(t alv_opt_recent)"
echo "3) $(t alv_opt_pending_actions)"
echo "0) $(t back)"
read -rp "  $(t choice_label)" opt

case "$opt" in
    1)
        echo -e "${YELLOW}$(t alv_by_operator_header)${NC}"
        echo ""
        while IFS='|' read -r _ op total crit high med low; do
            echo -e "${ORANGE}${op}${NC}  — $(tf alv_total_events "$total")"
            echo -e "  🔴 $crit  🟠 $high  🟡 $med  🟢 $low"
            echo ""
        done < <(python3 - "$RAQIB_EVENTS_FILE" << 'PYEOF'
import json, collections, sys
by_op = collections.defaultdict(lambda: collections.Counter())
with open(sys.argv[1], encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        op = e.get("operator", "unknown")
        by_op[op][e.get("severity", "low")] += 1
for op, counts in sorted(by_op.items(), key=lambda kv: -sum(kv[1].values())):
    total = sum(counts.values())
    print(f"OP|{op}|{total}|{counts.get('critical',0)}|{counts.get('high',0)}|{counts.get('medium',0)}|{counts.get('low',0)}")
PYEOF
)
        ;;
    2)
        read -rp "$(t alv_prompt_count)" n
        [[ "$n" =~ ^[0-9]+$ ]] || n=20
        echo -e "${YELLOW}$(tf alv_recent_header "$n")${NC}"
        echo ""
        tail -n "$n" "$RAQIB_EVENTS_FILE" | python3 -c "
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except Exception:
        continue
    print(f\"[{e.get('timestamp','-')}] {e.get('operator','unknown')} @ {e.get('tool','-')} ({e.get('severity','-')}): {e.get('message','')}\")
"
        ;;
    3)
        run_tool "$TOOLS_DIR/hardening/pending_actions_review.sh"
        ;;
    0) exit 0 ;;
    *) echo -e "${RED}$(t invalid_choice)${NC}" ;;
esac
