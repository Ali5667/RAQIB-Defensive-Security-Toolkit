#!/bin/bash
# siem_correlator.sh
# أصغر جزء حقيقي مفيد من عمل أي منتج SIEM: ربط الأحداث (correlation) +
# تصدير بصيغة قياسية (CEF) تقدر أي منصة SIEM حقيقية (Wazuh, ELK/Logstash,
# Splunk) تستوردها مباشرة. يقرأ سجل الأحداث المنظّم (.raqib_events.jsonl)
# اللي تولّده تلقائياً كل الأدوات الموجودة أصلاً بالمشروع (عبر finding_add).
#
# قاعدة الربط المطبّقة (مبسّطة، بس نفس المبدأ اللي تستخدمه أي SIEM حقيقي):
#   "لو 3 أدوات مختلفة أو أكثر سجّلت ملاحظة medium+ خلال نافذة زمنية واحدة،
#    هذا مؤشر على حادثة مركّبة (متعددة الأعراض) وليس ملاحظة معزولة"
#
# The smallest genuinely useful slice of what a SIEM does: event
# correlation + export in a standard format (CEF) any real SIEM platform
# can ingest directly. Reads the structured event log that every existing
# tool in the project already emits automatically via finding_add.

echo -e "${CYAN}$(t sc_title)${NC}"
echo -e "${GREY}$(t sc_disclaimer)${NC}"
echo ""

if [ ! -s "$RAQIB_EVENTS_FILE" ]; then
    echo -e "${YELLOW}$(t sc_no_events)${NC}"
    exit 0
fi

read -rp "$(t sc_window_prompt)" window_min
[[ "$window_min" =~ ^[0-9]+$ ]] || window_min=60

CORR_JSON=$(python3 "$TOOLS_DIR/monitoring/raqib_correlate.py" "$RAQIB_EVENTS_FILE" "$window_min")

PARSED=$(python3 - "$CORR_JSON" << 'PYEOF'
import sys, json
d = json.loads(sys.argv[1])
print(f"TOTAL_EVENTS={d['total_events']}")
print(f"RELEVANT_EVENTS={d['relevant_events']}")
print(f"INCIDENT_COUNT={d['incident_count']}")
for inc in d["incidents"]:
    t = inc["type"]
    if t == "multi_tool":
        print("MULTI|" + "|".join([inc["start"], inc["end"], str(inc["count"]),
              inc["top_severity"], ",".join(inc["tools"])]))
    elif t == "repeat_critical":
        print("REPEAT|" + "|".join([inc["tool"], inc["start"], inc["end"],
              str(inc["count"]), inc["severity"]]))
    elif t == "off_hours":
        print("OFFHOURS|" + "|".join([inc["timestamp"], inc["tool"],
              inc["severity"], str(inc["hour_utc"])]))
    elif t == "escalating":
        print("ESCALATE|" + "|".join([inc["start"], inc["end"],
              ",".join(inc["tools"]), ",".join(inc["sequence"])]))
PYEOF
)

total=$(printf '%s\n' "$PARSED" | sed -n 's/^TOTAL_EVENTS=//p')
relevant=$(printf '%s\n' "$PARSED" | sed -n 's/^RELEVANT_EVENTS=//p')
inc_count=$(printf '%s\n' "$PARSED" | sed -n 's/^INCIDENT_COUNT=//p')

echo -e "${YELLOW}$(tf sc_stats "$total" "$relevant")${NC}"
echo ""

if [ "${inc_count:-0}" -eq 0 ]; then
    echo -e "${GREEN}$(t sc_no_incidents)${NC}"
else
    echo -e "${BOLD}${CRIMSON}$(tf sc_incidents_found "$inc_count")${NC}"
    echo ""
    n=0
    while IFS='|' read -r kind a b c d2 e; do
        n=$((n + 1))
        case "$kind" in
            MULTI)
                echo -e "${ORANGE}$(t sc_incident_label) #$n${NC} — $(t sc_rule_multi_tool)  [$a → $b]"
                echo -e "  $(t sc_top_severity): $(_raqib_sev_badge "$d2")"
                echo -e "  $(t sc_involved_tools): $e"
                echo -e "  $(t sc_event_count): $c"
                ;;
            REPEAT)
                echo -e "${ORANGE}$(t sc_incident_label) #$n${NC} — $(t sc_rule_repeat)  [$b → $c]"
                echo -e "  $(t sc_tool_label): $a"
                echo -e "  $(t sc_top_severity): $(_raqib_sev_badge "$e")"
                echo -e "  $(t sc_event_count): $d2"
                ;;
            OFFHOURS)
                echo -e "${ORANGE}$(t sc_incident_label) #$n${NC} — $(t sc_rule_off_hours)  [$a UTC]"
                echo -e "  $(t sc_tool_label): $b"
                echo -e "  $(t sc_top_severity): $(_raqib_sev_badge "$c")"
                ;;
            ESCALATE)
                echo -e "${ORANGE}$(t sc_incident_label) #$n${NC} — $(t sc_rule_escalating)  [$a → $b]"
                echo -e "  $(t sc_involved_tools): $c"
                echo -e "  $(t sc_severity_sequence): $d2"
                ;;
        esac
        echo ""
    done < <(printf '%s\n' "$PARSED" | grep -E '^(MULTI|REPEAT|OFFHOURS|ESCALATE)\|')
fi

echo ""
read -rp "$(t sc_export_prompt)" export_ans
if [ "$export_ans" = "y" ] || [ "$export_ans" = "Y" ]; then
    export_file="$SCRIPT_DIR/raqib_events_export_$(date +%Y%m%d_%H%M%S).cef"
    python3 - "$RAQIB_EVENTS_FILE" "$export_file" << 'PYEOF'
import sys, json

src, dst = sys.argv[1], sys.argv[2]
sev_num = {"critical": 10, "high": 8, "medium": 5, "low": 2}
with open(src, encoding="utf-8") as f, open(dst, "w", encoding="utf-8") as out:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        name = (e.get("message") or e.get("tool", "event")).replace("|", "/")
        cef = (
            f"CEF:0|RAQIB|RAQIB-Defensive-Security-Toolkit|1.0|"
            f"{e.get('tool','unknown')}|{name}|"
            f"{sev_num.get(e.get('severity','low'), 2)}|"
            f"rt={e.get('timestamp','')} dvchost={e.get('host','')} "
            f"cs1={e.get('tool','')} cs1Label=RaqibTool"
        )
        out.write(cef + "\n")
PYEOF
    echo -e "${GREEN}$(tf sc_exported "$export_file")${NC}"
    echo -e "${GREY}$(t sc_export_note)${NC}"
fi
