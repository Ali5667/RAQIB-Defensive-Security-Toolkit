#!/bin/bash
# pending_actions_review.sh
# يعرض كل الطلبات المعلّقة (اللي سوّتها أدوات ثانية عبر raqib_request_approval
# بدل ما تنفّذ مباشرة) ويسمح بمراجعتها والموافقة/الرفض قبل أي تنفيذ فعلي.

echo -e "${CYAN}$(t par_title)${NC}"
echo -e "${GREY}$(t par_disclaimer)${NC}"
echo ""

if [ "${RAQIB_OPERATOR_ROLE:-analyst}" != "senior" ]; then
    echo -e "${RED}$(t par_rbac_denied)${NC}"
    exit 1
fi

if [ ! -s "$RAQIB_PENDING_FILE" ]; then
    echo -e "${GREEN}$(t par_none)${NC}"
    exit 0
fi

# نطبع بس آخر حالة لكل id (لو نفس id تكرر بالملف بسبب تحديث الحالة)، وبس
# الطلبات اللي لسا pending، بصيغة سطر واحد مفصول بـ| لكل طلب
PENDING_ROWS=$(python3 - "$RAQIB_PENDING_FILE" << 'PYEOF'
import json, sys

latest = {}
with open(sys.argv[1], encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        latest[e["id"]] = e

for e in latest.values():
    if e.get("status") != "pending":
        continue
    row = "|".join([
        e["id"], e["timestamp"], e.get("requested_by", "unknown"),
        e.get("action", ""), e.get("target", ""),
        e.get("details", "").replace("|", "/").replace("\n", " "),
        e.get("exec_cmd", "").replace("|", "/"),
    ])
    print(row)
PYEOF
)

if [ -z "$PENDING_ROWS" ]; then
    echo -e "${GREEN}$(t par_none)${NC}"
    exit 0
fi

# دالة تحدّث حالة طلب معيّن بالملف (تُلحق سطر جديد بنفس الـid وحالة جديدة —
# نفس نمط append-only اللي يستخدمه سجل الأحداث، أبسط وأأمن من إعادة الكتابة)
update_status() {
    local id="$1" new_status="$2" reviewer="$3"
    python3 - "$RAQIB_PENDING_FILE" "$id" "$new_status" "$reviewer" << 'PYEOF'
import json, sys, datetime

path, id_, status, reviewer = sys.argv[1:5]
latest = None
with open(path, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        e = json.loads(line)
        if e["id"] == id_:
            latest = e

if latest:
    latest["status"] = status
    latest["reviewed_by"] = reviewer
    latest["reviewed_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(latest, ensure_ascii=False) + "\n")
PYEOF
}

n=0
while IFS='|' read -r -u 3 id ts req_by action target details exec_cmd; do
    n=$((n + 1))
    echo -e "${ORANGE}#$n${NC} [$id]  —  $ts"
    echo -e "  $(t par_requested_by): $req_by"
    echo -e "  $(t par_action): $action  ($target)"
    echo -e "  $(t par_details): $details"
    if [ "$req_by" = "${RAQIB_OPERATOR:-unknown}" ]; then
        echo -e "  ${YELLOW}$(t par_self_warning)${NC}"
    fi
    read -rp "$(t par_decision_prompt)" decision
    case "$decision" in
        a|A)
            if bash -c "$exec_cmd"; then
                update_status "$id" "approved" "${RAQIB_OPERATOR:-unknown}"
                echo -e "${GREEN}$(t par_approved_executed)${NC}"
                finding_add low "$(tf par_log_approved "$id" "$req_by")"
            else
                update_status "$id" "failed" "${RAQIB_OPERATOR:-unknown}"
                echo -e "${RED}$(t par_exec_failed)${NC}"
            fi
            ;;
        r|R)
            update_status "$id" "rejected" "${RAQIB_OPERATOR:-unknown}"
            echo -e "${YELLOW}$(t par_rejected)${NC}"
            finding_add low "$(tf par_log_rejected "$id" "$req_by")"
            ;;
        *)
            echo -e "${GREY}$(t par_skipped)${NC}"
            ;;
    esac
    echo ""
done 3<<< "$PENDING_ROWS"
