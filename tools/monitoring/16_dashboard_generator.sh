#!/bin/bash
# dashboard_generator.sh
# يبني لوحة تحكم HTML واحدة مستقلة (self-contained) — كل البيانات مضمّنة
# جوا الملف نفسه (JSON inline + JS خام بدون مكتبات خارجية)، فتفتحها بأي
# متصفح حتى بدون إنترنت. تعرض: إحصائيات عامة، توزيع حسب الأداة والخطورة،
# الخط الزمني، والحوادث المركّبة (نفس محرك raqib_correlate.py المشترك).

echo -e "${CYAN}$(t dash_title)${NC}"
echo -e "${GREY}$(t dash_disclaimer)${NC}"
echo ""

if [ ! -s "$RAQIB_EVENTS_FILE" ]; then
    echo -e "${YELLOW}$(t sc_no_events)${NC}"
    exit 0
fi

PAYLOAD=$(python3 - "$RAQIB_EVENTS_FILE" "$TOOLS_DIR/monitoring/raqib_correlate.py" << 'PYEOF'
import sys, json, subprocess, collections

events_path, correlate_script = sys.argv[1], sys.argv[2]

events = []
with open(events_path, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except Exception:
            continue

by_severity = collections.Counter(e.get("severity", "low") for e in events)
by_tool = collections.Counter(e.get("tool", "unknown") for e in events)
by_hour = collections.Counter(e.get("timestamp", "")[:13] for e in events if e.get("timestamp"))

corr_raw = subprocess.run(
    ["python3", correlate_script, events_path, "60"],
    capture_output=True, text=True
).stdout
try:
    corr = json.loads(corr_raw)
except Exception:
    corr = {"incidents": [], "total_events": len(events), "relevant_events": 0}

payload = {
    "generated_at": events[-1].get("timestamp", "") if events else "",
    "total_events": len(events),
    "by_severity": dict(by_severity),
    "by_tool": dict(by_tool.most_common(15)),
    "by_hour": dict(sorted(by_hour.items())),
    "incidents": corr.get("incidents", []),
    "events_tail": events[-100:],
}
print(json.dumps(payload, ensure_ascii=False))
PYEOF
)

if [ -z "$PAYLOAD" ]; then
    echo -e "${RED}$(t dash_gen_failed)${NC}"
    exit 1
fi

out_default="$SCRIPT_DIR/raqib_dashboard_$(date +%Y%m%d_%H%M%S).html"
read -rp "$(tf dash_output_prompt "$out_default")" out_path
out_path="${out_path:-$out_default}"
case "$out_path" in
    "~") out_path="$HOME" ;;
    "~/"*) out_path="$HOME/${out_path#\~/}" ;;
esac
[ -d "$out_path" ] && out_path="${out_path%/}/raqib_dashboard_$(date +%Y%m%d_%H%M%S).html"

python3 - "$PAYLOAD" "$out_path" << 'PYEOF'
import sys, json

payload_json, out_path = sys.argv[1], sys.argv[2]

html = """<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RAQIB — لوحة التحكم</title>
<style>
  :root {
    --bg: #0b0f14; --panel: #131a22; --border: #223140;
    --cyan: #22d3ee; --purple: #a78bfa; --text: #e6edf3; --muted: #8b98a5;
    --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #22c55e;
  }
  * { box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text); font-family: 'Segoe UI', Tahoma, sans-serif;
    margin: 0; padding: 20px;
  }
  h1 { color: var(--cyan); font-size: 1.4rem; margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: .85rem; margin-bottom: 20px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 16px; text-align: center;
  }
  .card .num { font-size: 1.8rem; font-weight: 700; }
  .card .label { color: var(--muted); font-size: .8rem; margin-top: 4px; }
  .crit .num { color: var(--crit); } .high .num { color: var(--high); }
  .med .num { color: var(--med); } .low .num { color: var(--low); }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 18px; margin-bottom: 20px; }
  .panel h2 { font-size: 1rem; color: var(--purple); margin: 0 0 14px; }
  .bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; font-size: .85rem; }
  .bar-label { width: 160px; flex-shrink: 0; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { flex: 1; background: #0b0f14; border-radius: 6px; overflow: hidden; height: 18px; }
  .bar-fill { height: 100%; background: linear-gradient(90deg, var(--cyan), var(--purple)); border-radius: 6px; }
  .bar-val { width: 40px; text-align: left; color: var(--text); font-size: .8rem; }
  .incident {
    border-right: 4px solid var(--high); background: #0e141b; border-radius: 8px;
    padding: 12px 14px; margin-bottom: 10px; font-size: .85rem;
  }
  .incident.crit { border-color: var(--crit); }
  .incident .itype { color: var(--cyan); font-weight: 600; }
  .incident .imeta { color: var(--muted); margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: .78rem; }
  th, td { padding: 6px 8px; border-bottom: 1px solid var(--border); text-align: right; }
  th { color: var(--muted); font-weight: 500; }
  .sev-badge { padding: 2px 8px; border-radius: 6px; font-size: .72rem; font-weight: 600; }
  .sev-critical { background: rgba(239,68,68,.15); color: var(--crit); }
  .sev-high { background: rgba(249,115,22,.15); color: var(--high); }
  .sev-medium { background: rgba(234,179,8,.15); color: var(--med); }
  .sev-low { background: rgba(34,197,94,.15); color: var(--low); }
  .empty { color: var(--muted); font-size: .85rem; text-align: center; padding: 20px; }
</style>
</head>
<body>
  <h1>🦅 RAQIB — لوحة التحكم</h1>
  <div class="sub" id="genTime"></div>

  <div class="grid" id="summaryCards"></div>

  <div class="panel">
    <h2>الحوادث المركّبة (Correlated Incidents)</h2>
    <div id="incidentsList"></div>
  </div>

  <div class="panel">
    <h2>التوزيع حسب الأداة</h2>
    <div id="byToolChart"></div>
  </div>

  <div class="panel">
    <h2>آخر الأحداث</h2>
    <table>
      <thead><tr><th>الوقت</th><th>الأداة</th><th>الخطورة</th><th>الرسالة</th></tr></thead>
      <tbody id="eventsTable"></tbody>
    </table>
  </div>

<script>
const DATA = __PAYLOAD__;

const sevLabel = {critical: "حرج", high: "عالي", medium: "متوسط", low: "منخفض"};
const typeLabel = {
  multi_tool: "حادثة مركّبة (أدوات متعددة)",
  repeat_critical: "نمط متكرر",
  off_hours: "نشاط بساعات غير معتادة",
  escalating: "نمط تصاعدي"
};

document.getElementById('genTime').textContent =
  "آخر تحديث: " + (DATA.generated_at || "-") + " | إجمالي الأحداث: " + DATA.total_events;

// summary cards
const sevOrder = ["critical", "high", "medium", "low"];
const cardsHtml = sevOrder.map(s =>
  `<div class="card ${s === 'critical' ? 'crit' : s}"><div class="num">${DATA.by_severity[s] || 0}</div><div class="label">${sevLabel[s]}</div></div>`
).join("");
document.getElementById('summaryCards').innerHTML = cardsHtml;

// incidents
const incidents = DATA.incidents || [];
if (incidents.length === 0) {
  document.getElementById('incidentsList').innerHTML = '<div class="empty">ما فيه حوادث مركّبة مكتشفة</div>';
} else {
  document.getElementById('incidentsList').innerHTML = incidents.map(inc => {
    const isCrit = (inc.top_severity === 'critical' || inc.severity === 'critical');
    const tools = inc.tools ? inc.tools.join(', ') : (inc.tool || '-');
    const time = inc.start || inc.timestamp || '-';
    return `<div class="incident ${isCrit ? 'crit' : ''}">
      <div class="itype">${typeLabel[inc.type] || inc.type}</div>
      <div class="imeta">🕒 ${time} | الأدوات: ${tools}</div>
    </div>`;
  }).join("");
}

// by tool bar chart
const toolEntries = Object.entries(DATA.by_tool || {}).sort((a,b) => b[1]-a[1]);
const maxToolVal = Math.max(1, ...toolEntries.map(e => e[1]));
document.getElementById('byToolChart').innerHTML = toolEntries.map(([tool, count]) => `
  <div class="bar-row">
    <div class="bar-label">${tool}</div>
    <div class="bar-track"><div class="bar-fill" style="width:${(count/maxToolVal*100).toFixed(0)}%"></div></div>
    <div class="bar-val">${count}</div>
  </div>
`).join("") || '<div class="empty">ما فيه بيانات</div>';

// events table (latest first)
const events = (DATA.events_tail || []).slice().reverse();
document.getElementById('eventsTable').innerHTML = events.map(e => `
  <tr>
    <td>${e.timestamp || '-'}</td>
    <td>${e.tool || '-'}</td>
    <td><span class="sev-badge sev-${e.severity}">${sevLabel[e.severity] || e.severity}</span></td>
    <td>${(e.message || '').replace(/</g,'&lt;')}</td>
  </tr>
`).join("") || '<tr><td colspan="4" class="empty">ما فيه أحداث</td></tr>';
</script>
</body>
</html>
"""

with open(out_path, "w", encoding="utf-8") as f:
    f.write(html.replace("__PAYLOAD__", payload_json))

print(out_path)
PYEOF

if [ -f "$out_path" ]; then
    abs_path=$(raqib_realpath "$out_path" 2>/dev/null) || abs_path="$out_path"
    echo ""
    echo -e "${GREEN}$(tf dash_saved "$abs_path")${NC}"
    echo -e "${GREY}$(t dash_open_hint)${NC}"
else
    echo -e "${RED}$(t dash_gen_failed)${NC}"
fi
