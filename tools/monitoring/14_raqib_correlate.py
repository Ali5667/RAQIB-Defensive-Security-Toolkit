#!/usr/bin/env python3
"""
raqib_correlate.py — محرك ربط الأحداث المشترك (مصدر الحقيقة الوحيد).
يستخدمه tools/monitoring/siem_correlator.sh (تفاعلي) و
tools/monitoring/raqib_watchdog.sh (خلفية مستمرة) — نفس المنطق بالضبط،
بدون تكرار كود، فأي تحسين على قواعد الربط ينعكس بالمكانين تلقائياً.

Usage: raqib_correlate.py <events.jsonl> <window_minutes>
Output: JSON واحد على stdout بكل الحوادث المكتشفة (4 أنواع قواعد).
"""
import sys
import json
import datetime

SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def load_events(path):
    events = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    e["_ts"] = datetime.datetime.strptime(
                        e["timestamp"], "%Y-%m-%dT%H:%M:%SZ"
                    )
                    events.append(e)
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    events.sort(key=lambda e: e["_ts"])
    return events


def rule_multi_tool(relevant, window):
    """قاعدة 1: 3 أدوات مختلفة فأكثر خلال نافذة زمنية واحدة = حادثة مركّبة."""
    incidents = []
    i = 0
    while i < len(relevant):
        group = [relevant[i]]
        j = i + 1
        while j < len(relevant) and relevant[j]["_ts"] - group[0]["_ts"] <= window:
            group.append(relevant[j])
            j += 1
        tools = {e.get("tool", "unknown") for e in group}
        if len(tools) >= 3:
            top = max(group, key=lambda e: SEV_RANK.get(e.get("severity", "low"), 0))
            incidents.append({
                "type": "multi_tool",
                "start": group[0]["timestamp"],
                "end": group[-1]["timestamp"],
                "tools": sorted(tools),
                "count": len(group),
                "top_severity": top.get("severity", "low"),
            })
            i = j
        else:
            i += 1
    return incidents


def rule_repeat_critical(relevant, window):
    """قاعدة 2: نفس الأداة تكرّر high/critical 3 مرات فأكثر بنفس النافذة —
    مؤشر هجوم مستمر/متكرر (مثلاً محاولات دخول فاشلة متتالية)."""
    incidents = []
    high_sev = [e for e in relevant if SEV_RANK.get(e.get("severity", "low"), 0) >= 2]
    by_tool = {}
    for e in high_sev:
        by_tool.setdefault(e.get("tool", "unknown"), []).append(e)
    for tool, evs in by_tool.items():
        evs.sort(key=lambda e: e["_ts"])
        i = 0
        while i < len(evs):
            group = [evs[i]]
            j = i + 1
            while j < len(evs) and evs[j]["_ts"] - group[0]["_ts"] <= window:
                group.append(evs[j])
                j += 1
            if len(group) >= 3:
                top = max(group, key=lambda e: SEV_RANK.get(e.get("severity", "low"), 0))
                incidents.append({
                    "type": "repeat_critical",
                    "tool": tool,
                    "start": group[0]["timestamp"],
                    "end": group[-1]["timestamp"],
                    "count": len(group),
                    "severity": top.get("severity", "low"),
                })
                i = j
            else:
                i += 1
    return incidents


def rule_off_hours(relevant):
    """قاعدة 3: ملاحظة medium+ بساعات غير معتادة (12ص - 5ص) — نشاط بهالوقت
    أقل احتمال يكون المستخدم نفسه، وأعلى احتمال يكون آلي/مشبوه."""
    incidents = []
    for e in relevant:
        hour = e["_ts"].hour
        if 0 <= hour <= 5 and SEV_RANK.get(e.get("severity", "low"), 0) >= 1:
            incidents.append({
                "type": "off_hours",
                "timestamp": e["timestamp"],
                "tool": e.get("tool", "unknown"),
                "severity": e.get("severity", "low"),
                "hour_utc": hour,
            })
    return incidents


def rule_escalating(relevant, window):
    """قاعدة 4: تسلسل خطورة متصاعد (low->medium->high->critical) من أدوات
    مختلفة بنفس النافذة — نمط شائع بهجوم حقيقي يتطوّر تدريجياً، مو ملاحظات
    عشوائية متفرقة."""
    incidents = []
    i = 0
    while i < len(relevant):
        window_events = [relevant[i]]
        j = i + 1
        while j < len(relevant) and relevant[j]["_ts"] - window_events[0]["_ts"] <= window:
            window_events.append(relevant[j])
            j += 1
        seq = [SEV_RANK.get(e.get("severity", "low"), 0) for e in window_events]
        is_increasing = all(seq[k] <= seq[k + 1] for k in range(len(seq) - 1))
        distinct_levels = len(set(seq))
        if is_increasing and distinct_levels >= 3 and len(window_events) >= 3:
            incidents.append({
                "type": "escalating",
                "start": window_events[0]["timestamp"],
                "end": window_events[-1]["timestamp"],
                "tools": [e.get("tool", "unknown") for e in window_events],
                "sequence": [e.get("severity", "low") for e in window_events],
            })
            i = j
        else:
            i += 1
    return incidents


def correlate(events_path, window_minutes):
    window = datetime.timedelta(minutes=window_minutes)
    events = load_events(events_path)
    relevant = [e for e in events if SEV_RANK.get(e.get("severity", "low"), 0) >= 1]

    incidents = []
    incidents += rule_multi_tool(relevant, window)
    incidents += rule_repeat_critical(relevant, window)
    incidents += rule_off_hours(relevant)
    incidents += rule_escalating(relevant, window)

    return {
        "total_events": len(events),
        "relevant_events": len(relevant),
        "incident_count": len(incidents),
        "incidents": incidents,
    }


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: raqib_correlate.py <events.jsonl> <window_minutes>"}))
        sys.exit(1)
    result = correlate(sys.argv[1], int(sys.argv[2]))
    print(json.dumps(result, ensure_ascii=False))
