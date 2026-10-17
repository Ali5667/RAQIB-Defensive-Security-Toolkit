#!/usr/bin/env python3
"""
RAQIB Multi-Channel Alerter + SQLite Event Store + Prometheus Exporter
══════════════════════════════════════════════════════════════════════════

Three major monitoring upgrades in one module:

1) MULTI-CHANNEL ALERTS (Discord, Slack, Mattermost, Microsoft Teams)
   - Sends security alerts via webhooks to any supported platform
   - Usage: python3 raqib_alerter.py send <channel> <severity> <message>

2) SQLITE EVENT STORE (replaces JSONL linear reads)
   - Imports .raqib_events.jsonl into SQLite for fast queries
   - Usage: python3 raqib_alerter.py db-import
            python3 raqib_alerter.py db-query --severity high --last 24h

3) PROMETHEUS METRICS EXPORTER
   - Exposes metrics at /metrics for Grafana/Prometheus scraping
   - Usage: python3 raqib_alerter.py prometheus --port 9100

Pure Python — uses only stdlib (http.server, sqlite3, json, urllib).
"""
from __future__ import annotations
import argparse, json, os, re, sqlite3, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from threading import Thread

BASE = Path(__file__).resolve().parent
TOOLKIT_ROOT = BASE.parent.parent
EVENTS_JSONL = TOOLKIT_ROOT / ".raqib_events.jsonl"
DB_PATH = TOOLKIT_ROOT / "state" / "raqib_events.db"
CONFIG_PATH = TOOLKIT_ROOT / "state" / "raqib_alerter_config.json"

# ═══════════════════════════════════════════════════════════════════════
# 1) MULTI-CHANNEL WEBHOOK ALERTER
# ═══════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "channels": {
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": "",
        },
        "discord": {
            "enabled": False,
            "webhook_url": "",
        },
        "slack": {
            "enabled": False,
            "webhook_url": "",
        },
        "mattermost": {
            "enabled": False,
            "webhook_url": "",
        },
        "teams": {
            "enabled": False,
            "webhook_url": "",
        },
    },
    "severity_filter": "medium",  # minimum severity to alert on
    "rate_limit_seconds": 10,     # minimum seconds between alerts
}

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False),
                           encoding="utf-8")


def _webhook_post(url: str, payload: dict, headers: dict | None = None) -> bool:
    """Sends a JSON POST request to a webhook URL."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        print(f"  [!] Webhook error: {e}", file=sys.stderr)
        return False


def send_discord(webhook_url: str, severity: str, message: str, tool: str = "RAQIB") -> bool:
    """Sends an alert to Discord via webhook."""
    colors = {"critical": 0xFF0000, "high": 0xFF8C00, "medium": 0xFFD700, "low": 0x00FF00}
    payload = {
        "embeds": [{
            "title": f"{SEV_EMOJI.get(severity, '⚪')} RAQIB Alert [{severity.upper()}]",
            "description": message,
            "color": colors.get(severity, 0x808080),
            "fields": [
                {"name": "Tool", "value": tool, "inline": True},
                {"name": "Severity", "value": severity.upper(), "inline": True},
                {"name": "Time", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), "inline": True},
            ],
            "footer": {"text": "RAQIB Defensive Security Toolkit"},
        }]
    }
    return _webhook_post(webhook_url, payload)


def send_slack(webhook_url: str, severity: str, message: str, tool: str = "RAQIB") -> bool:
    """Sends an alert to Slack via webhook."""
    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{SEV_EMOJI.get(severity, '⚪')} RAQIB Alert [{severity.upper()}]"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{message}*"}
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Tool: `{tool}` | Severity: `{severity}` | {datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}"}
                ]
            }
        ]
    }
    return _webhook_post(webhook_url, payload)


def send_mattermost(webhook_url: str, severity: str, message: str, tool: str = "RAQIB") -> bool:
    """Sends an alert to Mattermost via webhook."""
    payload = {
        "text": f"### {SEV_EMOJI.get(severity, '⚪')} RAQIB Alert [{severity.upper()}]\n"
                f"**{message}**\n"
                f"> Tool: `{tool}` | Severity: `{severity}` | "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "username": "RAQIB",
        "icon_emoji": ":eagle:",
    }
    return _webhook_post(webhook_url, payload)


def send_teams(webhook_url: str, severity: str, message: str, tool: str = "RAQIB") -> bool:
    """Sends an alert to Microsoft Teams via webhook."""
    colors = {"critical": "FF0000", "high": "FF8C00", "medium": "FFD700", "low": "00FF00"}
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": colors.get(severity, "808080"),
        "summary": f"RAQIB Alert [{severity}]",
        "sections": [{
            "activityTitle": f"{SEV_EMOJI.get(severity, '⚪')} RAQIB Security Alert",
            "facts": [
                {"name": "Severity", "value": severity.upper()},
                {"name": "Tool", "value": tool},
                {"name": "Time", "value": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")},
            ],
            "text": message,
        }],
    }
    return _webhook_post(webhook_url, payload)


def send_telegram(bot_token: str, chat_id: str, severity: str, message: str, tool: str = "RAQIB") -> bool:
    """Sends an alert to Telegram."""
    text = (f"{SEV_EMOJI.get(severity, '⚪')} *RAQIB Alert \\[{severity.upper()}\\]*\n\n"
            f"{message}\n\n"
            f"🛠 Tool: `{tool}`\n"
            f"⏰ {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "MarkdownV2"}
    return _webhook_post(url, payload)


CHANNEL_SENDERS = {
    "discord": lambda cfg, sev, msg, tool: send_discord(cfg["webhook_url"], sev, msg, tool),
    "slack": lambda cfg, sev, msg, tool: send_slack(cfg["webhook_url"], sev, msg, tool),
    "mattermost": lambda cfg, sev, msg, tool: send_mattermost(cfg["webhook_url"], sev, msg, tool),
    "teams": lambda cfg, sev, msg, tool: send_teams(cfg["webhook_url"], sev, msg, tool),
    "telegram": lambda cfg, sev, msg, tool: send_telegram(cfg["bot_token"], cfg["chat_id"], sev, msg, tool),
}


def send_alert(severity: str, message: str, tool: str = "RAQIB", channel: str | None = None):
    """Sends alert to all enabled channels (or a specific one)."""
    config = load_config()
    min_sev = SEV_RANK.get(config.get("severity_filter", "medium"), 2)
    if SEV_RANK.get(severity, 0) < min_sev:
        return

    channels = config.get("channels", {})
    results = {}

    for ch_name, ch_config in channels.items():
        if channel and ch_name != channel:
            continue
        if not ch_config.get("enabled"):
            continue
        sender = CHANNEL_SENDERS.get(ch_name)
        if sender:
            ok = sender(ch_config, severity, message, tool)
            results[ch_name] = "✓" if ok else "✗"
            print(f"  {'✓' if ok else '✗'} {ch_name}: {'sent' if ok else 'failed'}")

    return results


# ═══════════════════════════════════════════════════════════════════════
# 2) SQLITE EVENT STORE
# ═══════════════════════════════════════════════════════════════════════

def init_db():
    """Creates the SQLite database and schema."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            tool TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT,
            category TEXT,
            hostname TEXT,
            operator TEXT,
            raw_json TEXT,
            imported_at TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tool ON events(tool)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_category ON events(category)")
    conn.commit()
    return conn


def import_jsonl_to_db():
    """Imports .raqib_events.jsonl into SQLite."""
    if not EVENTS_JSONL.exists():
        print(f"  [!] Events file not found: {EVENTS_JSONL}")
        return

    conn = init_db()
    imported = 0
    skipped = 0

    # Get last imported timestamp to avoid duplicates
    cursor = conn.execute("SELECT MAX(timestamp) FROM events")
    last_ts = cursor.fetchone()[0] or ""

    with open(EVENTS_JSONL, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            ts = event.get("timestamp", "")
            if ts and ts <= last_ts:
                skipped += 1
                continue

            conn.execute(
                "INSERT INTO events (timestamp, tool, severity, message, category, hostname, operator, raw_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    event.get("tool", "unknown"),
                    event.get("severity", "low"),
                    event.get("message", ""),
                    event.get("category", ""),
                    event.get("hostname", ""),
                    event.get("operator", ""),
                    line,
                )
            )
            imported += 1

    conn.commit()
    conn.close()
    print(f"  [+] Imported {imported} events, skipped {skipped} (duplicates/errors)")
    print(f"  [+] Database: {DB_PATH}")


def query_db(severity: str | None = None, tool: str | None = None,
             last_hours: int | None = None, limit: int = 100) -> list[dict]:
    """Queries the SQLite event store."""
    if not DB_PATH.exists():
        print("  [!] Database not found. Run 'db-import' first.")
        return []

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row

    conditions = []
    params = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if tool:
        conditions.append("tool = ?")
        params.append(tool)
    if last_hours:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=last_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conditions.append("timestamp >= ?")
        params.append(cutoff)

    where = " AND ".join(conditions) if conditions else "1=1"
    query = f"SELECT * FROM events WHERE {where} ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    cursor = conn.execute(query, params)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def db_stats():
    """Shows database statistics."""
    if not DB_PATH.exists():
        print("  [!] Database not found. Run 'db-import' first.")
        return

    conn = sqlite3.connect(str(DB_PATH))

    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    by_sev = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM events GROUP BY severity ORDER BY cnt DESC"
    ).fetchall()
    by_tool = conn.execute(
        "SELECT tool, COUNT(*) as cnt FROM events GROUP BY tool ORDER BY cnt DESC LIMIT 10"
    ).fetchall()
    latest = conn.execute(
        "SELECT timestamp FROM events ORDER BY timestamp DESC LIMIT 1"
    ).fetchone()
    oldest = conn.execute(
        "SELECT timestamp FROM events ORDER BY timestamp ASC LIMIT 1"
    ).fetchone()

    conn.close()

    print(f"\n  📊 RAQIB Event Database Statistics")
    print(f"  {'─' * 50}")
    print(f"  Total events:  {total}")
    print(f"  Time range:    {oldest[0] if oldest else 'N/A'} → {latest[0] if latest else 'N/A'}")
    print(f"  Database size: {DB_PATH.stat().st_size / 1024:.1f} KB")
    print(f"\n  By Severity:")
    for sev, cnt in by_sev:
        bar = "█" * min(cnt, 50)
        print(f"    {sev:10s} {cnt:5d}  {bar}")
    print(f"\n  Top 10 Tools:")
    for tool, cnt in by_tool:
        print(f"    {tool:30s} {cnt:5d}")


# ═══════════════════════════════════════════════════════════════════════
# 3) PROMETHEUS METRICS EXPORTER
# ═══════════════════════════════════════════════════════════════════════

def generate_prometheus_metrics() -> str:
    """Generates Prometheus-compatible metrics from the event store."""
    lines = [
        "# HELP raqib_events_total Total number of security events",
        "# TYPE raqib_events_total counter",
    ]

    if not DB_PATH.exists():
        lines.append('raqib_events_total{severity="all"} 0')
        return "\n".join(lines) + "\n"

    conn = sqlite3.connect(str(DB_PATH))

    # Total events by severity
    for sev in ("critical", "high", "medium", "low"):
        count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE severity = ?", (sev,)
        ).fetchone()[0]
        lines.append(f'raqib_events_total{{severity="{sev}"}} {count}')

    # Events by tool
    lines.extend([
        "",
        "# HELP raqib_tool_events_total Events per tool",
        "# TYPE raqib_tool_events_total counter",
    ])
    for tool, count in conn.execute(
        "SELECT tool, COUNT(*) FROM events GROUP BY tool"
    ).fetchall():
        safe_tool = re.sub(r'[^a-zA-Z0-9_]', '_', tool)
        lines.append(f'raqib_tool_events_total{{tool="{safe_tool}"}} {count}')

    # Events in last hour
    one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    recent = conn.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (one_hour_ago,)
    ).fetchone()[0]
    lines.extend([
        "",
        "# HELP raqib_events_last_hour Events in the last hour",
        "# TYPE raqib_events_last_hour gauge",
        f"raqib_events_last_hour {recent}",
    ])

    # Critical events in last 24h
    one_day_ago = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    critical_24h = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity = 'critical' AND timestamp >= ?",
        (one_day_ago,)
    ).fetchone()[0]
    lines.extend([
        "",
        "# HELP raqib_critical_events_24h Critical events in last 24 hours",
        "# TYPE raqib_critical_events_24h gauge",
        f"raqib_critical_events_24h {critical_24h}",
    ])

    conn.close()
    return "\n".join(lines) + "\n"


class PrometheusHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            metrics = generate_prometheus_metrics()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.end_headers()
            self.wfile.write(metrics.encode("utf-8"))
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "service": "raqib-exporter"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # صامت


def start_prometheus_server(port: int = 9100):
    """Starts a Prometheus metrics HTTP server."""
    server = HTTPServer(("0.0.0.0", port), PrometheusHandler)
    print(f"  [+] Prometheus exporter running on http://0.0.0.0:{port}/metrics")
    print(f"  [+] Health check: http://0.0.0.0:{port}/health")
    print(f"  [+] Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  [*] Exporter stopped")
        server.shutdown()


# ═══════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="RAQIB Multi-Channel Alerter + SQLite Store + Prometheus Exporter")
    sub = parser.add_subparsers(dest="command")

    # Alert commands
    p_send = sub.add_parser("send", help="Send an alert")
    p_send.add_argument("channel", choices=["discord", "slack", "mattermost", "teams", "telegram", "all"])
    p_send.add_argument("severity", choices=["critical", "high", "medium", "low"])
    p_send.add_argument("message")
    p_send.add_argument("--tool", default="RAQIB")

    p_setup = sub.add_parser("setup", help="Configure alert channels interactively")

    p_test = sub.add_parser("test", help="Send a test alert to all enabled channels")

    # Database commands
    p_import = sub.add_parser("db-import", help="Import JSONL events into SQLite")
    p_query = sub.add_parser("db-query", help="Query the event database")
    p_query.add_argument("--severity", choices=["critical", "high", "medium", "low"])
    p_query.add_argument("--tool")
    p_query.add_argument("--last", help="e.g. 24h, 7d")
    p_query.add_argument("--limit", type=int, default=50)
    p_query.add_argument("--json", action="store_true")

    p_stats = sub.add_parser("db-stats", help="Show database statistics")

    # Prometheus
    p_prom = sub.add_parser("prometheus", help="Start Prometheus metrics exporter")
    p_prom.add_argument("--port", type=int, default=9100)

    args = parser.parse_args()

    if args.command == "send":
        ch = None if args.channel == "all" else args.channel
        send_alert(args.severity, args.message, args.tool, ch)

    elif args.command == "setup":
        config = load_config()
        print("\n  RAQIB Alert Channel Setup")
        print("  " + "─" * 40)
        for ch_name in ("discord", "slack", "mattermost", "teams", "telegram"):
            ch = config["channels"].get(ch_name, {})
            enabled = input(f"\n  Enable {ch_name}? (y/n) [{('y' if ch.get('enabled') else 'n')}]: ").strip()
            if enabled.lower() == "y":
                ch["enabled"] = True
                if ch_name == "telegram":
                    ch["bot_token"] = input(f"    Bot token [{ch.get('bot_token', '')}]: ").strip() or ch.get("bot_token", "")
                    ch["chat_id"] = input(f"    Chat ID [{ch.get('chat_id', '')}]: ").strip() or ch.get("chat_id", "")
                else:
                    ch["webhook_url"] = input(f"    Webhook URL [{ch.get('webhook_url', '')}]: ").strip() or ch.get("webhook_url", "")
            else:
                ch["enabled"] = False
            config["channels"][ch_name] = ch

        min_sev = input(f"\n  Minimum severity to alert [{config.get('severity_filter', 'medium')}]: ").strip()
        if min_sev in SEV_RANK:
            config["severity_filter"] = min_sev

        save_config(config)
        print(f"\n  ✓ Config saved to {CONFIG_PATH}")

    elif args.command == "test":
        send_alert("medium", "🧪 This is a test alert from RAQIB Defensive Security Toolkit", "test")

    elif args.command == "db-import":
        import_jsonl_to_db()

    elif args.command == "db-query":
        last_hours = None
        if args.last:
            m = re.match(r"(\d+)(h|d)", args.last)
            if m:
                val, unit = int(m.group(1)), m.group(2)
                last_hours = val if unit == "h" else val * 24

        results = query_db(args.severity, args.tool, last_hours, args.limit)
        if args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
        else:
            for r in results:
                sev = r.get("severity", "low")
                emoji = SEV_EMOJI.get(sev, "⚪")
                print(f"  {emoji} [{sev:8s}] {r.get('timestamp', '?'):20s} {r.get('tool', '?'):25s} {r.get('message', '')[:60]}")
            print(f"\n  Total: {len(results)} events")

    elif args.command == "db-stats":
        db_stats()

    elif args.command == "prometheus":
        init_db()
        start_prometheus_server(args.port)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
