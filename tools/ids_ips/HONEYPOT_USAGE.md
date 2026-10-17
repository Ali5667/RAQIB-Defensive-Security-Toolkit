# 🍯 RAQIB Honeypot — Usage Guide

## Quick Start

```bash
# Listen on three decoy ports (SSH, HTTP, MySQL)
python3 tools/ids_ips/raqib_honeypot.py --ports 2222,8080,3307

# Single port with explicit SSH banner
python3 tools/ids_ips/raqib_honeypot.py --ports 2222 --banner ssh

# JSON stream (pipeable to jq, Logstash, etc.)
python3 tools/ids_ips/raqib_honeypot.py --ports 2222,8080 --json

# Full options
python3 tools/ids_ips/raqib_honeypot.py \
    --ports 2222,8080,9090 \
    --bind 0.0.0.0 \
    --banner ssh \
    --log /var/log/raqib_honeypot.jsonl \
    --max-capture 2048 \
    --rate-limit 20
```

## Testing Locally

```bash
# Terminal 1 — start the honeypot
python3 tools/ids_ips/raqib_honeypot.py --ports 9999

# Terminal 2 — trigger a connection
echo "GET /etc/passwd HTTP/1.0" | nc localhost 9999

# Terminal 2 — trigger a plain probe (no data)
nc -z localhost 9999
```

Expected output on Terminal 1:

```
  [14:32:07] 🟡 Connection: 127.0.0.1:54321 → :9999 (unknown)  [35B]
    Preview: GET /etc/passwd HTTP/1.0\r\n
  [14:32:07] 🔴   ⚡ Local File Inclusion (/etc/passwd)
    Why: This port should carry no legitimate traffic — any connection is suspicious
    Fix: Investigate 127.0.0.1: whois, reverse DNS, geo-IP.  Block via firewall
```

## How Severity Works

| Condition | Severity | Explanation |
|-----------|----------|-------------|
| Single silent connect (no data) | `low` | Port probe — scanner checking if port is open |
| Data captured OR 3+ from same IP | `medium` | Active interaction or repeat reconnaissance |
| 10+ connects/min from same IP | `high` | Aggressive port sweep or brute-force attempt |
| Known scanner signature (Nmap, etc.) | `high` | Automated scanning tool identified in payload |
| Known exploit signature (LFI, SQLi, etc.) | `critical` | Active attack attempt detected |

## JSON Output (--json)

Each connection emits one NDJSON line to stdout:

```json
{
  "timestamp": "2026-10-17T13:32:07Z",
  "event": "honeypot_connection",
  "source_ip": "192.168.1.50",
  "source_port": 54321,
  "dest_port": 2222,
  "service": "ssh",
  "severity": "high",
  "data_bytes": 42,
  "data_hex": "4e6d61702f...",
  "data_preview": "Nmap scanning...",
  "conn_count": 1,
  "signatures": [{"id": "nmap_probe", "description": "Nmap network scanner probe", "severity": "high"}],
  "what_checked": "TCP connection on honeypot port 2222 (ssh banner)",
  "what_found": "Connection from 192.168.1.50:54321 with 42-byte payload",
  "why_it_matters": "This port should carry no legitimate traffic",
  "suggested_fix": "Investigate 192.168.1.50: whois, reverse DNS, geo-IP"
}
```

## SIEM Integration

Events are automatically written to `.raqib_events.jsonl` using the
exact same schema as `raqib_emit_event` in `modules/common.sh`.
Compatible with Filebeat, Wazuh, Logstash, and the built-in
RAQIB SIEM correlator + dashboard.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Clean shutdown — no connections were detected |
| `1`  | Connections were detected during the session |
| `2`  | Usage or configuration error (bad port, bind failure) |

## Tips

- **Ports < 1024** require `sudo` on most systems.
- Use ports that **should be unused** on your machine — the whole idea
  is that any connection to them is suspicious by definition.
- Combine with RAQIB's watchdog (`17_raqib_watchdog.sh`) for 24/7
  monitoring with Telegram alerts.
- Pipe `--json` output to `jq` for real-time filtering:
  ```bash
  python3 raqib_honeypot.py --ports 2222 --json | jq 'select(.severity == "critical")'
  ```
