#!/usr/bin/env python3
"""
RAQIB Log Anomaly Detector + Multi-Format Parser
═══════════════════════════════════════════════════

1) Z-SCORE ANOMALY DETECTION
   حساب التباين اليومي/الساعي لمعدل الأخطاء والأحداث الأمنية.
   ينبّه تلقائياً عند تجاوز المعدل 3σ (ثلاثة انحرافات معيارية).

2) SPECIALIZED LOG PARSERS
   محللات ذكية لصيغ سجلات متعددة:
   - Nginx (access + error)
   - Apache (combined, common)
   - Docker (JSON log driver)
   - Kubernetes (kubelet, audit)
   - Syslog-ng / rsyslog
   - Traefik (JSON access logs)
   - systemd/journald

Usage:
  python3 log_anomaly_detector.py analyze <logfile> [--format auto]
  python3 log_anomaly_detector.py anomaly <logfile> [--window hourly|daily]
  python3 log_anomaly_detector.py parse <logfile> --format nginx
  python3 log_anomaly_detector.py baseline <logfile>
  python3 log_anomaly_detector.py report <logfile>

Pure Python — stdlib only (re, json, math, collections, datetime).
"""
from __future__ import annotations
import argparse, collections, json, math, os, re, sys
from datetime import datetime, timedelta
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# 1) LOG FORMAT PARSERS
# ═══════════════════════════════════════════════════════════════════

class LogEntry:
    __slots__ = ('timestamp', 'ip', 'method', 'path', 'status', 'size',
                 'message', 'severity', 'source', 'raw')
    def __init__(self, **kw):
        for s in self.__slots__:
            setattr(self, s, kw.get(s, ''))

    def to_dict(self):
        return {s: getattr(self, s, '') for s in self.__slots__ if getattr(self, s, '')}


# ─── Regex patterns for each format ──────────────────────────────

# Nginx/Apache combined log format
RE_COMBINED = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
)

# Syslog format (RFC 3164)
RE_SYSLOG = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'(?P<program>\S+?)(?:\[\d+\])?:\s+'
    r'(?P<message>.*)'
)

# Docker JSON log format
RE_DOCKER = re.compile(r'\{"log":"(?P<message>[^"]*)".*?"time":"(?P<timestamp>[^"]*)"')

# Kubernetes audit log (JSON)
# Handled as JSON directly

# Auth log patterns
RE_AUTH = re.compile(
    r'(?P<timestamp>\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+\S+:\s+(?P<message>.*)'
)

# Traefik JSON
# Handled as JSON directly

FORMATS = {
    'nginx': RE_COMBINED,
    'apache': RE_COMBINED,
    'syslog': RE_SYSLOG,
    'docker': RE_DOCKER,
    'auth': RE_AUTH,
}


def detect_format(lines: list[str]) -> str:
    """Auto-detect log format from sample lines."""
    sample = '\n'.join(lines[:20])

    # JSON-based formats
    json_count = sum(1 for l in lines[:10] if l.strip().startswith('{'))
    if json_count > 5:
        # Docker vs K8s vs Traefik
        try:
            j = json.loads(lines[0].strip())
            if 'log' in j and 'stream' in j:
                return 'docker'
            if 'kind' in j and 'apiVersion' in j:
                return 'kubernetes'
            if 'RouterName' in j or 'entryPointName' in j:
                return 'traefik'
        except Exception:
            pass
        return 'json'

    # Text-based formats
    if RE_COMBINED.search(sample):
        if 'nginx' in sample.lower():
            return 'nginx'
        return 'apache'

    if RE_SYSLOG.search(sample):
        if 'sshd' in sample or 'Failed password' in sample or 'sudo' in sample:
            return 'auth'
        return 'syslog'

    return 'unknown'


def parse_line(line: str, fmt: str) -> LogEntry | None:
    """Parse a single log line into a LogEntry."""
    line = line.strip()
    if not line:
        return None

    if fmt in ('docker', 'kubernetes', 'traefik', 'json'):
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            return None

        if fmt == 'docker':
            return LogEntry(
                timestamp=j.get('time', ''),
                message=j.get('log', '').strip(),
                source='docker',
                raw=line,
            )
        elif fmt == 'kubernetes':
            return LogEntry(
                timestamp=j.get('requestReceivedTimestamp', j.get('stageTimestamp', '')),
                message=json.dumps(j.get('responseStatus', {})),
                status=str(j.get('responseStatus', {}).get('code', '')),
                path=j.get('requestURI', ''),
                source='kubernetes',
                raw=line,
            )
        elif fmt == 'traefik':
            return LogEntry(
                timestamp=j.get('time', j.get('StartUTC', '')),
                ip=j.get('ClientAddr', j.get('downstream_remote_address', '')),
                method=j.get('RequestMethod', ''),
                path=j.get('RequestPath', ''),
                status=str(j.get('DownstreamStatus', j.get('downstream_status', ''))),
                size=str(j.get('DownstreamContentSize', '')),
                source='traefik',
                raw=line,
            )
        else:
            return LogEntry(
                timestamp=j.get('timestamp', j.get('time', j.get('@timestamp', ''))),
                message=j.get('message', j.get('msg', json.dumps(j)[:200])),
                severity=j.get('level', j.get('severity', '')),
                source='json',
                raw=line,
            )

    regex = FORMATS.get(fmt)
    if not regex:
        return LogEntry(message=line, raw=line, source=fmt)

    m = regex.search(line)
    if not m:
        return None

    d = m.groupdict()

    entry = LogEntry(
        timestamp=d.get('timestamp', ''),
        ip=d.get('ip', ''),
        method=d.get('method', ''),
        path=d.get('path', ''),
        status=d.get('status', ''),
        size=d.get('size', ''),
        message=d.get('message', ''),
        source=fmt,
        raw=line,
    )

    # Determine severity from status code or message
    status = entry.status
    msg_lower = entry.message.lower()
    if status and status.startswith('5'):
        entry.severity = 'high'
    elif status and status.startswith('4'):
        entry.severity = 'medium'
    elif 'error' in msg_lower or 'fail' in msg_lower or 'denied' in msg_lower:
        entry.severity = 'medium'
    elif 'critical' in msg_lower or 'emergency' in msg_lower:
        entry.severity = 'critical'
    elif 'warning' in msg_lower or 'warn' in msg_lower:
        entry.severity = 'low'
    else:
        entry.severity = 'info'

    return entry


def parse_file(filepath: str, fmt: str = 'auto') -> tuple[list[LogEntry], str]:
    """Parse an entire log file."""
    with open(filepath, encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    if fmt == 'auto':
        fmt = detect_format(lines)
        print(f"  [+] Detected format: {fmt}")

    entries = []
    for line in lines:
        entry = parse_line(line, fmt)
        if entry:
            entries.append(entry)

    return entries, fmt


# ═══════════════════════════════════════════════════════════════════
# 2) Z-SCORE ANOMALY DETECTION
# ═══════════════════════════════════════════════════════════════════

def extract_time_bucket(timestamp_str: str, window: str = 'hourly') -> str:
    """Extract a time bucket key from various timestamp formats."""
    # Try common formats
    for fmt in (
        '%d/%b/%Y:%H:%M:%S %z',  # Nginx/Apache
        '%d/%b/%Y:%H:%M:%S',
        '%b %d %H:%M:%S',         # Syslog
        '%Y-%m-%dT%H:%M:%S',      # ISO
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d %H:%M:%S',
    ):
        try:
            dt = datetime.strptime(timestamp_str.strip()[:len(fmt)+5], fmt)
            if window == 'hourly':
                return dt.strftime('%Y-%m-%d %H:00')
            elif window == 'daily':
                return dt.strftime('%Y-%m-%d')
            else:
                return dt.strftime('%Y-%m-%d %H:%M')
        except ValueError:
            continue
    return 'unknown'


def z_score_analysis(entries: list[LogEntry], window: str = 'hourly',
                     threshold: float = 3.0) -> list[dict]:
    """
    Z-Score anomaly detection on log event rates.
    Flags time buckets where the event count exceeds mean + threshold*std.
    """
    # Count events per time bucket
    buckets: dict[str, int] = collections.Counter()
    error_buckets: dict[str, int] = collections.Counter()
    ip_buckets: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)

    for entry in entries:
        bucket = extract_time_bucket(entry.timestamp, window)
        if bucket == 'unknown':
            continue
        buckets[bucket] += 1
        if entry.severity in ('high', 'critical', 'medium'):
            error_buckets[bucket] += 1
        if entry.ip:
            ip_buckets[bucket][entry.ip] += 1

    if len(buckets) < 3:
        return []

    # Calculate mean and std for total events
    counts = list(buckets.values())
    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / max(len(counts) - 1, 1)
    std = math.sqrt(variance) if variance > 0 else 1.0

    # Calculate for error events
    err_counts = [error_buckets.get(b, 0) for b in buckets]
    err_mean = sum(err_counts) / len(err_counts) if err_counts else 0
    err_var = sum((c - err_mean) ** 2 for c in err_counts) / max(len(err_counts) - 1, 1)
    err_std = math.sqrt(err_var) if err_var > 0 else 1.0

    anomalies = []
    for bucket in sorted(buckets.keys()):
        total = buckets[bucket]
        errors = error_buckets.get(bucket, 0)

        z_total = (total - mean) / std if std > 0 else 0
        z_errors = (errors - err_mean) / err_std if err_std > 0 else 0

        is_anomaly = abs(z_total) > threshold or abs(z_errors) > threshold

        if is_anomaly:
            # Find top IPs in this bucket
            top_ips = ip_buckets.get(bucket, collections.Counter()).most_common(5)
            anomalies.append({
                'time_bucket': bucket,
                'total_events': total,
                'error_events': errors,
                'z_score_total': round(z_total, 2),
                'z_score_errors': round(z_errors, 2),
                'top_ips': [{'ip': ip, 'count': c} for ip, c in top_ips],
                'severity': 'critical' if abs(z_total) > 5 or abs(z_errors) > 5
                           else 'high' if abs(z_total) > 4 or abs(z_errors) > 4
                           else 'medium',
            })

    return anomalies


# ═══════════════════════════════════════════════════════════════════
# 3) SECURITY PATTERN DETECTION
# ═══════════════════════════════════════════════════════════════════

ATTACK_PATTERNS = {
    'sql_injection': re.compile(
        r"(?:union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|--\s*$|;\s*drop\s|"
        r"information_schema|sleep\s*\(|benchmark\s*\(|load_file\s*\()", re.I),
    'xss': re.compile(
        r"<script|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie", re.I),
    'path_traversal': re.compile(
        r"\.\./\.\./|/etc/passwd|/etc/shadow|/proc/self|%2e%2e|%252e", re.I),
    'command_injection': re.compile(
        r";\s*(ls|cat|id|whoami|uname|curl|wget|nc|bash|sh)\b|`[^`]+`|\$\([^)]+\)", re.I),
    'scanner_ua': re.compile(
        r"nikto|sqlmap|nmap|dirbuster|gobuster|wfuzz|burpsuite|acunetix|nessus|qualys", re.I),
    'webshell_access': re.compile(
        r"(c99|r57|wso|b374k|alfa|mini)\.php|cmd\.php|shell\.php|backdoor", re.I),
    'brute_force': re.compile(
        r"Failed password|Invalid user|authentication fail|Access denied", re.I),
    'log4shell': re.compile(
        r'\$\{jndi:|%24%7Bjndi', re.I),
}


def detect_attacks(entries: list[LogEntry]) -> list[dict]:
    """Detect known attack patterns in log entries."""
    detections = []
    for entry in entries:
        check_text = f"{entry.path} {entry.message} {entry.raw}"
        for attack_name, pattern in ATTACK_PATTERNS.items():
            if pattern.search(check_text):
                detections.append({
                    'attack': attack_name,
                    'ip': entry.ip,
                    'path': entry.path,
                    'timestamp': entry.timestamp,
                    'severity': 'critical' if attack_name in ('log4shell', 'command_injection')
                               else 'high' if attack_name in ('sql_injection', 'webshell_access')
                               else 'medium',
                    'snippet': entry.raw[:200],
                })
    return detections


# ═══════════════════════════════════════════════════════════════════
# 4) REPORTING
# ═══════════════════════════════════════════════════════════════════

SEV_COLORS = {
    'critical': '\033[1;31m', 'high': '\033[38;5;208m',
    'medium': '\033[1;33m', 'low': '\033[0;32m', 'info': '\033[0;37m',
}
NC = '\033[0m'


def print_anomalies(anomalies: list[dict]):
    print(f"\n  {'─' * 60}")
    print(f"  📊 Anomaly Detection Results (Z-Score)")
    print(f"  {'─' * 60}")

    if not anomalies:
        print(f"  ✅ No anomalies detected")
        return

    for a in anomalies:
        sev = a['severity']
        color = SEV_COLORS.get(sev, NC)
        print(f"\n  {color}[{sev.upper()}]{NC} {a['time_bucket']}")
        print(f"    Events: {a['total_events']} (Z={a['z_score_total']:+.2f})")
        print(f"    Errors: {a['error_events']} (Z={a['z_score_errors']:+.2f})")
        if a['top_ips']:
            ips = ', '.join(f"{d['ip']}({d['count']})" for d in a['top_ips'][:3])
            print(f"    Top IPs: {ips}")


def print_attacks(detections: list[dict]):
    print(f"\n  {'─' * 60}")
    print(f"  🎯 Attack Pattern Detection")
    print(f"  {'─' * 60}")

    if not detections:
        print(f"  ✅ No attack patterns detected")
        return

    by_type = collections.Counter(d['attack'] for d in detections)
    for attack, count in by_type.most_common():
        print(f"    {attack:25s} {count:5d} hits")

    print(f"\n  Top detections:")
    for d in detections[:15]:
        color = SEV_COLORS.get(d['severity'], NC)
        print(f"    {color}[{d['severity']:8s}]{NC} {d['attack']:20s} IP={d['ip']:15s} {d['path'][:50]}")


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="RAQIB Log Anomaly Detector + Multi-Format Parser")
    sub = parser.add_subparsers(dest='command')

    p_analyze = sub.add_parser('analyze', help='Full analysis (parse + anomaly + attacks)')
    p_analyze.add_argument('logfile')
    p_analyze.add_argument('--format', default='auto',
                          choices=['auto', 'nginx', 'apache', 'syslog', 'auth',
                                   'docker', 'kubernetes', 'traefik', 'json'])
    p_analyze.add_argument('--window', default='hourly', choices=['hourly', 'daily', 'minute'])
    p_analyze.add_argument('--threshold', type=float, default=3.0, help='Z-score threshold')

    p_anomaly = sub.add_parser('anomaly', help='Z-score anomaly detection only')
    p_anomaly.add_argument('logfile')
    p_anomaly.add_argument('--format', default='auto')
    p_anomaly.add_argument('--window', default='hourly')
    p_anomaly.add_argument('--threshold', type=float, default=3.0)
    p_anomaly.add_argument('--json', action='store_true')

    p_parse = sub.add_parser('parse', help='Parse and display log entries')
    p_parse.add_argument('logfile')
    p_parse.add_argument('--format', default='auto')
    p_parse.add_argument('--limit', type=int, default=50)
    p_parse.add_argument('--json', action='store_true')

    p_report = sub.add_parser('report', help='Generate full security report')
    p_report.add_argument('logfile')
    p_report.add_argument('--format', default='auto')
    p_report.add_argument('--output', help='Output file path')

    args = parser.parse_args()

    if args.command == 'analyze':
        entries, fmt = parse_file(args.logfile, args.format)
        print(f"  [+] Parsed {len(entries)} entries from {args.logfile}")

        anomalies = z_score_analysis(entries, args.window, args.threshold)
        print_anomalies(anomalies)

        attacks = detect_attacks(entries)
        print_attacks(attacks)

        # Summary statistics
        statuses = collections.Counter(e.status for e in entries if e.status)
        ips = collections.Counter(e.ip for e in entries if e.ip)
        print(f"\n  {'─' * 60}")
        print(f"  📈 Summary")
        print(f"  {'─' * 60}")
        print(f"  Total entries:  {len(entries)}")
        print(f"  Unique IPs:     {len(ips)}")
        print(f"  Anomalies:      {len(anomalies)}")
        print(f"  Attack hits:    {len(attacks)}")
        if statuses:
            status_str = ', '.join(f"{s}:{c}" for s, c in statuses.most_common(5))
            print(f"  Top statuses:   {status_str}")
        if ips:
            ip_str = ', '.join(f"{ip}({c})" for ip, c in ips.most_common(5))
            print(f"  Top IPs:        {ip_str}")

    elif args.command == 'anomaly':
        entries, fmt = parse_file(args.logfile, args.format)
        anomalies = z_score_analysis(entries, args.window, args.threshold)
        if args.json:
            print(json.dumps(anomalies, indent=2, ensure_ascii=False))
        else:
            print_anomalies(anomalies)

    elif args.command == 'parse':
        entries, fmt = parse_file(args.logfile, args.format)
        for entry in entries[:args.limit]:
            if args.json:
                print(json.dumps(entry.to_dict()))
            else:
                sev = entry.severity
                color = SEV_COLORS.get(sev, NC)
                print(f"  {color}[{sev:8s}]{NC} {entry.timestamp:25s} {entry.ip:15s} "
                      f"{entry.status:4s} {entry.path[:40] or entry.message[:40]}")
        print(f"\n  Showing {min(len(entries), args.limit)}/{len(entries)} entries")

    elif args.command == 'report':
        entries, fmt = parse_file(args.logfile, args.format)
        anomalies = z_score_analysis(entries)
        attacks = detect_attacks(entries)

        report_lines = [
            "=" * 70,
            "  RAQIB Log Analysis Report",
            "=" * 70,
            f"  File:       {args.logfile}",
            f"  Format:     {fmt}",
            f"  Entries:    {len(entries)}",
            f"  Anomalies:  {len(anomalies)}",
            f"  Attacks:    {len(attacks)}",
            "",
        ]

        if anomalies:
            report_lines.append("  === ANOMALIES ===")
            for a in anomalies:
                report_lines.append(
                    f"  [{a['severity']}] {a['time_bucket']}  "
                    f"events={a['total_events']} z={a['z_score_total']:+.2f}")
            report_lines.append("")

        if attacks:
            report_lines.append("  === ATTACKS ===")
            by_type = collections.Counter(d['attack'] for d in attacks)
            for attack, count in by_type.most_common():
                report_lines.append(f"  {attack}: {count} hits")

        report_text = '\n'.join(report_lines)
        if args.output:
            Path(args.output).write_text(report_text, encoding='utf-8')
            print(f"  [+] Report saved to {args.output}")
        else:
            print(report_text)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
