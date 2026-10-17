#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =====================================================
#  RAQIB Honeypot — مصيدة شبكية منخفضة التفاعل (قراءة فقط)
#  Low-interaction network honeypot: listens on chosen TCP ports on
#  YOUR OWN machine, logs every connection attempt, and alerts through
#  the existing RAQIB event system.  Defensive use only.
#
#  Checks (heuristics only — every finding is explainable):
#    1. TCP connection attempts on monitored (unused) ports
#    2. Captured payload analysis (first N bytes per connection)
#    3. Repeat-offender tracking (same IP hitting multiple/same ports)
#    4. Known scanner / exploit signature detection in payloads
#
#  Usage:
#    python3 raqib_honeypot.py --ports 2222,8080,9090
#    python3 raqib_honeypot.py --ports 2222 --banner ssh --bind 0.0.0.0
#    python3 raqib_honeypot.py --ports 2222,8080 --json
#    python3 raqib_honeypot.py --help
#
#  Exit codes:
#    0 = clean shutdown, no connections detected
#    1 = connections were detected during the session
#    2 = usage / configuration error
#
#  Zero third-party dependencies (stdlib only).  Read-only: nothing on
#  the system is modified.  The honeypot only listens, captures, and logs.
# =====================================================
from __future__ import annotations

import argparse
import datetime
import json
import os
import signal
import socket
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

# ── Robust console output ────────────────────────────────────────────────
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

TOOL = "raqib_honeypot"

USAGE = """\
RAQIB Honeypot — low-interaction network honeypot (read-only, stdlib only)

Listens on chosen TCP ports on YOUR OWN machine.  Every connection attempt
is logged with source IP, port, timestamp, and captured payload.  Alerts
are raised through the existing RAQIB event system (.raqib_events.jsonl).

Usage:
  python3 raqib_honeypot.py --ports 2222,8080,9090
  python3 raqib_honeypot.py --ports 2222 --banner ssh --bind 0.0.0.0
  python3 raqib_honeypot.py --ports 2222,8080 --json --log session.jsonl
  python3 raqib_honeypot.py --help

Options:
  --ports PORT[,PORT,...]   Comma-separated TCP ports to listen on (required)
  --bind  ADDR              Bind address (default: 0.0.0.0)
  --banner SERVICE          Force banner for all ports:
                            ssh | http | ftp | smtp | telnet | mysql | none
  --json                    Stream NDJSON connection events to stdout
  --log   FILE              Also write connection events to a separate JSONL file
  --max-capture N           Max bytes to capture per connection (default: 1024)
  --rate-limit  N           Max connections/IP/minute before suppressing (default: 30)

Banner auto-detection: if --banner is not set the honeypot picks a banner
based on the port number (22→ssh, 80→http, etc.).  Use --banner none to
send no banner at all.

Exit codes: 0 = no connections | 1 = connections detected | 2 = usage error

⚠  Authorized use only — listen on YOUR OWN machines and ports only.
"""

# ── ANSI Colors (match modules/common.sh) ────────────────────────────────
GREEN   = "\033[0;32m"
CYAN    = "\033[0;36m"
YELLOW  = "\033[1;33m"
RED     = "\033[0;31m"
ORANGE  = "\033[38;5;208m"
CRIMSON = "\033[1;31m"
WHITE   = "\033[1;37m"
GREY    = "\033[1;30m"
BOLD    = "\033[1m"
NC      = "\033[0m"

SEV_COLOR = {"critical": CRIMSON, "high": RED, "medium": ORANGE, "low": YELLOW}
SEV_BADGE = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

# ── Service Banners ──────────────────────────────────────────────────────
# Realistic-looking greetings — just enough to make scanners reveal their
# payloads.  Nothing here exploits or attacks the connecting party.
BANNERS: dict[str, bytes] = {
    "ssh":    b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n",
    "http":   b"HTTP/1.1 400 Bad Request\r\nServer: Apache/2.4.52\r\n"
              b"Content-Length: 0\r\nConnection: close\r\n\r\n",
    "ftp":    b"220 ProFTPD 1.3.5e Server ready.\r\n",
    "smtp":   b"220 mail.localhost ESMTP Postfix\r\n",
    "telnet": b"\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03",
    "mysql":  b"\x4a\x00\x00\x00\x0a"                       # length + seq + proto
              b"8.0.32\x00"                                  # server version
              b"\x01\x00\x00\x00"                            # conn-id
              b"abcdefgh\x00",                               # auth-plugin stub
    "none":   b"",
}

PORT_SERVICE: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    80: "http", 110: "ftp", 143: "smtp", 443: "http",
    993: "smtp", 995: "ftp", 2222: "ssh", 3306: "mysql",
    3389: "none", 5432: "none", 6379: "none",
    8080: "http", 8443: "http", 8888: "http",
}

# ── Heuristic Signatures ────────────────────────────────────────────────
# (pattern_bytes, signature_id, human description)
# Scanner signatures → severity "high"
SCANNER_SIGS: list[tuple[bytes, str, str]] = [
    (b"Nmap",            "nmap_probe",      "Nmap network scanner probe"),
    (b"masscan",         "masscan_probe",   "Masscan high-speed scanner probe"),
    (b"zgrab",           "zgrab_probe",     "ZGrab scanner probe"),
    (b"gobuster",        "gobuster_probe",  "Gobuster directory brute-forcer"),
    (b"nikto",           "nikto_probe",     "Nikto web vulnerability scanner"),
    (b"sqlmap",          "sqlmap_probe",    "SQLMap injection scanner"),
    (b"dirbuster",       "dirbuster_probe", "DirBuster directory scanner"),
    (b"wpscan",          "wpscan_probe",    "WPScan WordPress scanner"),
    (b"python-requests", "py_requests",     "Python requests library probe"),
    (b"python-urllib",   "py_urllib",       "Python urllib probe"),
]

# Exploit signatures → severity "critical"
EXPLOIT_SIGS: list[tuple[bytes, str, str]] = [
    (b"/etc/passwd",       "lfi_passwd",     "Local File Inclusion (/etc/passwd)"),
    (b"/etc/shadow",       "lfi_shadow",     "Local File Inclusion (/etc/shadow)"),
    (b"../..",             "path_traversal", "Path traversal attempt"),
    (b"${jndi:",           "log4shell",      "Log4Shell exploit (CVE-2021-44228)"),
    (b"<?php",             "php_injection",  "PHP code injection attempt"),
    (b"; cat ",            "cmd_injection",  "Command injection (cat)"),
    (b"| cat ",            "cmd_injection",  "Command injection (pipe cat)"),
    (b"; wget ",           "cmd_downloader", "Command injection (wget)"),
    (b"; curl ",           "cmd_downloader", "Command injection (curl)"),
    (b"' OR '1'='1",       "sqli_or",        "SQL injection (OR 1=1)"),
    (b"\" OR \"1\"=\"1",   "sqli_or",        "SQL injection (OR 1=1)"),
    (b"UNION SELECT",      "sqli_union",     "SQL injection (UNION SELECT)"),
    (b"<script>",          "xss_attempt",    "Cross-site scripting (XSS)"),
    (b"/bin/sh",           "shell_spawn",    "Shell execution attempt (/bin/sh)"),
    (b"/bin/bash",         "shell_spawn",    "Shell execution attempt (/bin/bash)"),
]


# ── RAQIB Event Logging ─────────────────────────────────────────────────
EVENTS_FILE: str | None = None
JSON_MODE = False
LOG_FILE:  str | None = None


def emit_event(sev: str, msg: str) -> None:
    """Append to RAQIB's .raqib_events.jsonl — exact common.sh schema."""
    if not EVENTS_FILE:
        return
    try:
        line = json.dumps({
            "timestamp": datetime.datetime.now(datetime.timezone.utc
                         ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host":      socket.gethostname() or "unknown",
            "severity":  sev,
            "tool":      TOOL,
            "message":   msg,
            "operator":  os.environ.get("RAQIB_OPERATOR", "unknown"),
            "product":   "RAQIB",
        }, ensure_ascii=False)
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def json_out(obj: dict) -> None:
    """Print one NDJSON line to stdout (--json mode only)."""
    if JSON_MODE:
        print(json.dumps(obj, ensure_ascii=False), flush=True)


def log_connection(record: dict) -> None:
    """Write a connection record to the optional --log file."""
    if not LOG_FILE:
        return
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def human(sev: str, text: str) -> None:
    """Print a coloured line in human (non-JSON) mode."""
    if JSON_MODE:
        return
    color = SEV_COLOR.get(sev, "")
    badge = SEV_BADGE.get(sev, "")
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"  {GREY}[{ts}]{NC} {badge} {color}{text}{NC}", flush=True)


# ── Payload Analysis ────────────────────────────────────────────────────

def analyze_payload(data: bytes) -> list[tuple[str, str, str]]:
    """Match captured bytes against heuristic signatures.

    Returns list of (signature_id, description, severity).
    Every finding is explainable: what pattern matched and why it matters.
    """
    if not data:
        return []
    findings: list[tuple[str, str, str]] = []
    lower = data.lower()

    for pat, sid, desc in EXPLOIT_SIGS:
        if pat.lower() in lower:
            findings.append((sid, desc, "critical"))
    for pat, sid, desc in SCANNER_SIGS:
        if pat.lower() in lower:
            findings.append((sid, desc, "high"))
    return findings


# ── Rate Tracker ─────────────────────────────────────────────────────────

class RateTracker:
    """Per-IP connection frequency tracker (sliding 60-second window)."""

    def __init__(self, limit: int = 30):
        self.limit = limit
        self._lock = threading.Lock()
        self._ts: dict[str, list[float]] = defaultdict(list)

    def record(self, ip: str) -> tuple[int, bool]:
        """Return (count_in_window, is_suppressed)."""
        now = time.time()
        cutoff = now - 60.0
        with self._lock:
            self._ts[ip] = [t for t in self._ts[ip] if t > cutoff]
            self._ts[ip].append(now)
            n = len(self._ts[ip])
            return n, n > self.limit


# ── Session Statistics ───────────────────────────────────────────────────

class Stats:
    """Thread-safe connection statistics for the session summary."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total = 0
        self.ip_counts: dict[str, int] = defaultdict(int)
        self.port_counts: dict[int, int] = defaultdict(int)
        self.sev_counts: dict[str, int] = defaultdict(int)
        self.start = time.time()

    def record(self, ip: str, port: int, sev: str) -> None:
        with self._lock:
            self.total += 1
            self.ip_counts[ip] += 1
            self.port_counts[port] += 1
            self.sev_counts[sev] += 1

    def summary(self) -> dict:
        with self._lock:
            elapsed = time.time() - self.start
            h, rem = divmod(int(elapsed), 3600)
            m, s = divmod(rem, 60)
            return {
                "total_connections":   self.total,
                "unique_source_ips":   len(self.ip_counts),
                "top_source_ips":      dict(sorted(self.ip_counts.items(),
                                                   key=lambda x: x[1],
                                                   reverse=True)[:10]),
                "connections_per_port": dict(self.port_counts),
                "findings_by_severity": dict(self.sev_counts),
                "uptime":              f"{h}h{m:02d}m{s:02d}s",
            }


# ── Honeypot Core ────────────────────────────────────────────────────────

class Honeypot:
    """Multi-port low-interaction honeypot."""

    def __init__(self, ports: list[int], bind: str, banner: str | None,
                 max_capture: int, rate_limit: int) -> None:
        self.ports = ports
        self.bind = bind
        self.banner_override = banner
        self.max_capture = max_capture
        self.rate = RateTracker(rate_limit)
        self.stats = Stats()
        self.running = True
        self._sockets: list[socket.socket] = []
        self._threads: list[threading.Thread] = []

    # ── helpers ──────────────────────────────────────────────────────────

    def _banner_for(self, port: int) -> bytes:
        if self.banner_override:
            return BANNERS.get(self.banner_override, b"")
        return BANNERS.get(PORT_SERVICE.get(port, "none"), b"")

    def _service_for(self, port: int) -> str:
        if self.banner_override and self.banner_override != "none":
            return self.banner_override
        return PORT_SERVICE.get(port, "unknown")

    # ── connection handler ───────────────────────────────────────────────

    def _handle(self, conn: socket.socket, addr: tuple, port: int) -> None:
        src_ip, src_port = addr[0], addr[1]
        service = self._service_for(port)

        try:
            # Rate limit
            count, suppressed = self.rate.record(src_ip)
            if suppressed:
                return                       # silently drop flood

            # Send banner (make scanners reveal their payloads)
            banner = self._banner_for(port)
            if banner:
                try:
                    conn.sendall(banner)
                except OSError:
                    pass

            # Capture payload
            conn.settimeout(5.0)
            data = b""
            try:
                data = conn.recv(self.max_capture)
            except (socket.timeout, ConnectionResetError, OSError):
                pass

            # Analyse
            sigs = analyze_payload(data)

            # Severity logic — explainable heuristics, no ML
            if sigs:
                sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                severity = max(sigs, key=lambda s: sev_rank.get(s[2], 0))[2]
            elif count >= 10:
                severity = "high"            # aggressive repeat prober
            elif count >= 3 or data:
                severity = "medium"          # repeat or active interaction
            else:
                severity = "low"             # single silent connect

            self.stats.record(src_ip, port, severity)

            # Readable payload preview (safe ASCII, no raw binary to console)
            preview = ""
            if data:
                preview = (data[:80]
                           .decode("utf-8", errors="replace")
                           .replace("\r", "\\r").replace("\n", "\\n"))

            # ── Human output ─────────────────────────────────────────────
            human(severity,
                  f"Connection: {src_ip}:{src_port} → :{port} ({service})"
                  + (f"  [{len(data)}B]" if data else ""))
            if preview and not JSON_MODE:
                print(f"    {GREY}Preview: {preview}{NC}", flush=True)
            for sid, desc, ssev in sigs:
                human(ssev, f"  ⚡ {desc}")

            # ── What / Why / Fix — appended to every finding ─────────────
            what_checked  = (f"TCP connection on honeypot port {port} "
                             f"({service} banner)")
            what_found    = (f"Connection from {src_ip}:{src_port}"
                             + (f" with {len(data)}-byte payload" if data else "")
                             + (f", attempt #{count}" if count > 1 else ""))
            why_matters   = ("This port should carry no legitimate traffic — "
                             "any connection is suspicious reconnaissance or "
                             "an attack attempt")
            suggested_fix = (f"Investigate {src_ip}: whois, reverse DNS, "
                             f"geo-IP.  Block via firewall if unauthorised")

            if not JSON_MODE and sigs:
                print(f"    {YELLOW}Why:{NC} {why_matters}", flush=True)
                print(f"    {YELLOW}Fix:{NC} {suggested_fix}", flush=True)

            # ── SIEM event ───────────────────────────────────────────────
            base_msg = (f"honeypot_connection: {src_ip}:{src_port} → "
                        f"port {port}/{service}")
            if data:
                base_msg += f" — {len(data)} bytes captured"
            if count > 1:
                base_msg += f" (attempt #{count})"
            emit_event(severity, base_msg)

            for sid, desc, ssev in sigs:
                emit_event(ssev,
                           f"honeypot_signature: {sid} from {src_ip} "
                           f"on port {port} — {desc}")

            # ── JSON stream ──────────────────────────────────────────────
            record = {
                "timestamp":     datetime.datetime.now(
                                     datetime.timezone.utc
                                 ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "event":         "honeypot_connection",
                "source_ip":     src_ip,
                "source_port":   src_port,
                "dest_port":     port,
                "service":       service,
                "severity":      severity,
                "data_bytes":    len(data),
                "data_hex":      data.hex()[:2048] if data else "",
                "data_preview":  preview,
                "conn_count":    count,
                "signatures":    [{"id": s[0], "description": s[1],
                                   "severity": s[2]} for s in sigs],
                "what_checked":  what_checked,
                "what_found":    what_found,
                "why_it_matters": why_matters,
                "suggested_fix": suggested_fix,
            }
            json_out(record)
            log_connection(record)

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ── per-port listener ────────────────────────────────────────────────

    def _listen(self, port: int) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)
            sock.bind((self.bind, port))
            sock.listen(5)
            self._sockets.append(sock)
        except PermissionError:
            human("high",
                  f"Permission denied on port {port} — "
                  f"use sudo or a port > 1024")
            emit_event("medium",
                       f"honeypot_error: Permission denied for port {port}")
            return
        except OSError as exc:
            human("high", f"Cannot bind port {port}: {exc}")
            emit_event("medium",
                       f"honeypot_error: Cannot bind port {port}: {exc}")
            return

        service = self._service_for(port)
        human("low", f"Listening on {self.bind}:{port} ({service})")

        while self.running:
            try:
                conn, addr = sock.accept()
                t = threading.Thread(target=self._handle,
                                     args=(conn, addr, port),
                                     daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    human("high", f"Socket error on port {port}")
                break

    # ── lifecycle ────────────────────────────────────────────────────────

    def start(self) -> None:
        for port in self.ports:
            t = threading.Thread(target=self._listen, args=(port,),
                                 daemon=True)
            t.start()
            self._threads.append(t)
        time.sleep(0.5)                      # let listeners bind

        active = len(self._sockets)
        if active == 0:
            human("high", "No ports could be bound — exiting")
            sys.exit(2)
        human("low",
              f"{active}/{len(self.ports)} port(s) active — "
              f"waiting for connections  (Ctrl+C to stop)")

    def stop(self) -> None:
        self.running = False
        for s in self._sockets:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=3)

    def print_summary(self) -> int:
        """Print session summary.  Returns total connection count."""
        s = self.stats.summary()

        if JSON_MODE:
            json_out({"event": "honeypot_summary", **s})
        else:
            print(f"\n  {BOLD}{CYAN}{'═' * 60}{NC}")
            print(f"  {BOLD}RAQIB Honeypot — Session Summary{NC}")
            print(f"  {CYAN}{'─' * 60}{NC}")
            print(f"  {YELLOW}Uptime:{NC}              {s['uptime']}")
            print(f"  {YELLOW}Total connections:{NC}   {s['total_connections']}")
            print(f"  {YELLOW}Unique source IPs:{NC}  "
                  f"{s['unique_source_ips']}")

            if s["connections_per_port"]:
                print(f"  {YELLOW}Per port:{NC}")
                for p, n in sorted(s["connections_per_port"].items()):
                    svc = self._service_for(p)
                    print(f"    :{p} ({svc}) → {n} connections")

            if s["findings_by_severity"]:
                sev_order = {"critical": 4, "high": 3,
                             "medium": 2, "low": 1}
                print(f"  {YELLOW}By severity:{NC}")
                for sev, n in sorted(s["findings_by_severity"].items(),
                                     key=lambda x: sev_order.get(x[0], 0),
                                     reverse=True):
                    print(f"    {SEV_BADGE.get(sev, '')} {sev}: {n}")

            if s["top_source_ips"]:
                print(f"  {YELLOW}Top source IPs:{NC}")
                for ip, n in sorted(s["top_source_ips"].items(),
                                    key=lambda x: x[1], reverse=True)[:5]:
                    print(f"    {ip} → {n} connections")

            print(f"  {CYAN}{'═' * 60}{NC}\n")

        if s["total_connections"] > 0:
            emit_event("medium",
                       f"honeypot_summary: {s['total_connections']} "
                       f"connections from {s['unique_source_ips']} "
                       f"unique IPs during {s['uptime']} session")

        return s["total_connections"]


# ── Main ─────────────────────────────────────────────────────────────────

def main() -> None:
    global EVENTS_FILE, JSON_MODE, LOG_FILE  # noqa: PLW0603

    # ── arg-parse ────────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog="raqib_honeypot",
        description="RAQIB Honeypot — low-interaction network honeypot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=USAGE,
    )
    parser.add_argument("--ports", required=True,
                        help="Comma-separated TCP ports to listen on")
    parser.add_argument("--bind", default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--banner", choices=list(BANNERS.keys()),
                        default=None,
                        help="Force banner type for all ports")
    parser.add_argument("--json", action="store_true", dest="json_mode",
                        help="Stream NDJSON events to stdout")
    parser.add_argument("--log", metavar="FILE", default=None,
                        help="Write events to a separate JSONL file")
    parser.add_argument("--max-capture", type=int, default=1024,
                        metavar="N",
                        help="Max bytes per connection (default: 1024)")
    parser.add_argument("--rate-limit", type=int, default=30, metavar="N",
                        help="Max conn/IP/min before suppressing (default: 30)")

    args = parser.parse_args()

    # ── validate ports ───────────────────────────────────────────────────
    try:
        ports = sorted(set(
            int(p.strip()) for p in args.ports.split(",") if p.strip()
        ))
        for p in ports:
            if not 1 <= p <= 65535:
                print(f"Error: port {p} out of range (1-65535)",
                      file=sys.stderr)
                sys.exit(2)
    except ValueError:
        print("Error: --ports must be comma-separated integers",
              file=sys.stderr)
        sys.exit(2)

    if not ports:
        print("Error: at least one port is required", file=sys.stderr)
        sys.exit(2)

    JSON_MODE = args.json_mode
    LOG_FILE  = args.log

    # ── locate RAQIB event log (same discovery as email_header_analyzer) ─
    here = Path(__file__).resolve().parent
    for cand in (here / ".." / ".." / ".raqib_events.jsonl",
                 here / ".raqib_events.jsonl"):
        if cand.exists():
            EVENTS_FILE = str(cand.resolve())
            break

    # ── startup banner ───────────────────────────────────────────────────
    if not JSON_MODE:
        print(f"\n  {BOLD}{GREEN}🍯 RAQIB Honeypot — مصيدة شبكية{NC}")
        print(f"  {GREY}{'─' * 60}{NC}")
        print(f"  {YELLOW}Ports:{NC}        "
              f"{', '.join(str(p) for p in ports)}")
        print(f"  {YELLOW}Bind:{NC}         {args.bind}")
        print(f"  {YELLOW}Max capture:{NC}  {args.max_capture} bytes")
        print(f"  {YELLOW}Rate limit:{NC}   {args.rate_limit}/IP/min")
        if EVENTS_FILE:
            print(f"  {YELLOW}SIEM log:{NC}     {EVENTS_FILE}")
        else:
            print(f"  {YELLOW}SIEM log:{NC}     {GREY}(not found — events "
                  f"will not be persisted){NC}")
        if LOG_FILE:
            print(f"  {YELLOW}Session log:{NC}  {LOG_FILE}")
        print(f"  {GREY}{'─' * 60}{NC}")
        print(f"  {CYAN}Press Ctrl+C to stop and view summary{NC}\n")

    emit_event("low",
               f"honeypot_start: Listening on ports "
               f"{','.join(str(p) for p in ports)} (bind={args.bind})")

    # ── run ──────────────────────────────────────────────────────────────
    hp = Honeypot(ports=ports, bind=args.bind,
                  banner=args.banner,
                  max_capture=args.max_capture,
                  rate_limit=args.rate_limit)

    def _shutdown(signum, frame):             # noqa: ARG001
        if not JSON_MODE:
            print(f"\n  {YELLOW}Shutting down...{NC}")
        hp.running = False

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    hp.start()

    # block until stopped
    while hp.running:
        time.sleep(0.5)

    hp.stop()
    total = hp.print_summary()

    emit_event("low",
               f"honeypot_stop: Session ended — {total} total connections")

    sys.exit(1 if total > 0 else 0)


if __name__ == "__main__":
    main()
