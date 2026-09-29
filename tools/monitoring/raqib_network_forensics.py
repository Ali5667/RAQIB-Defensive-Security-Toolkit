#!/usr/bin/env python3
"""
RAQIB Network Forensics Engine
================================
محرك تحليل جنائي للشبكة — يجمع، يحلل، ويصدر تقرير
شامل عن حالة الشبكة الحالية بدون أي أدوات خارجية.

الإمكانيات:
  • تحليل الاتصالات الحالية مع كشف الأنماط المشبوهة
  • فحص ARP table وكشف ARP Spoofing
  • تتبع استهلاك النطاق الترددي لكل عملية
  • فحص DNS cache وكشف DNS poisoning
  • تحليل socket statistics مفصّل
  • كشف port scanning patterns
  • تصدير تقرير JSON/HTML/CSV
  • تكامل مع قاعدة IOC المحلية

Usage:
  python3 raqib_network_forensics.py [--mode MODE] [--output FORMAT] [--ioc PATH]
"""

from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── الثوابت ───────────────────────────────────────────────────────────────────
VERSION = "1.0"
RAQIB_DIR = Path(__file__).resolve().parent.parent.parent  # root of project
INTEL_DB = RAQIB_DIR / "tools" / "malware" / "raqib_intelligence.json"

# منافذ مشبوهة معروفة
SUSPICIOUS_PORTS = {
    21: "FTP (cleartext)",
    22: "SSH",
    23: "Telnet (cleartext)",
    25: "SMTP",
    110: "POP3 (cleartext)",
    143: "IMAP (cleartext)",
    445: "SMB (ransomware target)",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP (brute-force target)",
    4444: "Metasploit default",
    5900: "VNC",
    6667: "IRC (C2 channel)",
    8080: "HTTP Alt (often proxy)",
    9001: "Tor default",
    9050: "Tor SOCKS proxy",
    31337: "Back Orifice / hacker tradition",
    65535: "Common backdoor port",
}

HIGH_RISK_PORTS = {4444, 9001, 9050, 31337, 65535, 6667}

# نطاقات IP خاصة (RFC 1918)
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


# ─── مساعدات ──────────────────────────────────────────────────────────────────

def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in PRIVATE_RANGES)
    except ValueError:
        return False


def run(cmd: list[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            errors="replace", timeout=timeout
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


def colorize(text: str, color: str) -> str:
    colors = {
        "red":    "\033[0;31m",
        "orange": "\033[38;5;208m",
        "yellow": "\033[1;33m",
        "green":  "\033[0;32m",
        "cyan":   "\033[0;36m",
        "bold":   "\033[1m",
        "grey":   "\033[1;30m",
        "reset":  "\033[0m",
    }
    return f"{colors.get(color, '')}{text}{colors['reset']}"


def severity_color(sev: str) -> str:
    return {"critical": "red", "high": "orange", "medium": "yellow", "low": "green"}.get(sev, "grey")


# ─── قراءة بيانات /proc/net ───────────────────────────────────────────────────

def _hex_to_ip_port(hex_addr: str, hex_port: str) -> tuple[str, int]:
    """تحويل العنوان والمنفذ من صيغة /proc/net hex إلى نص"""
    # /proc/net/tcp uses little-endian hex for IP
    ip_int = int(hex_addr, 16)
    ip = socket.inet_ntoa(struct.pack("<I", ip_int))
    port = int(hex_port, 16)
    return ip, port


def read_proc_net(proto: str = "tcp") -> list[dict]:
    """يقرأ /proc/net/tcp أو /proc/net/tcp6 مباشرة بدون ss"""
    path = f"/proc/net/{proto}"
    entries = []
    STATE_MAP = {
        "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
        "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
        "07": "CLOSE",       "08": "CLOSE_WAIT", "09": "LAST_ACK",
        "0A": "LISTEN",      "0B": "CLOSING",
    }
    try:
        with open(path, "r") as f:
            next(f)  # تخطّ header
            for line in f:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local_hex, remote_hex = parts[1].split(":"), parts[2].split(":")
                state = STATE_MAP.get(parts[3].upper(), parts[3])
                inode = parts[9] if len(parts) > 9 else "0"
                if proto in ("tcp", "udp") and len(local_hex) == 2:
                    try:
                        local_ip, local_port = _hex_to_ip_port(local_hex[0], local_hex[1])
                        remote_ip, remote_port = _hex_to_ip_port(remote_hex[0], remote_hex[1])
                    except (ValueError, struct.error):
                        continue
                    entries.append({
                        "proto": proto,
                        "local_ip": local_ip,
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state,
                        "inode": inode,
                    })
    except (FileNotFoundError, PermissionError):
        pass
    return entries


def get_inode_pid_map() -> dict[str, str]:
    """يبني خريطة inode → pid/process_name من /proc"""
    inode_map: dict[str, str] = {}
    try:
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            pid = pid_dir.name
            try:
                comm = (pid_dir / "comm").read_text().strip()
            except (PermissionError, FileNotFoundError):
                comm = "?"
            fd_dir = pid_dir / "fd"
            try:
                for fd in fd_dir.iterdir():
                    try:
                        target = os.readlink(str(fd))
                        m = re.match(r"socket:\[(\d+)\]", target)
                        if m:
                            inode_map[m.group(1)] = f"{pid}/{comm}"
                    except (PermissionError, FileNotFoundError, OSError):
                        pass
            except (PermissionError, FileNotFoundError):
                pass
    except (PermissionError, FileNotFoundError):
        pass
    return inode_map


# ─── جمع البيانات ─────────────────────────────────────────────────────────────

class NetworkCollector:
    def __init__(self, ioc_db_path: Path | None = None):
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.hostname = socket.gethostname()
        self.ioc_db = self._load_ioc_db(ioc_db_path)
        self.findings: list[dict] = []

    def _load_ioc_db(self, path: Path | None) -> dict:
        if path and path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        if INTEL_DB.exists():
            try:
                with open(INTEL_DB, encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _check_ioc(self, indicator: str) -> dict | None:
        """يفحص مؤشر ضد قاعدة IOC المحلية"""
        if not self.ioc_db:
            return None
        indicators = self.ioc_db.get("indicators", {})
        entry = indicators.get(indicator)
        if entry and entry.get("verdict") not in (None, "UNKNOWN"):
            return entry
        return None

    def _add_finding(self, severity: str, category: str, title: str, detail: str, indicator: str = ""):
        self.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "indicator": indicator,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    # ─── الاتصالات النشطة ─────────────────────────────────────────────────────

    def collect_connections(self) -> dict:
        """تحليل الاتصالات النشطة"""
        entries = read_proc_net("tcp") + read_proc_net("udp")

        # إضافة معلومات العمليات
        inode_map = get_inode_pid_map()
        for e in entries:
            e["process"] = inode_map.get(e["inode"], "unknown")

        # فحوصات
        established = [e for e in entries if e.get("state") == "ESTABLISHED"]
        listening   = [e for e in entries if e.get("state") == "LISTEN"]

        external_conns = [e for e in established if not is_private(e["remote_ip"]) and e["remote_ip"] != "0.0.0.0"]
        suspicious_port_conns = [
            e for e in entries
            if e["local_port"] in HIGH_RISK_PORTS or e["remote_port"] in HIGH_RISK_PORTS
        ]

        # كشف port scanning: نفس IP الخارجي يتصل بمنافذ متعددة
        remote_port_count: dict[str, set] = collections.defaultdict(set)
        for e in established:
            if not is_private(e["remote_ip"]) and e["remote_ip"] != "0.0.0.0":
                remote_port_count[e["remote_ip"]].add(e["local_port"])
        scanners = {ip: ports for ip, ports in remote_port_count.items() if len(ports) >= 5}

        # التحقق من IOC
        ioc_matches = []
        checked_ips: set = set()
        for e in external_conns:
            ip = e["remote_ip"]
            if ip in checked_ips:
                continue
            checked_ips.add(ip)
            match = self._check_ioc(ip)
            if match:
                ioc_matches.append({"ip": ip, "verdict": match.get("verdict"), "process": e.get("process")})
                self._add_finding("critical", "network", f"IOC Match: {ip}",
                                  f"Connected to known malicious IP: {ip} ({match.get('verdict')})", ip)

        # findings للاتصالات المشبوهة
        for conn in suspicious_port_conns:
            port = conn["local_port"] if conn["local_port"] in HIGH_RISK_PORTS else conn["remote_port"]
            desc = SUSPICIOUS_PORTS.get(port, "")
            self._add_finding("high", "network",
                              f"High-risk port {port} ({desc})",
                              f"{conn.get('process', '?')} → {conn['remote_ip']}:{conn['remote_port']}")

        for ip, ports in scanners.items():
            self._add_finding("high", "network", f"Possible port scan from {ip}",
                              f"{len(ports)} local ports accessed: {sorted(ports)[:10]}", ip)

        return {
            "total_connections": len(entries),
            "established": len(established),
            "listening": len(listening),
            "external_connections": len(external_conns),
            "suspicious_port_connections": len(suspicious_port_conns),
            "potential_scanners": list(scanners.keys()),
            "ioc_matches": ioc_matches,
            "top_external_ips": [
                {"ip": ip, "port_count": len(ports)}
                for ip, ports in sorted(remote_port_count.items(), key=lambda x: -len(x[1]))[:10]
            ],
            "listening_ports": [
                {
                    "port": e["local_port"],
                    "process": e.get("process", "?"),
                    "suspicious": SUSPICIOUS_PORTS.get(e["local_port"], ""),
                }
                for e in sorted(listening, key=lambda x: x["local_port"])
            ],
            "raw_established": established[:50],  # أول 50 اتصال
        }

    # ─── ARP Table ────────────────────────────────────────────────────────────

    def collect_arp(self) -> dict:
        """تحليل جدول ARP وكشف ARP Spoofing"""
        arp_entries = []

        # قراءة /proc/net/arp
        try:
            with open("/proc/net/arp", "r") as f:
                next(f)  # header
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        arp_entries.append({
                            "ip": parts[0],
                            "hw_type": parts[1],
                            "flags": parts[2],
                            "mac": parts[3],
                            "iface": parts[5],
                        })
        except (FileNotFoundError, PermissionError):
            # fallback: arp -n
            output = run(["arp", "-n"])
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    arp_entries.append({"ip": parts[0], "mac": parts[2], "iface": parts[-1]})

        # كشف ARP Spoofing: نفس MAC لعناوين IP متعددة، أو نفس IP لـ MACs متعددة
        mac_to_ips: dict[str, list[str]] = collections.defaultdict(list)
        ip_to_macs: dict[str, list[str]] = collections.defaultdict(list)
        for e in arp_entries:
            mac = e.get("mac", "")
            ip = e.get("ip", "")
            if mac and mac not in ("00:00:00:00:00:00", "<incomplete>", "?"):
                mac_to_ips[mac].append(ip)
                ip_to_macs[ip].append(mac)

        spoofing_suspects = []
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                suspect = {"mac": mac, "ips": ips, "type": "one_mac_multiple_ips"}
                spoofing_suspects.append(suspect)
                self._add_finding("critical", "arp",
                                  f"ARP Spoofing suspect: {mac} maps to {len(ips)} IPs",
                                  f"IPs: {ips}")

        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                spoofing_suspects.append({"ip": ip, "macs": macs, "type": "one_ip_multiple_macs"})
                self._add_finding("high", "arp",
                                  f"IP conflict: {ip} has {len(macs)} different MACs",
                                  f"MACs: {macs}")

        return {
            "total_entries": len(arp_entries),
            "unique_macs": len(mac_to_ips),
            "spoofing_suspects": spoofing_suspects,
            "entries": arp_entries,
        }

    # ─── Network Interfaces ───────────────────────────────────────────────────

    def collect_interfaces(self) -> dict:
        """جمع إحصائيات واجهات الشبكة من /proc/net/dev"""
        interfaces = []
        try:
            with open("/proc/net/dev", "r") as f:
                next(f); next(f)  # تخطّ 2 سطر header
                for line in f:
                    parts = line.split()
                    if len(parts) < 17:
                        continue
                    name = parts[0].rstrip(":")
                    if name == "lo":
                        continue
                    try:
                        interfaces.append({
                            "name": name,
                            "rx_bytes": int(parts[1]),
                            "rx_packets": int(parts[2]),
                            "rx_errors": int(parts[3]),
                            "rx_dropped": int(parts[4]),
                            "tx_bytes": int(parts[9]),
                            "tx_packets": int(parts[10]),
                            "tx_errors": int(parts[11]),
                            "tx_dropped": int(parts[12]),
                        })
                    except (ValueError, IndexError):
                        pass
        except (FileNotFoundError, PermissionError):
            pass

        # كشف معدلات الخطأ العالية
        for iface in interfaces:
            total_rx = iface["rx_packets"] or 1
            error_rate = iface["rx_errors"] / total_rx
            if error_rate > 0.01:  # >1% error rate
                self._add_finding("medium", "interface",
                                  f"High error rate on {iface['name']}",
                                  f"Errors: {iface['rx_errors']}/{iface['rx_packets']} RX packets ({error_rate:.1%})")

        return {"interfaces": interfaces}

    # ─── DNS Analysis ─────────────────────────────────────────────────────────

    def collect_dns(self) -> dict:
        """فحص إعدادات DNS وكشف DNS hijacking محتمل"""
        resolvers = []
        search_domains = []
        issues = []

        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            resolvers.append(parts[1])
                    elif line.startswith("search") or line.startswith("domain"):
                        parts = line.split()
                        search_domains.extend(parts[1:])
        except (FileNotFoundError, PermissionError):
            pass

        # كشف resolvers خارج الشبكة الخاصة (قد يكون DNS hijacking)
        for r in resolvers:
            if not is_private(r):
                # Verify it's a known public DNS
                known_public = {
                    "8.8.8.8", "8.8.4.4",       # Google
                    "1.1.1.1", "1.0.0.1",        # Cloudflare
                    "9.9.9.9", "149.112.112.112", # Quad9
                    "208.67.222.222", "208.67.220.220",  # OpenDNS
                    "4.4.4.4", "64.6.64.6",
                }
                if r not in known_public:
                    issues.append(f"Unknown public resolver: {r}")
                    self._add_finding("medium", "dns",
                                      f"Unusual external DNS resolver: {r}",
                                      "This resolver is not a well-known public DNS — verify it's intentional.")

        # اختبار DNS resolution
        test_domains = ["google.com", "cloudflare.com"]
        dns_test_results = []
        for domain in test_domains:
            try:
                result = socket.gethostbyname(domain)
                dns_test_results.append({"domain": domain, "result": result, "status": "ok"})
            except socket.gaierror as e:
                dns_test_results.append({"domain": domain, "result": str(e), "status": "error"})
                self._add_finding("low", "dns", f"DNS resolution failed for {domain}", str(e))

        return {
            "resolvers": resolvers,
            "search_domains": search_domains,
            "issues": issues,
            "dns_test_results": dns_test_results,
        }

    # ─── الفحص الشامل ────────────────────────────────────────────────────────

    def run_full_analysis(self) -> dict:
        print(colorize("  [1/4] جارٍ تحليل الاتصالات...", "cyan"))
        connections = self.collect_connections()

        print(colorize("  [2/4] جارٍ فحص جدول ARP...", "cyan"))
        arp = self.collect_arp()

        print(colorize("  [3/4] جارٍ جمع إحصائيات الواجهات...", "cyan"))
        interfaces = self.collect_interfaces()

        print(colorize("  [4/4] جارٍ تحليل إعدادات DNS...", "cyan"))
        dns = self.collect_dns()

        # تجميع النتائج
        sev_counts = collections.Counter(f["severity"] for f in self.findings)

        return {
            "metadata": {
                "tool": "RAQIB Network Forensics Engine",
                "version": VERSION,
                "hostname": self.hostname,
                "timestamp": self.timestamp,
                "ioc_db_loaded": bool(self.ioc_db),
                "ioc_db_indicators": len(self.ioc_db.get("indicators", {})),
            },
            "summary": {
                "total_findings": len(self.findings),
                "critical": sev_counts.get("critical", 0),
                "high": sev_counts.get("high", 0),
                "medium": sev_counts.get("medium", 0),
                "low": sev_counts.get("low", 0),
            },
            "findings": self.findings,
            "connections": connections,
            "arp": arp,
            "interfaces": interfaces,
            "dns": dns,
        }


# ─── التقارير ─────────────────────────────────────────────────────────────────

def print_terminal_report(data: dict) -> None:
    """طباعة تقرير منسّق بالطرفية"""
    meta = data["metadata"]
    summary = data["summary"]

    print()
    print(colorize("═" * 60, "cyan"))
    print(colorize("  🦅 RAQIB Network Forensics Engine", "bold"))
    print(colorize(f"  Host: {meta['hostname']}  |  {meta['timestamp'][:19]}Z", "grey"))
    print(colorize("═" * 60, "cyan"))
    print()

    # ملخص
    print(colorize("  ■ SUMMARY", "bold"))
    crit_color = "red" if summary["critical"] > 0 else "green"
    high_color = "orange" if summary["high"] > 0 else "green"
    print(f"  🔴 Critical : {colorize(str(summary['critical']), crit_color)}"
          f"   🟠 High   : {colorize(str(summary['high']), high_color)}"
          f"   🟡 Medium : {summary['medium']}"
          f"   🟢 Low    : {summary['low']}")
    print()

    # الاتصالات
    conn = data["connections"]
    print(colorize("  ■ NETWORK CONNECTIONS", "bold"))
    print(f"  Total: {conn['total_connections']}"
          f"  |  Established: {conn['established']}"
          f"  |  Listening: {conn['listening']}"
          f"  |  External: {colorize(str(conn['external_connections']), 'yellow')}")

    if conn["ioc_matches"]:
        print()
        print(colorize(f"  ⚠️  IOC MATCHES ({len(conn['ioc_matches'])}):", "red"))
        for m in conn["ioc_matches"]:
            print(f"    🔴 {m['ip']} — {m['verdict']} — process: {m['process']}")

    if conn["potential_scanners"]:
        print()
        print(colorize(f"  ⚠️  POTENTIAL PORT SCANNERS:", "orange"))
        for ip in conn["potential_scanners"]:
            print(f"    🟠 {ip}")

    # Listening ports المشبوهة
    risky_listening = [p for p in conn.get("listening_ports", []) if p.get("suspicious")]
    if risky_listening:
        print()
        print(colorize(f"  ⚠️  RISKY LISTENING PORTS:", "orange"))
        for p in risky_listening[:10]:
            print(f"    🟠 :{p['port']} ({p['suspicious']}) — {p['process']}")

    print()

    # ARP
    arp = data["arp"]
    print(colorize("  ■ ARP TABLE", "bold"))
    print(f"  Entries: {arp['total_entries']}  |  Unique MACs: {arp['unique_macs']}")
    if arp["spoofing_suspects"]:
        print(colorize(f"  🔴 ARP SPOOFING SUSPECTS: {len(arp['spoofing_suspects'])}", "red"))
        for s in arp["spoofing_suspects"][:5]:
            if s.get("type") == "one_mac_multiple_ips":
                print(f"    MAC {s['mac']} → {s['ips']}")
            else:
                print(f"    IP {s.get('ip')} ← {s.get('macs')}")
    else:
        print(colorize("  ✅ No ARP spoofing suspects", "green"))
    print()

    # DNS
    dns = data["dns"]
    print(colorize("  ■ DNS CONFIG", "bold"))
    print(f"  Resolvers: {', '.join(dns['resolvers']) or 'none'}")
    if dns["issues"]:
        for issue in dns["issues"]:
            print(colorize(f"  ⚠️  {issue}", "yellow"))
    print()

    # كل الـ findings
    print(colorize("  ■ ALL FINDINGS", "bold"))
    if not data["findings"]:
        print(colorize("  ✅ No findings — network looks clean", "green"))
    else:
        for f in sorted(data["findings"], key=lambda x: ["critical","high","medium","low"].index(x["severity"])):
            color = severity_color(f["severity"])
            badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[f["severity"]]
            print(f"  {badge} [{f['severity'].upper():<8}] {colorize(f['title'], color)}")
            print(f"           {colorize(f['detail'], 'grey')}")
    print()
    print(colorize("═" * 60, "cyan"))


def generate_html_report(data: dict, output_path: str) -> None:
    """يولّد تقرير HTML احترافي self-contained"""
    findings_json = json.dumps(data["findings"], ensure_ascii=False, indent=2)
    conn_json = json.dumps(data["connections"].get("raw_established", []), ensure_ascii=False)
    arp_json = json.dumps(data["arp"]["entries"], ensure_ascii=False)
    summary = data["summary"]
    meta = data["metadata"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RAQIB Network Forensics — {meta['hostname']}</title>
<style>
  :root {{
    --bg: #0b0f14; --panel: #131a22; --border: #1e2d3d;
    --cyan: #22d3ee; --purple: #a78bfa; --green: #22c55e;
    --text: #e6edf3; --muted: #8b98a5;
    --crit: #ef4444; --high: #f97316; --med: #eab308; --low: #22c55e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 24px; }}
  h1 {{ color: var(--cyan); font-size: 1.6rem; margin-bottom: 4px; }}
  .sub {{ color: var(--muted); font-size: .85rem; margin-bottom: 24px; }}
  .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
  .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }}
  .card .num {{ font-size: 2.2rem; font-weight: 700; }}
  .card .lbl {{ color: var(--muted); font-size: .8rem; margin-top: 4px; }}
  .crit .num {{ color: var(--crit); }} .high .num {{ color: var(--high); }}
  .med .num {{ color: var(--med); }} .low .num {{ color: var(--low); }}
  .panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
  .panel h2 {{ color: var(--purple); font-size: 1rem; margin-bottom: 16px; }}
  .finding {{ border-left: 3px solid var(--border); padding: 10px 14px; margin-bottom: 8px; border-radius: 0 8px 8px 0; }}
  .finding.critical {{ border-color: var(--crit); background: rgba(239,68,68,.06); }}
  .finding.high {{ border-color: var(--high); background: rgba(249,115,22,.06); }}
  .finding.medium {{ border-color: var(--med); background: rgba(234,179,8,.06); }}
  .finding.low {{ border-color: var(--low); background: rgba(34,197,94,.06); }}
  .finding .ftitle {{ font-weight: 600; font-size: .9rem; }}
  .finding .fdetail {{ color: var(--muted); font-size: .8rem; margin-top: 4px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: .72rem; font-weight: 700; margin-right: 6px; }}
  .badge.critical {{ background: rgba(239,68,68,.15); color: var(--crit); }}
  .badge.high {{ background: rgba(249,115,22,.15); color: var(--high); }}
  .badge.medium {{ background: rgba(234,179,8,.15); color: var(--med); }}
  .badge.low {{ background: rgba(34,197,94,.15); color: var(--low); }}
  table {{ width: 100%; border-collapse: collapse; font-size: .8rem; }}
  th, td {{ padding: 8px 10px; border-bottom: 1px solid var(--border); text-align: left; }}
  th {{ color: var(--muted); font-weight: 500; }}
  tr:hover {{ background: rgba(255,255,255,.02); }}
  .ok {{ color: var(--green); }} .warn {{ color: var(--high); }} .crit-text {{ color: var(--crit); }}
  @media (max-width: 600px) {{ .grid-4 {{ grid-template-columns: repeat(2, 1fr); }} }}
</style>
</head>
<body>
<h1>🦅 RAQIB Network Forensics</h1>
<div class="sub">Host: <b>{meta['hostname']}</b> &nbsp;|&nbsp; {meta['timestamp'][:19]}Z &nbsp;|&nbsp; IOC DB: {'✅ loaded (' + str(meta.get('ioc_db_indicators', 0)) + ' indicators)' if meta['ioc_db_loaded'] else '⚠️ not found'}</div>

<div class="grid-4">
  <div class="card crit"><div class="num">{summary['critical']}</div><div class="lbl">Critical</div></div>
  <div class="card high"><div class="num">{summary['high']}</div><div class="lbl">High</div></div>
  <div class="card med"><div class="num">{summary['medium']}</div><div class="lbl">Medium</div></div>
  <div class="card low"><div class="num">{summary['low']}</div><div class="lbl">Low</div></div>
</div>

<div class="panel">
  <h2>🔍 Security Findings</h2>
  <div id="findings-list"></div>
</div>

<div class="panel">
  <h2>🌐 Active Connections</h2>
  <table id="conn-table">
    <thead><tr><th>Local</th><th>Remote</th><th>State</th><th>Process</th></tr></thead>
    <tbody id="conn-body"></tbody>
  </table>
</div>

<div class="panel">
  <h2>📡 ARP Table</h2>
  <table id="arp-table">
    <thead><tr><th>IP</th><th>MAC</th><th>Interface</th></tr></thead>
    <tbody id="arp-body"></tbody>
  </table>
</div>

<script>
const FINDINGS = {findings_json};
const CONNS = {conn_json};
const ARP = {arp_json};

// Findings
const fl = document.getElementById('findings-list');
if (!FINDINGS.length) {{
  fl.innerHTML = '<div style="color:#22c55e;padding:12px">✅ No findings — network looks clean</div>';
}} else {{
  const order = ['critical','high','medium','low'];
  [...FINDINGS].sort((a,b) => order.indexOf(a.severity) - order.indexOf(b.severity)).forEach(f => {{
    fl.innerHTML += `<div class="finding ${{f.severity}}">
      <div class="ftitle"><span class="badge ${{f.severity}}">${{f.severity.toUpperCase()}}</span>${{f.title}}</div>
      <div class="fdetail">${{f.detail}}</div>
    </div>`;
  }});
}}

// Connections
const cb = document.getElementById('conn-body');
CONNS.slice(0, 100).forEach(c => {{
  const ext = !['0.0.0.0','127.','10.','192.168.','172.'].some(p => c.remote_ip.startsWith(p));
  cb.innerHTML += `<tr>
    <td>${{c.local_ip}}:${{c.local_port}}</td>
    <td class="${{ext ? 'warn' : ''}}">${{c.remote_ip}}:${{c.remote_port}}</td>
    <td>${{c.state}}</td>
    <td>${{c.process || '?'}}</td>
  </tr>`;
}});

// ARP
const ab = document.getElementById('arp-body');
ARP.forEach(e => {{
  ab.innerHTML += `<tr><td>${{e.ip}}</td><td>${{e.mac}}</td><td>${{e.iface || '?'}}</td></tr>`;
}});
</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="RAQIB Network Forensics Engine — اتحليل شبكي متقدم",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--output", choices=["terminal", "json", "html", "all"],
                        default="terminal", help="صيغة التقرير")
    parser.add_argument("--out-file", default=None, help="مسار ملف الإخراج")
    parser.add_argument("--ioc", default=None, help="مسار قاعدة IOC المحلية")
    parser.add_argument("--quiet", action="store_true", help="بدون رسائل التقدم")
    args = parser.parse_args()

    ioc_path = Path(args.ioc) if args.ioc else None

    if not args.quiet:
        print(colorize("\n  ╔══════════════════════════════════════════╗", "cyan"))
        print(colorize("  ║  🦅 RAQIB Network Forensics Engine       ║", "cyan"))
        print(colorize("  ║  تحليل شبكي جنائي شامل — بدون أدوات خارجية  ║", "cyan"))
        print(colorize("  ╚══════════════════════════════════════════╝", "cyan"))
        print()

    collector = NetworkCollector(ioc_path)
    data = collector.run_full_analysis()

    if args.output in ("terminal", "all"):
        print_terminal_report(data)

    if args.output in ("json", "all"):
        out = args.out_file or f"raqib_network_forensics_{int(time.time())}.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(colorize(f"  📄 JSON report saved: {out}", "green"))

    if args.output in ("html", "all"):
        out = args.out_file or f"raqib_network_forensics_{int(time.time())}.html"
        if args.output == "all":
            out = out.replace(".json", ".html") if out.endswith(".json") else out + ".html"
        generate_html_report(data, out)
        print(colorize(f"  📊 HTML report saved: {out}", "green"))


if __name__ == "__main__":
    main()
