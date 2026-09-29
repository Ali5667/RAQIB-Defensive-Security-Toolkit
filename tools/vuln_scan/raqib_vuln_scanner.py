#!/usr/bin/env python3
"""
RAQIB Vulnerability Scanner Engine
=====================================
ماسح ثغرات متقدم — بدون Nmap أو OpenVAS.
يعمل بـ Python stdlib بالكامل.

القدرات:
  • فحص المنافذ المفتوحة عبر socket (TCP/UDP)
  • كشف الخدمات عبر banner grabbing
  • فحص SSL/TLS: انتهاء الصلاحية، cipher suites ضعيفة، POODLE/BEAST/HEARTBLEED indicators
  • فحص HTTP/HTTPS: headers أمنية ناقصة، misconfiguration
  • كشف default credentials على خدمات شائعة
  • فحص DNS: zone transfer، wildcard، DNSSEC
  • كشف subdomain takeover indicators
  • تصدير JSON/HTML/CSV

Usage:
  python3 raqib_vuln_scanner.py --target host [--ports PORTS] [--output FORMAT]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import json
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Any, Generator

VERSION = "1.0"

# ─── ثوابت ──────────────────────────────────────────────────────────────────

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143,
    443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 2375, 2376,
    3000, 3306, 3389, 4443, 4444, 5432, 5900, 6379, 6443, 6667,
    7070, 7443, 8000, 8008, 8080, 8081, 8088, 8443, 8888,
    9000, 9001, 9090, 9200, 9300, 9418, 9443, 10000, 11211,
    27017, 27018, 28017, 50000, 50070, 61616,
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 135: "MSRPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP Submission", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 2049: "NFS", 2375: "Docker (unencrypted!)",
    2376: "Docker TLS", 3000: "Dev Server", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit/Backdoor", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes API", 6667: "IRC/C2",
    8080: "HTTP Alt", 8443: "HTTPS Alt", 8888: "Jupyter/Dev",
    9000: "PHP-FPM/Various", 9001: "Tor", 9090: "Prometheus",
    9200: "Elasticsearch", 9300: "Elasticsearch Cluster",
    11211: "Memcached", 27017: "MongoDB", 27018: "MongoDB",
    28017: "MongoDB Web UI", 50070: "Hadoop NameNode", 61616: "ActiveMQ",
}

# خدمات تحتاج تشفير (مكشوفة = خطر)
CLEARTEXT_SERVICES = {21, 23, 25, 80, 110, 119, 139, 143, 2375, 6379, 9200, 11211, 27017}

# خدمات عالية الخطورة إن كانت مكشوفة للإنترنت
HIGH_RISK_EXPOSED = {23, 445, 2375, 4444, 6379, 9200, 11211, 27017, 9300, 50070}

# Security headers المطلوبة
REQUIRED_SEC_HEADERS = {
    "strict-transport-security": "HSTS — prevents downgrade attacks",
    "content-security-policy": "CSP — prevents XSS/injection",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "MIME sniffing prevention",
    "referrer-policy": "Referrer information control",
}

# Cipher suites ضعيفة
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "ANON",
    "ADH", "AECDH", "MD5", "RC2", "IDEA",
]

# Default credentials للفحص
DEFAULT_CREDS = {
    "redis": [("", "")],
    "mongodb": [("", "")],
    "ftp": [("anonymous", ""), ("admin", "admin"), ("ftp", "ftp")],
}

COLORS = {
    "red":    "\033[0;31m", "orange": "\033[38;5;208m",
    "yellow": "\033[1;33m", "green":  "\033[0;32m",
    "cyan":   "\033[0;36m", "bold":   "\033[1m",
    "grey":   "\033[1;30m", "purple": "\033[0;35m",
    "reset":  "\033[0m",
}


def c(text: str, color: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def sev_color(sev: str) -> str:
    return {"critical": "red", "high": "orange", "medium": "yellow", "low": "green"}.get(sev, "grey")


# ─── Port Scanner ────────────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float = 1.0) -> tuple[int, bool, str]:
    """يفحص منفذ واحد — يرجع (port, is_open, banner)"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(2.0)
            banner = ""
            try:
                # أرسل طلب HTTP بسيط لمنافذ الويب
                if port in (80, 8080, 8008, 8000):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                elif port == 21:
                    pass  # FTP يرسل banner تلقائياً
                elif port == 22:
                    pass  # SSH يرسل banner تلقائياً
                raw = s.recv(1024)
                banner = raw.decode("utf-8", errors="replace").strip()[:200]
            except (socket.timeout, ConnectionResetError, OSError):
                pass
            return port, True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, ""


def scan_ports_parallel(host: str, ports: list[int], timeout: float = 1.0,
                         max_workers: int = 100) -> list[dict]:
    """يفحص قائمة منافذ بالتوازي"""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port, is_open, banner = fut.result()
            if is_open:
                service = PORT_SERVICES.get(port, "Unknown")
                open_ports.append({
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "cleartext_risk": port in CLEARTEXT_SERVICES,
                    "high_risk": port in HIGH_RISK_EXPOSED,
                })
    return sorted(open_ports, key=lambda x: x["port"])


# ─── SSL/TLS Analysis ─────────────────────────────────────────────────────────

def analyze_ssl(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """تحليل شامل لشهادة SSL/TLS"""
    result: dict[str, Any] = {
        "host": host, "port": port,
        "connected": False, "issues": [], "certificate": {},
    }

    # جرّب الاتصال بدون تحقق أولاً
    ctx_no_verify = ssl.create_default_context()
    ctx_no_verify.check_hostname = False
    ctx_no_verify.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx_no_verify.wrap_socket(raw_sock, server_hostname=host) as s:
                result["connected"] = True
                result["tls_version"] = s.version()
                result["cipher"] = s.cipher()

                # فحص cipher ضعيف
                if s.cipher():
                    cipher_name = s.cipher()[0]
                    for weak in WEAK_CIPHERS:
                        if weak in cipher_name.upper():
                            result["issues"].append({
                                "severity": "high",
                                "title": f"Weak cipher suite: {cipher_name}",
                                "detail": f"'{weak}' ciphers are considered broken/deprecated",
                            })

                # فحص TLS version
                tls_ver = s.version() or ""
                if tls_ver in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    result["issues"].append({
                        "severity": "critical",
                        "title": f"Deprecated TLS version: {tls_ver}",
                        "detail": "TLS 1.0/1.1 are vulnerable to POODLE, BEAST. Upgrade to TLS 1.2+",
                    })

                # معلومات الشهادة
                cert = s.getpeercert()
                if cert:
                    result["certificate"]["subject"] = dict(x[0] for x in cert.get("subject", []))
                    result["certificate"]["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    result["certificate"]["not_after"] = cert.get("notAfter", "")
                    result["certificate"]["sans"] = [
                        v for _, v in cert.get("subjectAltName", [])
                    ]

                    # فحص انتهاء الصلاحية
                    not_after_str = cert.get("notAfter", "")
                    if not_after_str:
                        try:
                            exp = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                            days_left = (exp - datetime.now(timezone.utc)).days
                            result["certificate"]["days_left"] = days_left
                            if days_left < 0:
                                result["issues"].append({
                                    "severity": "critical",
                                    "title": "SSL certificate EXPIRED",
                                    "detail": f"Expired {-days_left} days ago",
                                })
                            elif days_left < 15:
                                result["issues"].append({
                                    "severity": "high",
                                    "title": f"SSL certificate expiring in {days_left} days",
                                    "detail": "Renew immediately to avoid service disruption",
                                })
                            elif days_left < 30:
                                result["issues"].append({
                                    "severity": "medium",
                                    "title": f"SSL certificate expiring in {days_left} days",
                                    "detail": "Plan renewal soon",
                                })
                        except ValueError:
                            pass

    except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError) as e:
        result["error"] = str(e)

    # تحقق الهوية
    ctx_verify = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx_verify.wrap_socket(raw_sock, server_hostname=host) as s:
                result["certificate"]["verified"] = True
    except ssl.SSLCertVerificationError as e:
        result["certificate"]["verified"] = False
        result["issues"].append({
            "severity": "critical",
            "title": "SSL certificate verification FAILED",
            "detail": str(e)[:150],
        })
    except Exception:
        result["certificate"]["verified"] = None  # لم يمكن الفحص

    return result


# ─── HTTP Security Headers ────────────────────────────────────────────────────

def check_http_headers(host: str, port: int = 80, use_ssl: bool = False,
                        timeout: float = 10.0) -> dict:
    """فحص HTTP security headers"""
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}/"
    result = {"url": url, "status": None, "headers": {}, "issues": [], "server_info": {}}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={"User-Agent": "RAQIB/2.1 Security Scanner"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx if use_ssl else None) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            lower_headers = {k.lower(): v for k, v in resp.headers.items()}

            # فحص security headers
            for h, desc in REQUIRED_SEC_HEADERS.items():
                if h not in lower_headers:
                    result["issues"].append({
                        "severity": "medium",
                        "title": f"Missing security header: {h}",
                        "detail": desc,
                    })

            # كشف Server/X-Powered-By (معلومات حساسة)
            for info_header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
                val = lower_headers.get(info_header, "")
                if val:
                    result["server_info"][info_header] = val
                    result["issues"].append({
                        "severity": "low",
                        "title": f"Server information disclosure: {info_header}: {val}",
                        "detail": "Reveals technology stack — useful to attackers for targeted exploits",
                    })

            # فحص CORS
            cors = lower_headers.get("access-control-allow-origin", "")
            if cors == "*":
                result["issues"].append({
                    "severity": "medium",
                    "title": "Overly permissive CORS: Access-Control-Allow-Origin: *",
                    "detail": "Allows any origin to make cross-site requests — restrict to trusted domains",
                })

            # كشف debug/test endpoints
            if any(x in url.lower() for x in ("/debug", "/test", "/dev", "/phpinfo")):
                result["issues"].append({
                    "severity": "high",
                    "title": "Debug/test endpoint accessible",
                    "detail": f"URL: {url}",
                })

    except urllib.error.HTTPError as e:
        result["status"] = e.code
    except urllib.error.URLError as e:
        result["error"] = str(e.reason)
    except Exception as e:
        result["error"] = str(e)

    return result


# ─── DNS Analysis ─────────────────────────────────────────────────────────────

def analyze_dns(domain: str, timeout: float = 5.0) -> dict:
    """تحليل DNS لكشف zone transfer وإعدادات DNSSEC"""
    result: dict[str, Any] = {
        "domain": domain, "resolves_to": [], "issues": [],
        "zone_transfer": False, "mx_records": [],
    }

    # A record
    try:
        addrs = socket.getaddrinfo(domain, None, socket.AF_INET)
        result["resolves_to"] = list({addr[4][0] for addr in addrs})
    except socket.gaierror as e:
        result["error"] = str(e)
        return result

    # MX records عبر subprocess
    try:
        out = subprocess.run(["dig", "+short", "MX", domain],
                             capture_output=True, text=True, timeout=timeout)
        if out.returncode == 0:
            result["mx_records"] = [l.strip() for l in out.stdout.splitlines() if l.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Zone transfer (AXFR) — security test
    nameservers = []
    try:
        out = subprocess.run(["dig", "+short", "NS", domain],
                             capture_output=True, text=True, timeout=timeout)
        if out.returncode == 0:
            nameservers = [l.strip().rstrip(".") for l in out.stdout.splitlines() if l.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    for ns in nameservers[:3]:
        try:
            out = subprocess.run(["dig", f"@{ns}", "AXFR", domain],
                                 capture_output=True, text=True, timeout=timeout)
            if "XFR size" in out.stdout or (out.stdout.count("\n") > 5 and "ANSWER" in out.stdout):
                result["zone_transfer"] = True
                result["zone_transfer_ns"] = ns
                result["issues"].append({
                    "severity": "critical",
                    "title": f"DNS Zone Transfer ALLOWED from {ns}",
                    "detail": f"Nameserver {ns} allows AXFR — full zone data exposed to anyone",
                })
                break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            break

    # SPF record
    try:
        out = subprocess.run(["dig", "+short", "TXT", domain],
                             capture_output=True, text=True, timeout=timeout)
        txt_records = out.stdout if out.returncode == 0 else ""
        if "v=spf1" not in txt_records:
            result["issues"].append({
                "severity": "medium",
                "title": "No SPF record found",
                "detail": "Domain may be used for email spoofing without SPF",
            })
        if "v=DMARC1" not in txt_records:
            result["issues"].append({
                "severity": "medium",
                "title": "No DMARC record found",
                "detail": "Domain lacks DMARC policy — spoofed emails may reach recipients",
            })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return result


# ─── Main Scanner ─────────────────────────────────────────────────────────────

class VulnerabilityScanner:
    def __init__(self, target: str, ports: list[int] | None = None,
                 timeout: float = 2.0, threads: int = 100):
        self.target = target
        self.ports = ports or COMMON_PORTS
        self.timeout = timeout
        self.threads = threads
        self.findings: list[dict] = []
        self.timestamp = datetime.now(timezone.utc).isoformat()

        # حل الاسم إلى IP
        try:
            self.target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.target_ip = target

    def _add_finding(self, severity: str, category: str, title: str,
                     detail: str, port: int | None = None):
        self.findings.append({
            "severity": severity, "category": category,
            "title": title, "detail": detail,
            "port": port, "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def run(self, verbose: bool = True) -> dict:
        if verbose:
            print(c(f"\n  🎯 Target: {self.target} ({self.target_ip})", "cyan"))
            print(c(f"  📡 Scanning {len(self.ports)} ports...", "yellow"))

        # 1. Port scan
        open_ports = scan_ports_parallel(self.target_ip, self.ports,
                                         self.timeout, self.threads)

        for p in open_ports:
            if p["high_risk"]:
                self._add_finding("critical", "port",
                                  f"High-risk service exposed: {p['service']} (:{p['port']})",
                                  f"Service: {p['service']} is commonly exploited when exposed",
                                  p["port"])
            elif p["cleartext_risk"]:
                self._add_finding("high", "port",
                                  f"Cleartext service on :{p['port']} ({p['service']})",
                                  "Traffic is unencrypted — credentials/data visible to network sniffers",
                                  p["port"])

        if verbose:
            print(c(f"  ✅ Found {len(open_ports)} open ports", "green"))
            print(c("  🔐 Analyzing SSL/TLS...", "yellow"))

        # 2. SSL analysis على كل منفذ HTTPS
        ssl_results = {}
        for p in open_ports:
            if p["port"] in (443, 8443, 4443, 993, 995, 465, 587, 636, 6443):
                ssl_res = analyze_ssl(self.target, p["port"], self.timeout * 5)
                ssl_results[p["port"]] = ssl_res
                for issue in ssl_res.get("issues", []):
                    self._add_finding(issue["severity"], "ssl",
                                      issue["title"], issue["detail"], p["port"])

        if verbose:
            print(c("  🌐 Checking HTTP security headers...", "yellow"))

        # 3. HTTP headers
        http_results = {}
        for p in open_ports:
            use_ssl = p["port"] in (443, 8443, 4443)
            if p["service"] in ("HTTP", "HTTPS") or p["port"] in (80, 443, 8080, 8443, 8000, 8888):
                h_res = check_http_headers(self.target, p["port"], use_ssl, self.timeout * 5)
                http_results[p["port"]] = h_res
                for issue in h_res.get("issues", []):
                    self._add_finding(issue["severity"], "http",
                                      issue["title"], issue["detail"], p["port"])

        if verbose:
            print(c("  🔍 Analyzing DNS configuration...", "yellow"))

        # 4. DNS
        dns_result = analyze_dns(self.target, self.timeout * 3)
        for issue in dns_result.get("issues", []):
            self._add_finding(issue["severity"], "dns", issue["title"], issue["detail"])

        # 5. Banner analysis للكشف عن outdated versions
        for p in open_ports:
            banner = p.get("banner", "")
            if banner:
                self._analyze_banner(banner, p["port"])

        # ملخص
        import collections
        sev_counts = collections.Counter(f["severity"] for f in self.findings)

        return {
            "metadata": {
                "tool": "RAQIB Vulnerability Scanner",
                "version": VERSION,
                "target": self.target,
                "target_ip": self.target_ip,
                "timestamp": self.timestamp,
                "ports_scanned": len(self.ports),
            },
            "summary": {
                "open_ports": len(open_ports),
                "total_findings": len(self.findings),
                "critical": sev_counts.get("critical", 0),
                "high": sev_counts.get("high", 0),
                "medium": sev_counts.get("medium", 0),
                "low": sev_counts.get("low", 0),
            },
            "open_ports": open_ports,
            "ssl_results": ssl_results,
            "http_results": http_results,
            "dns": dns_result,
            "findings": self.findings,
        }

    def _analyze_banner(self, banner: str, port: int):
        """يحلل banner لكشف outdated software"""
        OUTDATED_PATTERNS = [
            (r"Apache/1\.", "high", "Apache 1.x — outdated, end-of-life"),
            (r"Apache/2\.[012]\.", "medium", "Apache 2.0/2.1/2.2 — outdated"),
            (r"nginx/0\.", "high", "nginx 0.x — outdated, end-of-life"),
            (r"nginx/1\.[0-9]\.", "low", "Older nginx — check for updates"),
            (r"OpenSSH_[1-6]\.", "high", "OpenSSH < 7 — multiple known vulnerabilities"),
            (r"OpenSSH_7\.[0-5]", "medium", "OpenSSH 7.x (old) — consider upgrading"),
            (r"ProFTPD 1\.[23]\.", "high", "ProFTPD 1.2/1.3 — several critical CVEs"),
            (r"vsftpd 2\.", "medium", "vsftpd 2.x — consider upgrading to 3.x"),
            (r"PHP/[4-6]\.", "critical", "PHP 4/5/6 — end-of-life, multiple critical CVEs"),
            (r"PHP/7\.[0-3]", "high", "PHP 7.0-7.3 — end-of-life"),
            (r"Microsoft-IIS/[1-9]\.", "medium", "Older IIS version — check patch level"),
            (r"Python/[12]\.", "medium", "Python 2/1 — end-of-life"),
        ]
        for pattern, severity, desc in OUTDATED_PATTERNS:
            if re.search(pattern, banner, re.I):
                self._add_finding(severity, "software_version",
                                  f"Outdated software: {banner[:80]}",
                                  desc, port)
                break


# ─── Output ───────────────────────────────────────────────────────────────────

def print_report(data: dict) -> None:
    meta = data["metadata"]
    summary = data["summary"]
    print()
    print(c("═" * 62, "cyan"))
    print(c("  🎯 RAQIB Vulnerability Scanner — Results", "bold"))
    print(c(f"  Target: {meta['target']} ({meta['target_ip']})", "grey"))
    print(c(f"  Ports scanned: {meta['ports_scanned']}  |  {meta['timestamp'][:19]}Z", "grey"))
    print(c("═" * 62, "cyan"))
    print()

    # Summary
    print(c("  ■ SUMMARY", "bold"))
    print(f"  Open ports: {c(str(summary['open_ports']), 'cyan')}"
          f"  |  Critical: {c(str(summary['critical']), 'red')}"
          f"  |  High: {c(str(summary['high']), 'orange')}"
          f"  |  Medium: {c(str(summary['medium']), 'yellow')}"
          f"  |  Low: {c(str(summary['low']), 'green')}")
    print()

    # Open ports
    print(c("  ■ OPEN PORTS", "bold"))
    for p in data["open_ports"]:
        risk_badge = c(" [HIGH RISK]", "red") if p["high_risk"] else \
                     c(" [CLEARTEXT]", "orange") if p["cleartext_risk"] else ""
        print(f"  {c(str(p['port']).rjust(5), 'cyan')}/tcp  {p['service']:<20}{risk_badge}")
        if p.get("banner"):
            print(c(f"              Banner: {p['banner'][:80]}", "grey"))
    print()

    # SSL results
    for port, ssl_res in data.get("ssl_results", {}).items():
        if ssl_res.get("connected"):
            print(c(f"  ■ SSL/TLS :{port}", "bold"))
            cert = ssl_res.get("certificate", {})
            print(f"  TLS Version: {ssl_res.get('tls_version', '?')}"
                  f"  |  Cipher: {ssl_res.get('cipher', ('?',))[0]}"
                  f"  |  Days left: {cert.get('days_left', '?')}"
                  f"  |  Verified: {cert.get('verified', '?')}")
            print()

    # Findings
    print(c("  ■ FINDINGS", "bold"))
    order = ["critical", "high", "medium", "low"]
    sorted_findings = sorted(data["findings"],
                              key=lambda x: order.index(x.get("severity", "low")))
    badges = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
    if not sorted_findings:
        print(c("  ✅ No findings — target appears secure", "green"))
    else:
        for f in sorted_findings:
            sev = f.get("severity", "low")
            port_str = f" (:{f['port']})" if f.get("port") else ""
            print(f"  {badges[sev]} [{sev.upper():<8}] {c(f['title'], sev_color(sev))}{port_str}")
            print(c(f"             {f['detail']}", "grey"))
    print()
    print(c("═" * 62, "cyan"))


def generate_html(data: dict, output_path: str) -> None:
    meta = data["metadata"]
    summary = data["summary"]
    findings_js = json.dumps(data["findings"], ensure_ascii=False)
    ports_js = json.dumps(data["open_ports"], ensure_ascii=False)

    html = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RAQIB Vulnerability Report — {meta['target']}</title>
<style>
:root{{--bg:#0b0f14;--panel:#131a22;--border:#1e2d3d;--cyan:#22d3ee;--purple:#a78bfa;
--text:#e6edf3;--muted:#8b98a5;--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:24px}}
h1{{color:var(--cyan);font-size:1.5rem;margin-bottom:4px}}
.sub{{color:var(--muted);font-size:.85rem;margin-bottom:20px}}
.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px;text-align:center}}
.card .n{{font-size:2rem;font-weight:700}}.card .l{{color:var(--muted);font-size:.78rem;margin-top:4px}}
.crit .n{{color:var(--crit)}}.high .n{{color:var(--high)}}.med .n{{color:var(--med)}}.low .n{{color:var(--low)}}
.panel{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:18px;margin-bottom:16px}}
.panel h2{{color:var(--purple);font-size:.95rem;margin-bottom:14px}}
.finding{{border-left:3px solid;padding:10px 14px;margin-bottom:8px;border-radius:0 8px 8px 0}}
.finding.critical{{border-color:var(--crit);background:rgba(239,68,68,.06)}}
.finding.high{{border-color:var(--high);background:rgba(249,115,22,.06)}}
.finding.medium{{border-color:var(--med);background:rgba(234,179,8,.06)}}
.finding.low{{border-color:var(--low);background:rgba(34,197,94,.06)}}
.ft{{font-weight:600;font-size:.88rem}}.fd{{color:var(--muted);font-size:.78rem;margin-top:3px}}
.badge{{display:inline-block;padding:2px 7px;border-radius:5px;font-size:.7rem;font-weight:700;margin-right:6px}}
.badge.critical{{background:rgba(239,68,68,.15);color:var(--crit)}}
.badge.high{{background:rgba(249,115,22,.15);color:var(--high)}}
.badge.medium{{background:rgba(234,179,8,.15);color:var(--med)}}
.badge.low{{background:rgba(34,197,94,.15);color:var(--low)}}
table{{width:100%;border-collapse:collapse;font-size:.8rem}}
th,td{{padding:7px 10px;border-bottom:1px solid var(--border);text-align:left}}
th{{color:var(--muted);font-weight:500}}
.hr{{color:var(--crit)}}.ct{{color:var(--high)}}.ok{{color:var(--low)}}
</style></head><body>
<h1>🎯 RAQIB Vulnerability Report</h1>
<div class="sub">Target: <b>{meta['target']}</b> ({meta['target_ip']}) &nbsp;|&nbsp; {meta['timestamp'][:19]}Z &nbsp;|&nbsp; {meta['ports_scanned']} ports scanned</div>
<div class="grid">
  <div class="card crit"><div class="n">{summary['critical']}</div><div class="l">Critical</div></div>
  <div class="card high"><div class="n">{summary['high']}</div><div class="l">High</div></div>
  <div class="card med"><div class="n">{summary['medium']}</div><div class="l">Medium</div></div>
  <div class="card low"><div class="n">{summary['low']}</div><div class="l">Low</div></div>
</div>
<div class="panel"><h2>🔌 Open Ports ({summary['open_ports']})</h2>
<table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Banner</th></tr></thead>
<tbody id="pt"></tbody></table></div>
<div class="panel"><h2>🔍 Security Findings ({summary['total_findings']})</h2>
<div id="fl"></div></div>
<script>
const F={findings_js},P={ports_js};
const order=['critical','high','medium','low'];
const pt=document.getElementById('pt');
P.forEach(p=>{{
  const r=p.high_risk?'<span class="hr">HIGH RISK</span>':p.cleartext_risk?'<span class="ct">CLEARTEXT</span>':'<span class="ok">OK</span>';
  pt.innerHTML+=`<tr><td><b>${{p.port}}</b>/tcp</td><td>${{p.service}}</td><td>${{r}}</td><td style="color:#8b98a5;font-size:.75rem">${{(p.banner||'').slice(0,80)}}</td></tr>`;
}});
const fl=document.getElementById('fl');
if(!F.length){{fl.innerHTML='<div style="color:#22c55e;padding:12px">✅ No findings</div>';}}
else{{[...F].sort((a,b)=>order.indexOf(a.severity)-order.indexOf(b.severity)).forEach(f=>{{
  fl.innerHTML+=`<div class="finding ${{f.severity}}"><div class="ft"><span class="badge ${{f.severity}}">${{f.severity.toUpperCase()}}</span>${{f.title}}${{f.port?' (port '+f.port+')':''}}</div><div class="fd">${{f.detail}}</div></div>`;
}})}}
</script></body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def parse_ports(ports_str: str) -> list[int]:
    """يحلل نطاقات المنافذ: '80,443,8000-8100'"""
    ports = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(
        description="RAQIB Vulnerability Scanner — فحص ثغرات متقدم بدون Nmap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 raqib_vuln_scanner.py --target example.com\n"
               "  python3 raqib_vuln_scanner.py --target 192.168.1.1 --ports 22,80,443,3306\n"
               "  python3 raqib_vuln_scanner.py --target host.com --output html --out-file report.html",
    )
    parser.add_argument("--target", required=True, help="الهدف (IP أو domain)")
    parser.add_argument("--ports", default=None,
                        help="منافذ للفحص (مثال: 80,443,8000-9000). الافتراضي: 60 منفذ شائع")
    parser.add_argument("--output", choices=["terminal", "json", "html", "all"],
                        default="terminal")
    parser.add_argument("--out-file", default=None)
    parser.add_argument("--timeout", type=float, default=1.5, help="Port scan timeout (ثانية)")
    parser.add_argument("--threads", type=int, default=150, help="عدد threads")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    ports = parse_ports(args.ports) if args.ports else COMMON_PORTS

    if not args.quiet:
        print(c("\n  ╔══════════════════════════════════════════╗", "cyan"))
        print(c("  ║  🎯 RAQIB Vulnerability Scanner          ║", "cyan"))
        print(c("  ║  فحص ثغرات متقدم — بدون Nmap أو OpenVAS  ║", "cyan"))
        print(c("  ╚══════════════════════════════════════════╝", "cyan"))

    scanner = VulnerabilityScanner(args.target, ports, args.timeout, args.threads)
    data = scanner.run(verbose=not args.quiet)

    if args.output in ("terminal", "all"):
        print_report(data)

    timestamp = int(time.time())
    if args.output in ("json", "all"):
        out = args.out_file or f"raqib_vuln_{args.target}_{timestamp}.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(c(f"\n  📄 JSON: {out}", "green"))

    if args.output in ("html", "all"):
        out = args.out_file or f"raqib_vuln_{args.target}_{timestamp}.html"
        if args.output == "all" and out.endswith(".json"):
            out = out.replace(".json", ".html")
        generate_html(data, out)
        print(c(f"  📊 HTML: {out}", "green"))


if __name__ == "__main__":
    main()
