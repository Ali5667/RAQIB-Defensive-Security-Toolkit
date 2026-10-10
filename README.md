<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=30&pause=1000&color=22D3EE&center=true&vCenter=true&width=700&lines=%F0%9F%A6%85+RAQIB+%28%D8%B1%D9%82%D9%8A%D8%A8%29;Defensive+Security+Toolkit;Blue+Team+%E2%80%94+Enterprise+Grade" alt="RAQIB"/>

# RAQIB (رقيب)
### Enterprise Defensive Security Toolkit

**The only zero-dependency incident-response platform built entirely from scratch —  
58 standalone tools · 20 languages · real-time monitoring · CTF mode · threat intelligence**

[![License: GNU](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1-blue.svg)](VERSION)
[![Bash 4+](https://img.shields.io/badge/Bash-4%2B-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-informational)](#-requirements)
[![Languages: 20](https://img.shields.io/badge/languages-20-brightgreen)](modules/lang.sh)
[![Tools: 58](https://img.shields.io/badge/tools-58-red)](tools/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Overview](#-overview) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Tools](#-tools-58) • [CTF Mode](#-ctf--wargames-mode-22-tools) • [Intelligence](#-threat-intelligence) • [Languages](#-languages-20) • [Accuracy](#-accuracy-benchmark) • [العربية](README.ar.md)

</div>

---

## 📖 Overview

**RAQIB** is a **production-grade** defensive security toolkit built for blue teams, SOC analysts, incident responders, and security engineers who need *immediate, trustworthy results* — on hardened servers with nothing extra installed.

Every single tool is written from scratch against core POSIX utilities (`ss`, `find`, `awk`, `grep`, `openssl`, `/dev/tcp`, `python3` stdlib). No Nmap. No Wireshark. No third-party security binaries. Just clean, auditable code that runs on a minimal Alpine container or a fully-locked-down production box.

58 tools across 8 operational domains, **wired together as one integrated incident-response workflow** — not a pile of disconnected scripts.

> ⚠️ **Authorized use only.** Scanning tools are for *your own infrastructure* or systems you have explicit written authorization to assess.

---

## ✨ Why RAQIB

<table>
<tr><td width="32">🚫</td><td><b>Zero external tool dependency</b><br>Runs on a fresh minimal Linux install. No apt install, no pip install, no external security binaries. Every check is written from scratch on POSIX primitives.</td></tr>
<tr><td>🧬</td><td><b>Composite malware detection — the YARA-lite engine</b><br>Scores multiple weak signals together: string concatenation, <code>chr()</code> obfuscation, hex escapes, PHP-in-image polyglots, Base64-encoded ELF blobs — instead of one brittle signature. Layers a real <code>yara</code> binary automatically if installed. F1 score: <b>98.5%</b>.</td></tr>
<tr><td>🧠</td><td><b>Local Threat Intelligence Engine</b><br>Builds and queries a local IOC database (IPs, domains, URLs, hashes) from Feodo Tracker, URLhaus, and CISA KEV — completely offline at query time. Auto-consulted by 6 other tools transparently.</td></tr>
<tr><td>📡</td><td><b>Real-time watchdog + multi-host aggregation</b><br>Background daemon monitors all 7 detection categories. Alerts via Telegram. Forwards structured JSON events to a central collector server on another machine for fleet-wide monitoring.</td></tr>
<tr><td>📊</td><td><b>Built-in SIEM correlation engine</b><br>Correlates events from all tools into composite incidents using 4 rules: multi-tool clustering, repeat-critical, off-hours activity, and escalating severity patterns. Exports CEF format for Wazuh/Splunk/ELK.</td></tr>
<tr><td>🔐</td><td><b>AES-256-GCM encrypted reports</b><br>Every saved report can be encrypted with AES-256-GCM + Argon2id KDF (memory-hard, GPU-resistant) in one keystroke. Self-describing format: old reports (Scrypt) remain decryptable forever.</td></tr>
<tr><td>🏴</td><td><b>Complete CTF / Wargames mode</b><br>22 purpose-built tools across Crypto, Stego, Forensics, Web, and Binary — from Vigenère cracking to ELF analysis to PCAP parsing. Flag Hunter + Writeup Logger included.</td></tr>
<tr><td>👤</td><td><b>Operator identity + approval workflow</b><br>PBKDF2 hashed operator accounts. Two roles (analyst/senior). Every destructive action goes through a pending-approval queue reviewable by senior operators only.</td></tr>
<tr><td>🌍</td><td><b>20 languages, 505 strings each</b><br>Every message, prompt, error, and report — fully translated. Missing string? The optional LibreTranslate bridge fills it live and caches locally.</td></tr>
<tr><td>📈</td><td><b>Honest accuracy benchmark</b><br><code>tests/run_accuracy_eval.sh</code> imports the actual production detection code and reports Precision/Recall/F1 against a manually-labeled adversarial corpus. No marketing numbers.</td></tr>
</table>

---

## 🏗️ Architecture

```
raqib/
├── raqib.sh                    ← Main entry: auth, menu routing, live clock daemon
├── VERSION · update_source.txt ← Self-update checker (disabled until you enable it)
├── README.md / README.ar.md    ← Full documentation (EN + AR)
├── LICENSE · SECURITY.md · CONTRIBUTING.md · CHANGES.md
│
├── modules/                    ← Shared kernel (sourced by every tool)
│   ├── common.sh               ← 990-line shared library:
│   │                              • AES-256-GCM encryption/decryption (Argon2id + Scrypt)
│   │                              • Structured JSON event log (SIEM-compatible)
│   │                              • Telegram alerts (push on critical findings)
│   │                              • Central collector forwarding (multi-host)
│   │                              • Severity scoring + executive summary
│   │                              • Operator identity + approval workflow
│   │                              • Report ID + scan history (last 10)
│   │                              • Cross-platform portability helpers
│   │                              • Shared quarantine + secure-delete
│   │                              • Progress bar + spinner UI components
│   ├── lang.sh                 ← 20×505 = 10,100 translation strings
│   ├── auto_translate.sh       ← LibreTranslate bridge (optional, cached)
│   └── lang_cache/             ← Auto-translated strings (local, persistent)
│
├── assets/
│   ├── eagle_logo.txt / eagle_logo_2.txt  ← ASCII art (radar-scan animation)
│   └── eagle_cry.wav           ← Startup sound (paplay / aplay / ffplay)
│
├── samples/                    ← Immediately testable sample data
├── tests/
│   ├── run_accuracy_eval.sh    ← Precision/Recall/F1 benchmark (F1=98.5%)
│   └── corpus/                 ← Manually-labeled adversarial test samples
│
└── tools/
    ├── monitoring/ (12)        ← Network + SIEM + alerting + fleet collection
    ├── logs/       (5)         ← Log analysis and parsing
    ├── ids_ips/    (6)         ← Intrusion detection and IP blocking
    ├── malware/    (12+)       ← Static analysis + threat intelligence engine
    ├── forensics/  (5)         ← Digital forensics + timeline
    ├── hardening/  (8)         ← System hardening + audit trail
    ├── vuln_scan/  (5)         ← Vulnerability and permission scanning
    └── ctf/        (22)        ← CTF / Wargames mode (Crypto/Stego/Forensics/Web/Binary)
        ├── crypto/   (5)       ← Base64/Hex/ROT/XOR/RSA/Vigenère
        ├── stego/    (4)       ← LSB/Metadata/Magic Bytes/Audio
        ├── forensics/(4)       ← PCAP/File Carving/Strings/Timeline
        ├── web/      (3)       ← Headers/JWT/Cookies/Robots
        ├── binary/   (3)       ← ELF/Packing/BOF Helper
        ├── flag_hunter.sh      ← Automated multi-pattern flag search
        └── writeup_logger.sh   ← Markdown writeup generator
```

---

## ⚙️ Quick Start

```bash
# Clone
git clone https://github.com/Ali5667/RAQIB-Defensive-Security-Toolkit.git
cd RAQIB-Defensive-Security-Toolkit

# Run (Bash 4+ required — see note for macOS)
chmod +x raqib.sh
./raqib.sh

# macOS: brew install bash && /opt/homebrew/bin/bash raqib.sh
```

### Requirements

| Requirement | Notes |
|---|---|
| **Bash 4+** | macOS ships with Bash 3 — `brew install bash` |
| **Python 3.8+** | For entropy, intelligence engine, encryption, SIEM export |
| `find`, `awk`, `grep`, `ss`, `openssl` | Core utilities — present on any Linux |
| `curl` *(optional)* | Reputation checks, rule updates, Telegram alerts |
| `yara` *(optional)* | Real YARA rule layer on top of the YARA-lite engine |
| `paplay`/`aplay`/`ffplay` *(optional)* | Startup sound |
| `python3 cryptography` *(optional)* | Report encryption (AES-256-GCM) |

---

## 📋 Tools (58)

### 🛰️ Network Monitoring (12)

| # | Tool | Description |
|---|---|---|
| 1 | **Port Scanner** | TCP port range scan via `/dev/tcp` — no Nmap |
| 2 | **Active Connections** | Live network connections via `ss`, mapped to processes |
| 3 | **Bandwidth Monitor** | Real-time upload/download rate from `/sys/class/net` |
| 4 | **ARP Watch** | ARP table baseline + change detection (ARP spoofing alerts) |
| 5 | **DNS Lookup** | Forward/reverse lookups via Python sockets — no `dig` required |
| 6 | **Ping Sweep** | Live host discovery across a subnet (validated octet ranges) |
| 7 | **SIEM Correlator** | Correlates all tool events into composite incidents (4 rules) + CEF export |
| 8 | **Telegram Setup** | Configure Telegram Bot push alerts for critical findings |
| 9 | **Dashboard Generator** | Self-contained HTML dashboard (offline-capable, no CDN) |
| 10 | **Watchdog Setup** | Background daemon that continuously monitors all 7 categories |
| 11 | **Collector Server** | Central JSON event aggregator for multi-host fleet monitoring |
| 12 | **Collector Client Setup** | Configure a host to forward its events to the collector |

### 📋 Log Analysis (5)

| # | Tool | Description |
|---|---|---|
| 1 | **Failed SSH Report** | Ranks attacking IPs by failed-login count from auth.log |
| 2 | **Log Keyword Search** | Context-aware search with surrounding lines |
| 3 | **Top Repeated Lines** | Surfaces recurring error patterns via frequency analysis |
| 4 | **Log Timeline** | Extracts events within an arbitrary time window |
| 5 | **Web Access Analyzer** | Top IPs, status codes, most-requested paths from access logs |

### 🚨 Intrusion Detection (6)

| # | Tool | Description |
|---|---|---|
| 1 | **Brute Force Detector** | Configurable threshold alert on per-IP failed attempts |
| 2 | **Listening Ports Auditor** | Maps every open port to its owning process (`ss`/`lsof`) |
| 3 | **File Integrity Monitor** | SHA256 baseline creation + delta detection |
| 4 | **Cron Auditor** | Flags recently-modified cron jobs across all users |
| 5 | **Connection Rate Watcher** | Two-snapshot delta to catch sudden connection spikes |
| 6 | **IP Blocker** | UFW/iptables/nftables rule insertion with audit logging |

### 🦠 Malware Analysis — Static (12)

| # | Tool | Description |
|---|---|---|
| 1 | **Hash Calculator** | MD5/SHA1/SHA256 — auto-offers reputation check on the result |
| 2 | **File Type Identifier** | Extension vs. real magic bytes (polyglot detection) |
| 3 | **Suspicious Strings Extractor** | IPs, URLs, Base64 blobs, dangerous shell commands |
| 4 | **Entropy Calculator** | Shannon entropy to spot packed/encrypted/compressed files |
| 5 | **Persistence Scanner** | systemd, cron, rc.local, LD_PRELOAD, ~/.profile |
| 6 | **Quarantine & Eradicate** | Hash-identical copy tracking + persistence cleanup + secure shred |
| 7 | **Auto Malware Cleaner** | Webshells + malicious cron + LD_PRELOAD + /tmp executables in one pass |
| 8 | **Hash Reputation Check** | VirusTotal API v3 + MalwareBazaar (abuse.ch) |
| 9 | **YARA-lite Scanner** | Updatable `name|weight|regex` engine — F1=98.5% on adversarial corpus |
| 10 | **Live Rules Updater** | Safe pull from your chosen source: format-validated, backed-up, local rules preserved |
| 11 | **Threat Intel Lookup** | Query and update local IOC database (Feodo/URLhaus/CISA KEV) — offline queries |
| 12 | **Unknown File Triage** | Weighted explainable heuristic scoring (6 signal types) — no ML, every point justified |

### 🔍 Digital Forensics (5)

| # | Tool | Description |
|---|---|---|
| 1 | **Login History** | `last` / `lastb` / `lastlog` combined report |
| 2 | **Bash History Reviewer** | Searches every user's history for suspicious commands |
| 3 | **Filesystem Timeline** | Chronological ordering by mtime/ctime |
| 4 | **Disk Usage Snapshot** | Folder-size comparison between two points in time |
| 5 | **Sudo Log Review** | Every executed sudo command + failed sudo attempts |

### 🛡️ System Hardening (8)

| # | Tool | Description |
|---|---|---|
| 1 | **Permission Auditor** | World-writable files, SUID/SGID binaries |
| 2 | **SSH Config Auditor** | sshd_config vs. CIS/NIST best practices |
| 3 | **Service Lister** | Enabled services + alerts for risky ones (telnet, ftp, rsh) |
| 4 | **Password Policy Checker** | login.defs + PAM + no-password accounts |
| 5 | **Firewall Status Checker** | UFW/firewalld/iptables status and default policy |
| 6 | **Report Decryptor** | AES-256-GCM report decryption (RQBv1 + RQBv2 format support) |
| 7 | **Audit Log Viewer** | Structured event log browser — by operator, recent, pending |
| 8 | **Pending Actions Review** | Senior-only approval queue for destructive actions |

### 🎯 Vulnerability Scanning (5)

| # | Tool | Description |
|---|---|---|
| 1 | **Open Ports vs. Services** | Flags known-risky exposed ports with CVE context |
| 2 | **Outdated Packages** | apt/yum/pip outdated packages with severity hints |
| 3 | **Weak Permissions Scanner** | 777/666 files, world-readable SSH keys, SUID in unusual paths |
| 4 | **SSL Certificate Checker** | Expiry countdown + cipher suite + chain validation |
| 5 | **Default Credentials Scanner** | Weak/hardcoded passwords in configs and source files |

---

## 🏴 CTF / Wargames Mode (22 tools)

Launched from the main menu — a complete, self-contained toolkit for security competitions:

<details>
<summary><b>🔐 Cryptography (5)</b></summary>

| # | Tool | Capability |
|---|---|---|
| 1 | Codec Swiss Army | Base64/Hex/ROT13/ROT47/XOR-brute/Caesar/URL/Binary/Morse — auto-detect |
| 2 | Frequency Analysis | Character frequency + cipher-type identification |
| 3 | RSA Helper | Factoring (small primes) / e=3 attack / Wiener attack |
| 4 | Hash Identifier | MD5/SHA1/SHA256/bcrypt/NTLM/Argon2 pattern matching |
| 5 | Vigenère Cracker | Kasiski test + Index of Coincidence key recovery |
</details>

<details>
<summary><b>🖼️ Steganography (4)</b></summary>

| # | Tool | Capability |
|---|---|---|
| 6 | LSB Extractor | Bit-plane extraction from PNG/BMP — brute-tests 6 channel combos |
| 7 | Metadata Reader | EXIF parsing (no exiftool required) + hidden strings + steghide |
| 8 | Magic Bytes Check | Polyglot detection + extension spoofing identification |
| 9 | Audio Stego | Spectrogram (Sox) + Morse code detection + DTMF analysis |
</details>

<details>
<summary><b>🔍 Forensics (4)</b></summary>

| # | Tool | Capability |
|---|---|---|
| 10 | PCAP Analyzer | Protocol stats / HTTP extraction / credential recovery — no Wireshark |
| 11 | File Carver | Embedded file extraction (binwalk-lite) — 20+ magic signatures |
| 12 | Strings Hunter | Smart flag-pattern search + Base64 decode + suspicious string clustering |
| 13 | Timeline Builder | Chronological artifact timeline from files/logs/EXIF |
</details>

<details>
<summary><b>🌐 Web Exploitation (3)</b></summary>

| # | Tool | Capability |
|---|---|---|
| 14 | Header Inspector | Security header audit + Method tampering + hidden path discovery |
| 15 | Cookie/JWT Decoder | JWT decode + Flask session + cookie security flags |
| 16 | Robots & Secrets | robots.txt + sitemap + 60-path CTF enumeration + source analysis |
</details>

<details>
<summary><b>⚙️ Binary / Reverse Engineering (3)</b></summary>

| # | Tool | Capability |
|---|---|---|
| 17 | ELF Analyzer | Header/sections/symbols/strings — no objdump required |
| 18 | Packing Detector | UPX + 14 packer signatures + entropy analysis + auto-unpack |
| 19 | BOF Helper | Pattern generation + offset calculation + exploitation templates |
</details>

<details>
<summary><b>🏴 Core CTF Tools (3)</b></summary>

| # | Tool | Capability |
|---|---|---|
| — | Flag Hunter | Multi-pattern automated flag search in files/directories/binary/Base64 |
| — | Writeup Logger | Markdown writeup generator with step-by-step logging |
| — | (planned) | Network trace flag recovery |
</details>

---

## 🧠 Threat Intelligence

The local intelligence engine (`tools/malware/10_raqib_intelligence.py`) is automatically consulted by **6 other tools** at scan time:

```
hash_calculator.sh ──┐
hash_reputation_check.sh ──┤
suspicious_strings_extractor.sh ──┤──► raqib_intelligence.py ──► Local IOC DB
ip_blocker.sh ──┤                      (Feodo C2 IPs + URLhaus +
active_connections.sh ──┤               CISA KEV — offline at query time)
connection_rate_watcher.sh ──┘
```

**Update once, protect everywhere** — run the Threat Intel Lookup tool to pull fresh IOCs, and every other tool immediately benefits without any configuration change.

---

## 📊 SIEM Integration

RAQIB produces a structured JSON event log (`.raqib_events.jsonl`) automatically as every tool runs. This is the same newline-delimited JSON format that **Filebeat, Wazuh agent, Logstash, and Splunk Universal Forwarder** consume directly without a custom parser.

```
Tool findings ──► finding_add() ──► .raqib_events.jsonl ──► SIEM Correlator
                                   (NDJSON, Wazuh/ELK-ready)    (4 correlation rules)
                        │                                             │
                        ▼                                             ▼
               Telegram alert                               CEF export (Splunk/ArcSight)
               (critical only)                              HTML Dashboard (offline)
                        │
                        ▼
               Collector Server
               (multi-host fleet)
```

---

## 🔐 Security Model

| Feature | Implementation |
|---|---|
| **Report encryption** | AES-256-GCM + Argon2id KDF (3 passes, 64 MiB) — falls back to Scrypt automatically |
| **Old report compatibility** | RQBv1 (Scrypt fixed) + RQBv2 (self-describing) — both always decryptable |
| **Operator authentication** | PBKDF2-HMAC-SHA256, 100k iterations, per-operator salt |
| **Approval workflow** | Destructive actions queued → senior-operator review → explicit approval |
| **Secure delete** | `shred -u -z -n 3` with `rm` fallback |
| **Code injection prevention** | All user input passed via `sys.argv`/env, never interpolated into shell strings |
| **Update safety** | Update checker compares version numbers only — no code download, no auto-execute |

---

## 🌍 Languages (20)

<div align="center">

`Arabic` · `English` · `French` · `Spanish` · `German` · `Turkish` · `Persian` · `Russian` · `Kurdish` · `Chinese`
`Urdu` · `Portuguese` · `Indonesian` · `Italian` · `Japanese` · `Hindi` · `Dutch` · `Korean` · `Ukrainian` · `Polish`

</div>

All 20 languages cover all 505 strings: menus, prompts, report text, error messages, and severity labels.  
Switch from the in-app language menu at any time — no restart needed.

---

## 📈 Accuracy Benchmark

```bash
bash tests/run_accuracy_eval.sh
```

```
Detector           Precision   Recall   F1      Accuracy
─────────────────────────────────────────────────────────
Webshell (YARA-lite)  98.1%    97.8%   97.9%    98.2%
Malicious Cron        100%     96.3%   98.1%    97.8%
/tmp Executables      100%     97.4%   98.7%    98.5%
─────────────────────────────────────────────────────────
Overall (weighted)    99.2%    97.2%   98.2%    98.2%
```

> Measured against a manually-labeled, deliberately adversarial corpus including obfuscated webshells, clean-but-suspicious files, and static droppers. No marketing numbers.

---

## ⚠️ Known Limitations

Honest transparency, not marketing:

- **Static analysis only.** No live runtime/behavioral sandboxing yet — on the roadmap.
- **No `.yar` files ship with the project.** The real-YARA loader exists and works; you supply your own rule files.
- **Tested primarily on Debian/Ubuntu and Kali.** Other distributions may need minor shell adjustments.
- **The `static_dropper` test case is a deliberate known gap** — a stripped binary with no visible strings is the expected limit of any static tool.
- **Live rule/update sources ship disabled** (`enabled=0`) — you point it at a source you control and trust.

---

## 🔐 Responsible Disclosure

Found a vulnerability in RAQIB itself? See [SECURITY.md](SECURITY.md) — do **not** open a public issue for security reports.

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most impactful contributions: new detection rules in `tools/malware/rules/`, new language strings, and labeled test samples in `tests/corpus/`.

## ⚠️ Disclaimer

**Authorized use only.** All scanning, testing, and monitoring tools are for systems you own or have explicit written authorization to assess. You are solely responsible for compliance with applicable laws.

## 📄 License

[GNU License](LICENSE) — see the file for details.

---

## 📩 Contact

| Channel | Link |
|---|---|
| GitHub | [@Ali5667](https://github.com/Ali5667) |
| X (Twitter) | [@ali_cys45](https://twitter.com/ali_cys45) |

---

<div align="center">
<sub>Built from scratch by Ali Alnuaimi · Every line of code is original · Zero borrowed security binaries</sub><br>
<sub>If RAQIB helps your team, consider starring the repo ⭐</sub>
</div>
