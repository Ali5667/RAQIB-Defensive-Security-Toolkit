<div align="center">

# RAQIB (رقيب)
### Defensive Security Toolkit

**A dependency-free, Bash/Python incident-response toolkit — 43 standalone tools, zero external security binaries, 20 languages.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1-blue.svg)](VERSION)
[![Bash 4+](https://img.shields.io/badge/Bash-4%2B-4EAA25?logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-informational)](#-requirements)
[![Languages: 20](https://img.shields.io/badge/languages-20-brightgreen)](modules/lang.sh)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Overview](#-overview) • [Why RAQIB](#-why-raqib) • [Quick Start](#-quick-start) • [Tools](#-tools-43-standalone) • [Languages](#-languages) • [Security](#-security) • [Contributing](#-contributing) • [العربية](README.ar.md)

</div>

---

## 📖 Overview

RAQIB is a **defensive** security toolkit for blue teams, sysadmins, and incident responders who need fast, reliable checks on **systems they own or are authorized to assess** — without pulling in Nmap, Wireshark, or any other well-known external binary.

Every one of its 43 tools is a standalone script built from scratch on core Linux utilities (`ss`, `find`, `awk`, `grep`, `openssl`, `/dev/tcp`...), so it runs on a bare-minimum server with nothing extra installed. Organized into 7 categories — network monitoring, log analysis, intrusion detection, malware analysis, digital forensics, system hardening, and vulnerability scanning — it's built as one integrated incident-response workflow rather than a pile of disconnected scripts.

> ⚠️ **Scope:** the scanning tools (ports, vulnerabilities, permissions) are for **your own systems and networks only**, or systems you have explicit authorization to test. See [Disclaimer](#-disclaimer).

---

## ✨ Why RAQIB

| | |
|---|---|
| 🚫 **Zero external tool dependency** | No Nmap, no Wireshark, no third-party scanners — every check is written from scratch against core system utilities, so it runs anywhere Bash does. |
| 🧬 **Composite malware detection** | The "YARA-lite" engine scores multiple weak signals together (string concatenation, `chr()` obfuscation, hex escapes, PHP-in-image polyglots) instead of one brittle signature, and layers on top of a real `yara` binary automatically if one's installed. |
| 🔄 **Live rule updates, safe by design** | Pull detection rules from a source *you* choose — disabled until you enable it, every line format/regex-validated before acceptance, automatic backup, your local rules always preserved. |
| 📊 **A real accuracy benchmark, not a marketing number** | `tests/run_accuracy_eval.sh` imports the actual production detection code and reports Precision/Recall/F1 against a manually-labeled, deliberately-adversarial corpus. |
| 🌍 **20 languages, fully translated** | Not just the menu — every message, report, and error string. Missing a language string in the future? An optional live auto-translate (LibreTranslate) fills the gap and caches it locally. |
| 🔗 **Integrated workflow** | Compute a hash → get offered a reputation check on the same file immediately. Full quarantine-and-eradicate. A comprehensive auto-cleaner checking multiple threat sources in one pass. |
| 📝 **Honest about limitations** | An explicit, unvarnished [Known Limitations](#-known-limitations) section instead of overselling — this is static analysis, and it says so. |

---

## ⚙️ Quick Start

```bash
git clone https://github.com/Ali5667/RAQIB-Defensive-Security-Toolkit.git
cd RAQIB-Defensive-Security-Toolkit
chmod +x raqib.sh
./raqib.sh
```

### Requirements
- Bash 4+
- Python3 (only used by the entropy calculator)
- Core Linux utilities: `find`, `awk`, `grep`, `ss`, `openssl`
- Optional: `curl` (reputation/rule-update tools), `yara` binary (real YARA rule layer), `paplay`/`aplay`/`ffplay` (startup sound)

---

## 🗂️ Project Structure

```
raqib/
├── raqib.sh
├── VERSION                # current version + repo URL, used by the update checker
├── README.md / README.ar.md
├── LICENSE · SECURITY.md · CONTRIBUTING.md
├── modules/          # Menu wiring for every tool category
│   ├── lang.sh             # all 20 languages' translation tables
│   ├── auto_translate.sh   # optional live translation via LibreTranslate
│   └── lang_cache/         # auto-translated strings cached here
├── assets/           # ASCII eagle art + eagle_cry.wav startup sound
├── samples/          # Sample logs + a binary to test tools immediately
├── tests/            # Manually-labeled test corpus + accuracy-measurement script
└── tools/
    ├── monitoring/   # 6 tools      ├── forensics/    # 5 tools
    ├── logs/         # 5 tools      ├── hardening/    # 6 tools
    ├── ids_ips/      # 6 tools      └── vuln_scan/    # 5 tools
    └── malware/      # 10 tools (+ rules/ for updatable, live YARA-lite rules)
```

---

## 📋 Tools (43 standalone)

<details>
<summary><b>🛰️ Network Monitoring (6)</b></summary>

1. Port Scanner — TCP port range scan via `/dev/tcp`
2. Active Connections — current network connections via `ss`
3. Bandwidth Monitor — real upload/download rate from `/sys/class/net`
4. ARP Watch — baseline + compare to detect ARP spoofing
5. DNS Lookup — forward and reverse, via Python sockets
6. Ping Sweep — scans a subnet to find live hosts
</details>

<details>
<summary><b>📋 Log Analysis (5)</b></summary>

1. Failed SSH Report — ranks the most frequent attacking IPs from auth.log
2. Keyword Search — context-aware search inside any log file
3. Top Repeated Lines — surfaces recurring error patterns
4. Timeline — extracts a specific time window from a log
5. Access Log Analyzer — top IPs, status codes, requested pages
</details>

<details>
<summary><b>🚨 Intrusion & Threat Detection (5)</b></summary>

1. Brute Force Detector — failed attempts per IP vs. an alert threshold
2. Listening Ports Auditor — maps every open port to its owning process
3. File Integrity Monitor — SHA256 baseline + change detection
4. Cron Auditor — flags recently-modified cron jobs (system + all users)
5. Connection Rate Watcher — two snapshots to catch a sudden connection spike
</details>

<details>
<summary><b>🦠 Suspicious File Analysis — Static Analysis (10)</b></summary>

1. Hash Calculator — MD5/SHA1/SHA256, auto-offers a reputation check
2. File Type Identifier — extension vs. real magic bytes
3. Suspicious Strings Extractor — IPs, URLs, long Base64 blobs, dangerous commands
4. Entropy Calculator — Shannon entropy to spot encrypted/packed files
5. Persistence Scanner — systemd, cron, rc.local, LD_PRELOAD
6. Full Quarantine & Eradication — hash-identical copy tracking + persistence-reference cleanup + safe shred
7. Comprehensive Auto Cleaner — webshells + cron + LD_PRELOAD + tmpexec in one pass
8. Hash Reputation Check — VirusTotal API v3 + MalwareBazaar (abuse.ch)
9. YARA-lite Rules Scan — updatable `name|weight|regex` engine, catches obfuscated webshell variants; layers a real `yara` binary automatically if installed
10. Live Rules Update — pulls new rules from sources you define, with format validation, backup, and local-rule preservation
</details>

<details>
<summary><b>🔍 Digital Forensics (5)</b></summary>

1. Login History Report — last / lastb / lastlog
2. Bash History Review — searches every user's history for suspicious commands
3. File Timeline — chronological ordering by mtime/ctime
4. Disk Usage Snapshot — compares folder sizes between two points in time
5. Sudo Log Review — every executed sudo command + failed attempts
</details>

<details>
<summary><b>🛡️ System Hardening (6)</b></summary>

1. Permission Auditor — world-writable files, SUID, SGID
2. SSH Auditor — sshd_config vs. best practices
3. Service Lister — enabled services + alerts for risky ones (telnet, ftp...)
4. Password Policy Checker — login.defs + PAM + no-password accounts
5. Firewall Status Checker — UFW/firewalld/iptables status and default policy
</details>

<details>
<summary><b>🎯 Vulnerability & Permission Scan — your own systems only (5)</b></summary>

1. Ports vs. Services — flags known-risky exposed ports
2. Outdated Packages Checker — apt/yum/pip outdated
3. Weak Permissions Checker — 777/666 files, wrong-permission SSH keys
4. SSL Certificate Checker — expiry and details for any domain
5. Default Credentials Checker — weak passwords / hardcoded API keys in source
</details>

---

## 🌍 Languages

Arabic · English · French · Spanish · German · Turkish · Persian · Russian · Kurdish · Chinese · Urdu · Portuguese · Indonesian · Italian · Japanese · Hindi · Dutch · Korean · Ukrainian · Polish

All 20 are translated end-to-end (505 strings each — menus, prompts, report text, and error messages). Switch anytime from the in-app language menu.

---

## 🎯 Accuracy Testing

`tests/corpus/` holds manually-labeled samples (benign/malicious) for three heuristic detectors (webshell, cron, `/tmp` executables), including deliberately obfuscated and "clean but suspicious-looking" samples to keep false positives in check.

```bash
bash tests/run_accuracy_eval.sh
```

Prints Precision/Recall/F1/Accuracy per detector plus a named list of every false positive/negative, measuring the tool's actual production logic — not a parallel copy of it.

> This is an internal regression benchmark, not a "100% accuracy" claim. No threat-detection tool, commercial or otherwise, hits 100% — especially against zero-days or static binaries with no visible strings/behavior under static analysis. Those need live behavioral monitoring, which is on the roadmap (see below).

To improve accuracy without touching code: add `name|weight|regex` lines to `tools/malware/rules/webshell_lite.rules`, add matching labeled samples to `tests/corpus/`, and re-run the script.

---

## ⚠️ Known Limitations

Full transparency, not marketing:

- **Static analysis only, for now.** No live runtime/behavioral monitoring (real-time network connections, in-process suspicious behavior) yet — this is the single biggest item on the roadmap.
- **Live rule sources are unverified against a real feed.** The mechanism (format validation, backup, merge) is built and tested against mock sources but ships disabled (`enabled=0`) until you point it at, and verify, a source you trust.
- **`raqib.sh` has not been end-to-end tested on a wide range of real machines** — most testing has used stub functions in a dev environment.
- **The `static_dropper` test case is a known, deliberately-left gap** — a static binary with no visible strings/behavior, an expected limit of any static-only tool.
- **Zero real `.yar` rules ship with the project** — the loader for real YARA rules exists and works, but you supply your own rule files.
- **Not yet tested on macOS or non-reference Linux distributions.**

---

## 🔐 Security

Found a vulnerability in RAQIB itself? Please see [SECURITY.md](SECURITY.md) for responsible-disclosure instructions — do not open a public issue for security reports.

## 🤝 Contributing

Bug reports, new detection rules, translations, and new tools are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and how to run the accuracy tests before submitting a PR.

## ⚠️ Disclaimer

The scanning-related tools (ports, vulnerabilities, permissions) are intended **exclusively for scanning your own systems and networks**, or systems you have explicit, documented authorization to assess. You are solely responsible for complying with applicable local laws.

## 📄 License

Released under the [MIT License](LICENSE) — see the file for details.

## 📩 Contact

- GitHub: [@Ali5667](https://github.com/Ali5667)
- X (Twitter): [@ali_cys45](https://twitter.com/ali_cys45)

---

<div align="center">
<sub>Built by Ali Alnuaimi. If RAQIB is useful to you, consider starring the repo ⭐</sub>
</div>
