#!/usr/bin/env python3
"""
RAQIB Secret Scanner + Offline Vulnerability Matcher
═════════════════════════════════════════════════════

1) GIT SECRET SCANNER
   يفحص مستودعات Git ومجلدات الكود بحثاً عن:
   - مفاتيح API مسرّبة (AWS, GCP, Azure, GitHub, Stripe...)
   - كلمات مرور مكتوبة بالكود (hardcoded passwords)
   - مفاتيح SSH/GPG خاصة
   - رموز JWT وتوكنات OAuth
   - ملفات .env ومعلومات اتصال قواعد البيانات

2) OFFLINE VULNERABILITY MATCHER
   يطابق إصدارات البرمجيات المثبتة مع قاعدة بيانات
   CISA KEV المحلية المحدثة (من محرك الاستخبارات).

Usage:
  python3 raqib_secret_scanner.py scan <directory>
  python3 raqib_secret_scanner.py scan-git <repo_path>
  python3 raqib_secret_scanner.py match-vulns
  python3 raqib_secret_scanner.py show-rules

Pure Python — stdlib only.
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys
from pathlib import Path

# ═══════════════════════════════════════════════════════════════════
# 1) SECRET DETECTION RULES
# ═══════════════════════════════════════════════════════════════════

SECRET_RULES = [
    # AWS
    {"id": "aws-access-key", "severity": "critical",
     "description": "AWS Access Key ID",
     "pattern": re.compile(r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])')},
    {"id": "aws-secret-key", "severity": "critical",
     "description": "AWS Secret Access Key",
     "pattern": re.compile(r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access)?[_\-\s]*key["\s:=]+["\']?([A-Za-z0-9/+=]{40})')},

    # GCP
    {"id": "gcp-api-key", "severity": "critical",
     "description": "Google Cloud API Key",
     "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}')},
    {"id": "gcp-service-account", "severity": "critical",
     "description": "GCP Service Account Key",
     "pattern": re.compile(r'"type"\s*:\s*"service_account"')},

    # Azure
    {"id": "azure-storage-key", "severity": "critical",
     "description": "Azure Storage Account Key",
     "pattern": re.compile(r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}')},

    # GitHub
    {"id": "github-token", "severity": "critical",
     "description": "GitHub Personal Access Token",
     "pattern": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,255}')},
    {"id": "github-token-classic", "severity": "critical",
     "description": "GitHub Token (classic)",
     "pattern": re.compile(r'github_pat_[A-Za-z0-9_]{22,255}')},

    # Stripe
    {"id": "stripe-secret", "severity": "critical",
     "description": "Stripe Secret Key",
     "pattern": re.compile(r'sk_live_[0-9a-zA-Z]{24,}')},
    {"id": "stripe-publishable", "severity": "medium",
     "description": "Stripe Publishable Key",
     "pattern": re.compile(r'pk_live_[0-9a-zA-Z]{24,}')},

    # Slack
    {"id": "slack-webhook", "severity": "high",
     "description": "Slack Webhook URL",
     "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+')},
    {"id": "slack-token", "severity": "critical",
     "description": "Slack API Token",
     "pattern": re.compile(r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}')},

    # SSH/Crypto Keys
    {"id": "private-key", "severity": "critical",
     "description": "Private Key (RSA/DSA/EC/OpenSSH)",
     "pattern": re.compile(r'-----BEGIN\s+(RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----')},
    {"id": "pgp-private", "severity": "critical",
     "description": "PGP Private Key",
     "pattern": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----')},

    # JWT
    {"id": "jwt-token", "severity": "high",
     "description": "JWT Token",
     "pattern": re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')},

    # Database connections
    {"id": "db-connection-string", "severity": "critical",
     "description": "Database Connection String",
     "pattern": re.compile(r'(?i)(mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s"\'<>]+:[^\s"\'<>]+@[^\s"\'<>]+')},

    # Generic passwords
    {"id": "hardcoded-password", "severity": "high",
     "description": "Hardcoded Password",
     "pattern": re.compile(r'(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|api-key)["\s:=]+["\']([^\s"\']{8,})["\']')},

    # .env patterns
    {"id": "env-secret", "severity": "high",
     "description": "Environment Variable Secret",
     "pattern": re.compile(r'(?i)^(?:DB_PASSWORD|SECRET_KEY|API_SECRET|JWT_SECRET|ENCRYPTION_KEY|PRIVATE_KEY)\s*=\s*\S+', re.MULTILINE)},

    # Telegram Bot Token
    {"id": "telegram-bot-token", "severity": "high",
     "description": "Telegram Bot Token",
     "pattern": re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}')},

    # Discord Bot Token
    {"id": "discord-bot-token", "severity": "high",
     "description": "Discord Bot Token",
     "pattern": re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}')},

    # Sendgrid
    {"id": "sendgrid-api-key", "severity": "critical",
     "description": "SendGrid API Key",
     "pattern": re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}')},

    # Generic API Key pattern
    {"id": "generic-api-key", "severity": "medium",
     "description": "Generic API Key Pattern",
     "pattern": re.compile(r'(?i)(?:api[_\-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9_\-]{20,})["\']?')},
]

# Files to skip
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2',
    '.ttf', '.eot', '.mp3', '.mp4', '.avi', '.mov', '.zip', '.tar',
    '.gz', '.bz2', '.7z', '.rar', '.pdf', '.doc', '.docx', '.xls',
    '.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.dat', '.db',
    '.sqlite', '.sqlite3', '.class', '.jar', '.war',
}

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env',
    '.tox', '.eggs', 'dist', 'build', '.mypy_cache', '.pytest_cache',
    'vendor', 'bower_components', '.next', '.nuxt',
}

# Files that commonly contain secrets
HIGH_PRIORITY_FILES = {
    '.env', '.env.local', '.env.production', '.env.development',
    'credentials', 'secrets.yml', 'secrets.yaml', 'secrets.json',
    'config.json', 'config.yml', 'config.yaml',
    '.npmrc', '.pypirc', '.docker/config.json',
    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
    '.htpasswd', '.pgpass', '.my.cnf', '.netrc',
}


def scan_file(filepath: str) -> list[dict]:
    """Scan a single file for secrets."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(1024 * 1024)  # Max 1MB per file
    except (OSError, PermissionError):
        return findings

    lines = content.splitlines()
    basename = os.path.basename(filepath)

    # Check if it's a high-priority file
    is_priority = basename in HIGH_PRIORITY_FILES or basename.startswith('.env')

    for rule in SECRET_RULES:
        for line_num, line in enumerate(lines, 1):
            matches = rule['pattern'].finditer(line)
            for match in matches:
                # Avoid false positives in comments/examples
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
                    if 'example' in stripped.lower() or 'sample' in stripped.lower():
                        continue

                secret_val = match.group(0)
                # Mask the secret
                if len(secret_val) > 12:
                    masked = secret_val[:6] + '***' + secret_val[-4:]
                else:
                    masked = secret_val[:3] + '***'

                findings.append({
                    'file': filepath,
                    'line': line_num,
                    'rule_id': rule['id'],
                    'severity': 'critical' if is_priority else rule['severity'],
                    'description': rule['description'],
                    'secret_masked': masked,
                    'context': line.strip()[:120],
                })
                break  # One match per rule per line is enough

    return findings


def scan_directory(directory: str, include_git_history: bool = False) -> list[dict]:
    """Scan a directory recursively for secrets."""
    all_findings = []
    files_scanned = 0

    for root, dirs, files in os.walk(directory):
        # Skip directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)

            # Skip large files
            try:
                if os.path.getsize(fpath) > 2 * 1024 * 1024:  # 2MB
                    continue
            except OSError:
                continue

            findings = scan_file(fpath)
            all_findings.extend(findings)
            files_scanned += 1

    # Optionally scan git history
    if include_git_history and os.path.isdir(os.path.join(directory, '.git')):
        git_findings = scan_git_history(directory)
        all_findings.extend(git_findings)

    return all_findings


def scan_git_history(repo_path: str, max_commits: int = 50) -> list[dict]:
    """Scan git commit history for leaked secrets."""
    findings = []
    try:
        result = subprocess.run(
            ['git', 'log', f'-{max_commits}', '--diff-filter=A', '--name-only', '--pretty=format:%H'],
            capture_output=True, text=True, cwd=repo_path, timeout=30
        )
        if result.returncode != 0:
            return findings

        current_commit = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if len(line) == 40 and all(c in '0123456789abcdef' for c in line):
                current_commit = line
                continue
            if current_commit:
                # Check the file content at that commit
                try:
                    content_result = subprocess.run(
                        ['git', 'show', f'{current_commit}:{line}'],
                        capture_output=True, text=True, cwd=repo_path, timeout=10
                    )
                    if content_result.returncode == 0:
                        for rule in SECRET_RULES:
                            if rule['pattern'].search(content_result.stdout[:500000]):
                                findings.append({
                                    'file': f'{line} (commit {current_commit[:8]})',
                                    'line': 0,
                                    'rule_id': rule['id'],
                                    'severity': rule['severity'],
                                    'description': f"[GIT HISTORY] {rule['description']}",
                                    'secret_masked': '***in-git-history***',
                                    'context': f'Found in commit {current_commit[:12]}',
                                })
                                break
                except subprocess.TimeoutExpired:
                    continue

    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return findings


# ═══════════════════════════════════════════════════════════════════
# 2) OFFLINE VULNERABILITY MATCHER
# ═══════════════════════════════════════════════════════════════════

INTEL_DB_PATH = Path(__file__).resolve().parent.parent / "malware" / "raqib_intelligence.json"


def get_installed_packages() -> list[dict]:
    """Get list of installed packages with versions."""
    packages = []

    # Try dpkg (Debian/Ubuntu)
    try:
        result = subprocess.run(
            ['dpkg-query', '-W', '-f', '${Package} ${Version}\n'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split(' ', 1)
                if len(parts) == 2:
                    packages.append({'name': parts[0], 'version': parts[1], 'manager': 'dpkg'})
            return packages
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Try rpm (RHEL/CentOS/Fedora)
    try:
        result = subprocess.run(
            ['rpm', '-qa', '--queryformat', '%{NAME} %{VERSION}-%{RELEASE}\n'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split(' ', 1)
                if len(parts) == 2:
                    packages.append({'name': parts[0], 'version': parts[1], 'manager': 'rpm'})
            return packages
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Try pacman (Arch)
    try:
        result = subprocess.run(
            ['pacman', '-Q'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.strip().split(' ', 1)
                if len(parts) == 2:
                    packages.append({'name': parts[0], 'version': parts[1], 'manager': 'pacman'})
            return packages
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    return packages


def match_vulnerabilities() -> list[dict]:
    """Match installed packages against CISA KEV database."""
    matches = []

    # Load CISA KEV from intelligence database
    if not INTEL_DB_PATH.exists():
        print("  [!] Intelligence database not found. Run:")
        print("      python3 tools/malware/10_raqib_intelligence.py update")
        return matches

    try:
        intel_db = json.loads(INTEL_DB_PATH.read_text(encoding='utf-8'))
    except Exception:
        print("  [!] Cannot read intelligence database")
        return matches

    vulns = intel_db.get('vulnerabilities', {})
    if not vulns:
        print("  [!] No vulnerability data in database. Run update first.")
        return matches

    packages = get_installed_packages()
    if not packages:
        print("  [!] No packages found on this system")
        return matches

    print(f"  [+] Checking {len(packages)} packages against {len(vulns)} known vulnerabilities...")

    # Build a lookup of package names
    pkg_names = {p['name'].lower(): p for p in packages}

    for cve_id, vuln_info in vulns.items():
        vendor = vuln_info.get('vendor', '').lower() if isinstance(vuln_info, dict) else ''
        product = vuln_info.get('product', '').lower() if isinstance(vuln_info, dict) else ''
        vuln_name = vuln_info.get('name', '') if isinstance(vuln_info, dict) else str(vuln_info)

        # Try to match against installed packages
        for pkg_name, pkg_info in pkg_names.items():
            if product and (product in pkg_name or pkg_name in product):
                matches.append({
                    'cve': cve_id,
                    'package': pkg_info['name'],
                    'installed_version': pkg_info['version'],
                    'vulnerability': vuln_name,
                    'vendor': vendor,
                    'product': product,
                    'severity': 'critical',
                })

    return matches


# ═══════════════════════════════════════════════════════════════════
# CLI & OUTPUT
# ═══════════════════════════════════════════════════════════════════

SEV_COLORS = {
    'critical': '\033[1;31m', 'high': '\033[38;5;208m',
    'medium': '\033[1;33m', 'low': '\033[0;32m',
}
NC = '\033[0m'


def print_findings(findings: list[dict]):
    if not findings:
        print(f"  {SEV_COLORS['low']}✅ No secrets found{NC}")
        return

    by_severity = {}
    for f in findings:
        by_severity.setdefault(f['severity'], []).append(f)

    for sev in ('critical', 'high', 'medium', 'low'):
        items = by_severity.get(sev, [])
        if not items:
            continue
        color = SEV_COLORS.get(sev, NC)
        print(f"\n  {color}━━━ {sev.upper()} ({len(items)}) ━━━{NC}")
        for f in items[:20]:
            print(f"    {color}[{f['rule_id']}]{NC} {f['file']}:{f['line']}")
            print(f"      {f['description']}: {f['secret_masked']}")

    # Summary
    print(f"\n  {'─' * 50}")
    print(f"  Total secrets found: {len(findings)}")
    for sev in ('critical', 'high', 'medium', 'low'):
        count = len(by_severity.get(sev, []))
        if count:
            color = SEV_COLORS.get(sev, NC)
            print(f"    {color}{sev}: {count}{NC}")

    # Unique files affected
    files = set(f['file'] for f in findings)
    print(f"  Files affected: {len(files)}")


def main():
    parser = argparse.ArgumentParser(description="RAQIB Secret Scanner + Vulnerability Matcher")
    sub = parser.add_subparsers(dest='command')

    p_scan = sub.add_parser('scan', help='Scan directory for secrets')
    p_scan.add_argument('directory')
    p_scan.add_argument('--json', action='store_true')

    p_git = sub.add_parser('scan-git', help='Scan including git history')
    p_git.add_argument('repo_path')
    p_git.add_argument('--commits', type=int, default=50)
    p_git.add_argument('--json', action='store_true')

    p_vuln = sub.add_parser('match-vulns', help='Match installed packages against CISA KEV')
    p_vuln.add_argument('--json', action='store_true')

    p_rules = sub.add_parser('show-rules', help='Show all detection rules')

    args = parser.parse_args()

    if args.command == 'scan':
        print(f"  [+] Scanning: {args.directory}")
        findings = scan_directory(args.directory)
        if args.json:
            print(json.dumps(findings, indent=2, ensure_ascii=False))
        else:
            print_findings(findings)

    elif args.command == 'scan-git':
        print(f"  [+] Scanning repo: {args.repo_path} (including git history)")
        findings = scan_directory(args.repo_path, include_git_history=True)
        if args.json:
            print(json.dumps(findings, indent=2, ensure_ascii=False))
        else:
            print_findings(findings)

    elif args.command == 'match-vulns':
        print(f"  [+] Matching installed packages against CISA KEV...")
        matches = match_vulnerabilities()
        if args.json:
            print(json.dumps(matches, indent=2, ensure_ascii=False))
        elif matches:
            print(f"\n  ⚠️  Found {len(matches)} potential vulnerability matches:")
            for m in matches:
                print(f"    {SEV_COLORS['critical']}[{m['cve']}]{NC} {m['package']} ({m['installed_version']})")
                print(f"      {m['vulnerability']}")
        else:
            print(f"  ✅ No known vulnerabilities matched against installed packages")

    elif args.command == 'show-rules':
        print(f"  Secret Detection Rules ({len(SECRET_RULES)}):")
        print(f"  {'─' * 60}")
        for rule in SECRET_RULES:
            color = SEV_COLORS.get(rule['severity'], NC)
            print(f"    {color}[{rule['severity']:8s}]{NC} {rule['id']:25s} {rule['description']}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
