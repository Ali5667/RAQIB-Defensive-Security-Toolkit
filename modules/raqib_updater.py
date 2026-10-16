#!/usr/bin/env python3
"""
RAQIB (رقيب) — Advanced Toolkit Updater & Integrity Manager
Author: Ali Alnuaimi (@Ali5667)
Repository: https://github.com/Ali5667/RAQIB-Defensive-Security-Toolkit

Zero-dependency update management engine:
- Checks remote version & commit history via GitHub API and raw mirrors.
- Compares semantic versions (e.g. 2.1 < 2.2) and git commit distances.
- Performs atomic pre-update snapshots with automatic rollback capability.
- Supports both Git repository updates (fast-forward) and standalone archive sync.
- Post-update integrity verification (syntax validation for Bash and Python scripts).
- Rich interactive cyber terminal UI with live progress indicators.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
DEFAULT_REPO = "Ali5667/RAQIB-Defensive-Security-Toolkit"
GITHUB_API_BASE = f"https://api.github.com/repos/{DEFAULT_REPO}"
RAW_GITHUB_BASE = f"https://raw.githubusercontent.com/{DEFAULT_REPO}/main"
BACKUP_DIR = ROOT_DIR / ".raqib_backups"

# =============================================================================
# Terminal Aesthetics & ANSI Colors
# =============================================================================
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[38;5;203m"
    GREEN = "\033[38;5;48m"
    YELLOW = "\033[38;5;220m"
    BLUE = "\033[38;5;75m"
    MAGENTA = "\033[38;5;176m"
    CYAN = "\033[38;5;45m"
    WHITE = "\033[38;5;255m"
    GREY = "\033[38;5;244m"
    BG_DARK = "\033[48;5;235m"

    @classmethod
    def strip(cls, text: str) -> str:
        return re.sub(r"\033\[[0-9;]*m", "", text)


def banner():
    art = f"""
{C.CYAN}  ____      _    ___ ___ ____ {C.GREEN}   _   _ ____  ____    _  _____ _____ ____  
{C.CYAN} |  _ \\    / \\  / _ \\_ _| __ ){C.GREEN}  | | | |  _ \\|  _ \\  / \\|_   _| ____|  _ \\ 
{C.CYAN} | |_) |  / _ \\| | | | ||  _ \\{C.GREEN}  | | | | |_) | | | |/ _ \\ | | |  _| | |_) |
{C.CYAN} |  _ <  / ___ \\ |_| | || |_) ){C.GREEN} | |_| |  __/| |_| / ___ \\| | | |___|  _ < 
{C.CYAN} |_| \\_\\/_/   \\_\\__\\_\\___|____/{C.GREEN}   \\___/|_|   |____/_/   \\_\\_| |_____|_| \\_\\
{C.RESET}
    {C.BOLD}{C.WHITE}RAQIB Toolkit Integrity & Automated Update System{C.RESET}
    {C.GREY}Safe atomic updates • Pre-upgrade snapshots • Syntax validation{C.RESET}
    {C.DIM}------------------------------------------------------------------------{C.RESET}
"""
    print(art)


# =============================================================================
# Version Parsing & Semantic Comparison
# =============================================================================
def parse_version(v_str: str) -> Tuple[int, ...]:
    """Extract numeric components from a version string (e.g., '2.2' -> (2, 2))."""
    clean = re.sub(r"[^\d.]", "", v_str.strip())
    parts = []
    for p in clean.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return tuple(parts) if parts else (0,)


def is_version_newer(remote_v: str, local_v: str) -> bool:
    """Returns True if remote_v is strictly greater than local_v."""
    r = parse_version(remote_v)
    l = parse_version(local_v)
    max_len = max(len(r), len(l))
    r_padded = r + (0,) * (max_len - len(r))
    l_padded = l + (0,) * (max_len - len(l))
    return r_padded > l_padded


def get_local_version() -> str:
    """Read local version from VERSION file, fallback to raqib.sh."""
    v_file = ROOT_DIR / "VERSION"
    if v_file.is_file():
        try:
            first_line = v_file.read_text(encoding="utf-8").splitlines()[0].strip()
            if first_line:
                return first_line
        except Exception:
            pass
    
    # Fallback to parsing raqib.sh
    sh_file = ROOT_DIR / "raqib.sh"
    if sh_file.is_file():
        try:
            content = sh_file.read_text(encoding="utf-8")
            m = re.search(r'VERSION=["\']([0-9.]+)["\']', content)
            if m:
                return m.group(1)
        except Exception:
            pass
    return "0.0"


# =============================================================================
# Git Environment Diagnostics
# =============================================================================
def get_git_status() -> Dict[str, Any]:
    """Inspect local git repository metadata."""
    res = {
        "is_git": False,
        "branch": None,
        "commit": None,
        "dirty": False,
        "modified_files": [],
        "remote_url": None,
    }
    
    git_dir = ROOT_DIR / ".git"
    if not git_dir.exists():
        return res

    try:
        # Check inside work tree
        out = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if out.returncode != 0 or out.stdout.strip() != "true":
            return res
        
        res["is_git"] = True

        # Current branch
        b_out = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if b_out.returncode == 0:
            res["branch"] = b_out.stdout.strip()

        # Commit hash
        c_out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if c_out.returncode == 0:
            res["commit"] = c_out.stdout.strip()

        # Remote URL
        r_out = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if r_out.returncode == 0:
            res["remote_url"] = r_out.stdout.strip()

        # Working tree status
        s_out = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if s_out.returncode == 0:
            lines = [line.strip() for line in s_out.stdout.splitlines() if line.strip()]
            res["modified_files"] = lines
            res["dirty"] = len(lines) > 0

    except Exception:
        pass

    return res


# =============================================================================
# Remote Discovery & Feed Queries
# =============================================================================
def get_configured_source_url() -> Optional[str]:
    """Parse update_source.txt to find user-configured URL."""
    src_file = ROOT_DIR / "update_source.txt"
    if not src_file.is_file():
        return None
    try:
        for line in src_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 2 and parts[1].strip() == "1":
                return parts[0].strip()
    except Exception:
        pass
    return None


def fetch_url(url: str, timeout: int = 10) -> Tuple[bool, str]:
    """HTTP GET with proper User-Agent and error handling."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "RAQIB-Toolkit-Updater/2.2 (+https://github.com/Ali5667)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return True, data
    except Exception as e:
        return False, str(e)


def fetch_remote_version() -> Dict[str, Any]:
    """Check remote repository for updates via multiple channels."""
    result = {
        "remote_version": None,
        "remote_commit": None,
        "release_url": None,
        "changelog": None,
        "source": "none",
        "error": None,
    }

    # 1. First check user-configured URL in update_source.txt
    custom_url = get_configured_source_url()
    if custom_url:
        ok, data = fetch_url(custom_url)
        if ok and data:
            lines = data.strip().splitlines()
            if lines and re.match(r"^[\d.]+$", lines[0].strip()):
                result["remote_version"] = lines[0].strip()
                if len(lines) > 1 and lines[1].startswith("http"):
                    result["release_url"] = lines[1].strip()
                result["source"] = f"configured ({custom_url})"
                return result

    # 2. Try GitHub Releases API
    api_release_url = f"{GITHUB_API_BASE}/releases/latest"
    ok, data = fetch_url(api_release_url)
    if ok:
        try:
            rel = json.loads(data)
            tag = rel.get("tag_name", "").lstrip("v")
            if tag:
                result["remote_version"] = tag
                result["release_url"] = rel.get("html_url")
                result["changelog"] = rel.get("body", "")[:600]
                result["source"] = "GitHub Releases API"
                return result
        except Exception:
            pass

    # 3. Fallback to Raw GitHub VERSION file
    raw_version_url = f"{RAW_GITHUB_BASE}/VERSION"
    ok, data = fetch_url(raw_version_url)
    if ok and data:
        lines = data.strip().splitlines()
        if lines and re.match(r"^[\d.]+$", lines[0].strip()):
            result["remote_version"] = lines[0].strip()
            result["release_url"] = f"https://github.com/{DEFAULT_REPO}"
            result["source"] = "GitHub Raw Mirror"
            return result

    result["error"] = "Failed to reach remote release endpoints (offline or network blocked)."
    return result


def fetch_remote_commit(branch: str = "main") -> Optional[str]:
    """Query GitHub API for latest commit hash on branch."""
    url = f"{GITHUB_API_BASE}/commits/{branch}"
    ok, data = fetch_url(url, timeout=7)
    if ok:
        try:
            info = json.loads(data)
            sha = info.get("sha", "")
            return sha[:7] if sha else None
        except Exception:
            pass
    return None


# =============================================================================
# Backup & Rollback Engine
# =============================================================================
def create_backup() -> Optional[Path]:
    """Create a compressed snapshot of current project files before updating."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    tar_path = BACKUP_DIR / f"raqib_snapshot_{ts}.tar.gz"

    excluded_dirs = {".git", ".raqib_backups", "reports", "__pycache__", "tmp", "temp"}
    excluded_files = {".DS_Store"}

    try:
        with tarfile.open(tar_path, "w:gz") as tar:
            for item in ROOT_DIR.iterdir():
                if item.name in excluded_dirs or item.name in excluded_files:
                    continue
                tar.add(str(item), arcname=item.name)
        return tar_path
    except Exception as e:
        print(f"{C.RED}[!] Backup creation failed: {e}{C.RESET}")
        return None


def get_latest_backup() -> Optional[Path]:
    """Find the most recent snapshot in .raqib_backups."""
    if not BACKUP_DIR.is_dir():
        return None
    backups = sorted(BACKUP_DIR.glob("raqib_snapshot_*.tar.gz"), reverse=True)
    return backups[0] if backups else None


def restore_backup(backup_file: Optional[Path] = None) -> bool:
    """Restore project files from backup."""
    target = backup_file or get_latest_backup()
    if not target or not target.is_file():
        print(f"{C.RED}[!] No valid backup snapshot found in {BACKUP_DIR}{C.RESET}")
        return False

    print(f"{C.YELLOW}[*] Restoring snapshot: {target.name}...{C.RESET}")
    try:
        with tarfile.open(target, "r:gz") as tar:
            tar.extractall(path=str(ROOT_DIR))
        print(f"{C.GREEN}[✔] Successfully restored snapshot: {target.name}{C.RESET}")
        return True
    except Exception as e:
        print(f"{C.RED}[✘] Rollback failed: {e}{C.RESET}")
        return False


# =============================================================================
# Update Execution Engine
# =============================================================================
def verify_scripts_integrity() -> bool:
    """Perform syntax checks on Bash and Python scripts."""
    print(f"{C.CYAN}[*] Verifying integrity of updated files...{C.RESET}")
    
    # Check bash scripts if bash is available
    if shutil.which("bash"):
        core_scripts = ["raqib.sh"] + [str(p.relative_to(ROOT_DIR)) for p in (ROOT_DIR / "modules").glob("*.sh")]
        for s in core_scripts:
            full_path = ROOT_DIR / s
            if not full_path.is_file():
                continue
            r = subprocess.run(["bash", "-n", str(full_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if r.returncode != 0:
                print(f"{C.RED}[✘] Syntax error detected in {s}: {r.stderr.decode().strip()}{C.RESET}")
                return False

    # Check python syntax
    for py_file in (ROOT_DIR / "modules").glob("*.py"):
        r = subprocess.run([sys.executable, "-m", "py_compile", str(py_file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0:
            print(f"{C.RED}[✘] Syntax error detected in {py_file.name}{C.RESET}")
            return False

    print(f"{C.GREEN}[✔] Code integrity verified: all syntax checks passed.{C.RESET}")
    return True


def apply_git_update(git_info: Dict[str, Any], force: bool = False) -> bool:
    """Pull changes via Git with stash safety."""
    branch = git_info.get("branch") or "main"
    print(f"{C.CYAN}[*] Fetching latest commits from origin/{branch}...{C.RESET}")

    # Check dirty working tree
    if git_info.get("dirty") and not force:
        print(f"{C.YELLOW}[!] Local uncommitted changes detected:{C.RESET}")
        for mf in git_info["modified_files"][:8]:
            print(f"    {C.GREY}{mf}{C.RESET}")
        print(f"{C.YELLOW}[*] Stashing working changes temporarily...{C.RESET}")
        subprocess.run(["git", "stash", "push", "-m", "raqib_pre_update_stash"], cwd=str(ROOT_DIR))

    # Pull
    pull_cmd = ["git", "pull", "--ff-only", "origin", branch]
    p_res = subprocess.run(pull_cmd, cwd=str(ROOT_DIR), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    if p_res.returncode != 0:
        # Try normal pull
        p_res = subprocess.run(["git", "pull", "origin", branch], cwd=str(ROOT_DIR), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if p_res.returncode != 0:
            print(f"{C.RED}[✘] Git pull failed: {p_res.stderr.strip()}{C.RESET}")
            return False

    # Restore executable permissions on scripts
    for sh in ROOT_DIR.glob("**/*.sh"):
        try:
            sh.chmod(sh.stat().st_mode | 0o755)
        except Exception:
            pass

    return True


def apply_tarball_update() -> bool:
    """Download tarball from GitHub and unpack over root directory."""
    archive_url = f"https://github.com/{DEFAULT_REPO}/archive/refs/heads/main.tar.gz"
    print(f"{C.CYAN}[*] Downloading latest release archive from GitHub...{C.RESET}")

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        req = urllib.request.Request(archive_url, headers={"User-Agent": "RAQIB-Updater"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(tmp_path, "wb") as f_out:
            shutil.copyfileobj(resp, f_out)

        print(f"{C.CYAN}[*] Extracting update files...{C.RESET}")
        with tarfile.open(tmp_path, "r:gz") as tar:
            # GitHub tarballs have a root directory like `RAQIB-Defensive-Security-Toolkit-main/`
            top_dir = tar.getnames()[0].split("/")[0]
            for member in tar.getmembers():
                if not member.name.startswith(top_dir + "/"):
                    continue
                rel_path = member.name[len(top_dir) + 1 :]
                if not rel_path:
                    continue
                # Do not overwrite local user configurations
                if rel_path in {".raqib_lang", ".raqib_telegram.conf", ".raqib_events.jsonl"}:
                    continue
                dest = ROOT_DIR / rel_path
                if member.isdir():
                    dest.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    f_in = tar.extractfile(member)
                    if f_in:
                        with open(dest, "wb") as f_dst:
                            shutil.copyfileobj(f_in, f_dst)
                        # Retain permissions
                        if rel_path.endswith(".sh") or rel_path.endswith(".py"):
                            dest.chmod(0o755)

        return True
    except Exception as e:
        print(f"{C.RED}[✘] Tarball update failed: {e}{C.RESET}")
        return False
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


# =============================================================================
# Main Orchestration Loop
# =============================================================================
def run_update_flow(args: argparse.Namespace) -> int:
    banner()

    # 1. Rollback mode
    if args.rollback:
        success = restore_backup()
        return 0 if success else 1

    local_v = get_local_version()
    git_info = get_git_status()

    print(f"{C.BOLD}{C.WHITE}[+] Local System Status:{C.RESET}")
    print(f"    • Installed Version : {C.CYAN}v{local_v}{C.RESET}")
    if git_info["is_git"]:
        print(f"    • Git Repository    : {C.GREEN}Yes{C.RESET} (branch: {C.YELLOW}{git_info['branch']}{C.RESET}, commit: {C.DIM}{git_info['commit']}{C.RESET})")
        if git_info["dirty"]:
            print(f"    • Working Tree      : {C.YELLOW}Dirty ({len(git_info['modified_files'])} modified files){C.RESET}")
        else:
            print(f"    • Working Tree      : {C.GREEN}Clean{C.RESET}")
    else:
        print(f"    • Git Repository    : {C.GREY}Standalone installation (No .git){C.RESET}")

    print(f"\n{C.CYAN}[*] Checking for updates from remote channels...{C.RESET}")
    remote_data = fetch_remote_version()

    if remote_data.get("error"):
        print(f"{C.RED}[✘] {remote_data['error']}{C.RESET}")
        return 1

    remote_v = remote_data["remote_version"]
    source = remote_data["source"]
    print(f"{C.BOLD}{C.WHITE}[+] Remote Feed Status:{C.RESET}")
    print(f"    • Latest Available  : {C.GREEN}v{remote_v}{C.RESET} (via {source})")
    if remote_data.get("release_url"):
        print(f"    • Release Link      : {C.BLUE}{remote_data['release_url']}{C.RESET}")

    # Check commit hash difference if version numbers match
    has_newer_version = is_version_newer(remote_v, local_v)
    remote_commit = None
    has_newer_commit = False

    if git_info["is_git"] and not has_newer_version:
        remote_commit = fetch_remote_commit(git_info["branch"] or "main")
        if remote_commit and git_info["commit"] and remote_commit != git_info["commit"]:
            has_newer_commit = True
            print(f"    • Latest Commit     : {C.YELLOW}{remote_commit}{C.RESET} (local: {git_info['commit']})")

    needs_update = has_newer_version or has_newer_commit or args.force

    print("\n" + C.DIM + "────────────────────────────────────────────────────────────────────────" + C.RESET)

    if not needs_update:
        print(f"{C.GREEN}{C.BOLD}[✔] RAQIB is completely up to date! (v{local_v}){C.RESET}")
        print(f"{C.GREY}No updates are required at this time.{C.RESET}\n")
        return 0

    if has_newer_version:
        print(f"{C.YELLOW}{C.BOLD}[★] New Version Available: v{local_v} → v{remote_v}{C.RESET}")
    elif has_newer_commit:
        print(f"{C.YELLOW}{C.BOLD}[★] New Commits Available on branch '{git_info['branch']}': {git_info['commit']} → {remote_commit}{C.RESET}")
    elif args.force:
        print(f"{C.YELLOW}{C.BOLD}[!] Force update flag triggered.{C.RESET}")

    if remote_data.get("changelog"):
        print(f"\n{C.WHITE}{C.BOLD}Release Highlights:{C.RESET}")
        for cl_line in remote_data["changelog"].splitlines()[:6]:
            print(f"  {C.CYAN}•{C.RESET} {cl_line}")

    # If --check was requested, stop here
    if args.check and not args.apply:
        print(f"\n{C.GREY}Run with {C.CYAN}--apply{C.GREY} or {C.CYAN}-y{C.GREY} to install this update.{C.RESET}\n")
        return 2

    # Prompt user unless non-interactive
    if not args.yes:
        try:
            choice = input(f"\n{C.YELLOW}Do you want to apply this update now? [y/N]: {C.RESET}").strip().lower()
            if choice not in ("y", "yes"):
                print(f"{C.GREY}[*] Update cancelled by user.{C.RESET}\n")
                return 0
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.GREY}[*] Aborted.{C.RESET}\n")
            return 0

    # 1. Create Pre-Upgrade Snapshot
    print(f"\n{C.CYAN}[*] Step 1/3: Creating pre-update safety backup...{C.RESET}")
    backup_file = create_backup()
    if backup_file:
        print(f"{C.GREEN}[✔] Snapshot saved to: {backup_file.name}{C.RESET}")
    else:
        print(f"{C.YELLOW}[!] Continuing without backup...{C.RESET}")

    # 2. Apply Update
    print(f"\n{C.CYAN}[*] Step 2/3: Applying code updates...{C.RESET}")
    update_ok = False
    if git_info["is_git"]:
        update_ok = apply_git_update(git_info, force=args.force)
    else:
        update_ok = apply_tarball_update()

    if not update_ok:
        print(f"{C.RED}[✘] Update installation encountered errors.{C.RESET}")
        if backup_file:
            print(f"{C.YELLOW}[*] You can revert immediately using: python3 modules/raqib_updater.py --rollback{C.RESET}")
        return 1

    # 3. Post-Upgrade Verification
    print(f"\n{C.CYAN}[*] Step 3/3: Verifying system integrity...{C.RESET}")
    if not verify_scripts_integrity():
        print(f"{C.RED}[✘] Integrity verification failed! Reverting changes...{C.RESET}")
        if backup_file:
            restore_backup(backup_file)
        return 1

    new_v = get_local_version()
    print("\n" + C.GREEN + C.BOLD + "========================================================================" + C.RESET)
    print(f"{C.GREEN}{C.BOLD} [✔] RAQIB Toolkit Successfully Updated to v{new_v}!{C.RESET}")
    print(C.GREEN + C.BOLD + "========================================================================" + C.RESET)
    print(f"{C.WHITE}All security tools, engines, modules, and rules are now current.{C.RESET}")
    print(f"{C.GREY}Restart ./raqib.sh to launch the upgraded session.{C.RESET}\n")
    return 0


# =============================================================================
# CLI Entrypoint
# =============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="RAQIB Toolkit Advanced Updater & Integrity Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--check", "-c", action="store_true", help="Check for updates without downloading or applying them")
    parser.add_argument("--apply", "-u", action="store_true", help="Check and apply updates automatically")
    parser.add_argument("--yes", "-y", action="store_true", help="Automatically accept update prompts without confirmation")
    parser.add_argument("--force", "-f", action="store_true", help="Force update even if version appears current or tree is dirty")
    parser.add_argument("--rollback", "-r", action="store_true", help="Restore the most recent pre-update snapshot")
    parser.add_argument("--json", action="store_true", help="Output status as structured JSON (for scripts/SIEM)")

    args = parser.parse_args()

    if args.json:
        local_v = get_local_version()
        git_info = get_git_status()
        remote_data = fetch_remote_version()
        remote_v = remote_data.get("remote_version") or "0.0"
        payload = {
            "local_version": local_v,
            "remote_version": remote_v,
            "has_update": is_version_newer(remote_v, local_v),
            "git": git_info,
            "source": remote_data.get("source"),
            "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        print(json.dumps(payload, indent=2))
        return

    sys.exit(run_update_flow(args))


if __name__ == "__main__":
    main()
