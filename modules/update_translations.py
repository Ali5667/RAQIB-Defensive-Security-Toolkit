#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAQIB Translation & Language Synchronizer
Author: Ali Alnuaimi / RAQIB Defensive Security Toolkit
Description:
    Analyzes, updates, and completes translations across all 20 supported languages in RAQIB.
    Features:
      - Batch translation with Google Translate API (fast, reliable, free, zero API key)
      - Placeholder & format specifier protection (%s, %d, %0.2f, etc.)
      - Escaping validation for safe Bash string injection
      - Automatic backup (.bak) of modules/lang.sh before writing
      - Support for updating modules/lang.sh directly or writing to modules/lang_cache/
      - Single-string mode for integration with auto_translate.sh
"""

import sys
import os
import re
import json
import time
import argparse
import urllib.request
import urllib.parse
from collections import defaultdict

# Force UTF-8 stdout on all platforms
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Root directory resolution
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
LANG_SH_PATH = os.path.join(SCRIPT_DIR, "lang.sh")
CACHE_DIR = os.path.join(SCRIPT_DIR, "lang_cache")

# All 20 supported language codes in RAQIB
SUPPORTED_LANGUAGES = [
    ("ar", "العربية", "ar"),
    ("en", "English", "en"),
    ("fr", "Français", "fr"),
    ("es", "Español", "es"),
    ("de", "Deutsch", "de"),
    ("tr", "Türkçe", "tr"),
    ("fa", "فارسی", "fa"),
    ("ru", "Русский", "ru"),
    ("ku", "کوردی", "ckb"),
    ("zh", "中文", "zh-CN"),
    ("ur", "اردو", "ur"),
    ("pt", "Português", "pt"),
    ("id", "Bahasa Indonesia", "id"),
    ("it", "Italiano", "it"),
    ("ja", "日本語", "ja"),
    ("hi", "हिन्दी", "hi"),
    ("nl", "Nederlands", "nl"),
    ("ko", "한국어", "ko"),
    ("pl", "Polski", "pl"),
    ("uk", "Українська", "uk"),
]

LANG_CODE_TO_GOOGLE = {code: gcode for code, _, gcode in SUPPORTED_LANGUAGES}
LANG_CODE_TO_NAME = {code: name for code, name, _ in SUPPORTED_LANGUAGES}

# ANSI Colors for Terminal
GREEN = "\033[0;32m"
CYAN = "\033[0;36m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BOLD = "\033[1m"
GREY = "\033[1;30m"
NC = "\033[0m"


def parse_lang_file(filepath=LANG_SH_PATH):
    """
    Parses modules/lang.sh and returns:
      - translations: dict of dicts {lang_code: {key: value}}
      - all_keys: set of all distinct keys across EN and AR
    """
    if not os.path.isfile(filepath):
        print(f"{RED}[!] Error: File not found: {filepath}{NC}", file=sys.stderr)
        sys.exit(1)

    translations = defaultdict(dict)
    pattern = re.compile(r'^\s*STR_([A-Za-z]+)\[([a-zA-Z0-9_]+)\]\s*=\s*(.*)$')

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_clean = line.strip()
            if not line_clean.startswith("STR_"):
                continue
            m = pattern.match(line_clean)
            if m:
                lang = m.group(1).lower()
                key = m.group(2)
                raw_val = m.group(3).strip()
                # Strip leading and trailing quotes if present
                if (raw_val.startswith('"') and raw_val.endswith('"')) or (raw_val.startswith("'") and raw_val.endswith("'")):
                    val = raw_val[1:-1]
                else:
                    val = raw_val
                translations[lang][key] = val

    all_keys = set(translations["en"].keys()) | set(translations["ar"].keys())
    return translations, all_keys


def protect_placeholders(text):
    """
    Replaces %s, %d, %0.2f, %1$s, etc. with safe tokens __VAR_N__
    so external translation engines don't alter or corrupt them.
    """
    placeholders = []

    def repl(m):
        placeholders.append(m.group(0))
        return f"__VAR{len(placeholders)-1}__"

    # Matches %s, %d, %i, %f, %1$s, %0.2f, etc.
    protected = re.sub(r'%(\d+\$)?[0-9]*\.?[0-9]*[a-zA-Z]', repl, text)
    return protected, placeholders


def restore_placeholders(text, placeholders):
    """Restores __VAR_N__ back to original placeholders."""
    res = text
    for i, orig in enumerate(placeholders):
        # Allow case-insensitive and whitespace tolerant replacement
        res = re.sub(rf'__\s*VAR\s*{i}\s*__', orig, res, flags=re.IGNORECASE)
    return res


def translate_text(text, target_lang, source_lang="en", timeout=7, retries=3):
    """Translates a single text string using Google Translate free endpoint."""
    if not text.strip():
        return text

    g_target = LANG_CODE_TO_GOOGLE.get(target_lang, target_lang)
    protected, placeholders = protect_placeholders(text)

    url = (
        f"https://translate.googleapis.com/translate_a/single?"
        f"client=gtx&sl={source_lang}&tl={g_target}&dt=t&q={urllib.parse.quote(protected)}"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                translated = "".join(chunk[0] for chunk in data[0] if chunk[0])
                restored = restore_placeholders(translated, placeholders)
                return restored.strip()
        except Exception as e:
            if attempt == retries - 1:
                return ""
            time.sleep(0.5 * (attempt + 1))
    return ""


def translate_batch(texts, target_lang, source_lang="en", timeout=10, retries=3):
    """
    Translates a list of texts in a single batch request using delimiter separator.
    Dramatically increases speed and avoids request overhead.
    """
    if not texts:
        return []

    DELIMITER = "\n---RAQIB_SEP---\n"
    g_target = LANG_CODE_TO_GOOGLE.get(target_lang, target_lang)

    protected_list = []
    all_placeholders = []
    for t in texts:
        p, ph = protect_placeholders(t)
        protected_list.append(p)
        all_placeholders.append(ph)

    combined = DELIMITER.join(protected_list)
    url = (
        f"https://translate.googleapis.com/translate_a/single?"
        f"client=gtx&sl={source_lang}&tl={g_target}&dt=t&q={urllib.parse.quote(combined)}"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                full = "".join(chunk[0] for chunk in data[0] if chunk[0])
                # Split back by delimiter (flexible regex for spacing/punctuation changes by translator)
                parts = re.split(r'\s*---\s*RAQIB_SEP\s*---\s*', full)

                # Fallback if delimiter was mangled: line-by-line fallback
                if len(parts) != len(texts):
                    # Fallback to individual translation for this batch
                    results = []
                    for single_text in texts:
                        res = translate_text(single_text, target_lang, source_lang)
                        results.append(res if res else single_text)
                    return results

                results = []
                for p, ph in zip(parts, all_placeholders):
                    restored = restore_placeholders(p, ph)
                    results.append(restored.strip())
                return results
        except Exception:
            if attempt == retries - 1:
                # Last resort fallback: individual translations
                results = []
                for single_text in texts:
                    res = translate_text(single_text, target_lang, source_lang)
                    results.append(res if res else single_text)
                return results
            time.sleep(0.5 * (attempt + 1))

    return texts


def escape_bash_string(text):
    """Escapes special Bash characters inside double quotes."""
    text = text.replace("\\", "\\\\")
    text = text.replace('"', '\\"')
    text = text.replace("`", "\\`")
    text = text.replace("$", "\\$")
    return text


def print_status_report(translations, all_keys):
    """Displays a colored terminal report showing completeness for each language."""
    total_keys = len(all_keys)
    print(f"\n{BOLD}{CYAN}═════════════════════════════════════════════════════════════════{NC}")
    print(f"{BOLD}  🛡️  RAQIB Translation Completeness Report ({total_keys} total keys){NC}")
    print(f"{BOLD}{CYAN}═════════════════════════════════════════════════════════════════{NC}")
    print(f"  {BOLD}{'Code':<5} {'Language':<22} {'Available':<12} {'Missing':<10} {'Status'}{NC}")
    print(f"  {'─'*4} {'─'*21} {'─'*11} {'─'*9} {'─'*12}")

    fully_complete = 0
    for code, name, _ in SUPPORTED_LANGUAGES:
        have = len(translations.get(code, {}))
        missing = total_keys - have
        pct = (have / total_keys * 100) if total_keys > 0 else 0

        if missing == 0:
            status = f"{GREEN}100.0%  ✔ Complete{NC}"
            fully_complete += 1
        elif pct >= 80:
            status = f"{YELLOW}{pct:5.1f}%  ⠹ Needs Sync ({missing}){NC}"
        else:
            status = f"{RED}{pct:5.1f}%  ✘ Incomplete ({missing}){NC}"

        print(f"  {BOLD}{code:<5}{NC} {name:<22} {have:<12} {missing:<10} {status}")

    print(f"{BOLD}{CYAN}═════════════════════════════════════════════════════════════════{NC}")
    print(f"  Summary: {fully_complete}/{len(SUPPORTED_LANGUAGES)} languages fully complete.\n")


def update_language(code, translations, all_keys, batch_size=25, dry_run=False):
    """Translates all missing keys for a given language code and returns new key-value dict."""
    en_dict = translations.get("en", {})
    ar_dict = translations.get("ar", {})
    target_dict = translations.get(code, {})

    missing_keys = [k for k in sorted(all_keys) if k not in target_dict or not target_dict[k].strip()]
    if not missing_keys:
        return {}

    name = LANG_CODE_TO_NAME.get(code, code)
    print(f"  {CYAN}▶{NC} Translating {YELLOW}{len(missing_keys)}{NC} missing keys for {BOLD}{name} ({code}){NC}...")

    # Prepare batches
    new_translations = {}
    batches = [missing_keys[i:i + batch_size] for i in range(0, len(missing_keys), batch_size)]

    for idx, batch in enumerate(batches, 1):
        sources = []
        for k in batch:
            src = en_dict.get(k) or ar_dict.get(k, k)
            sources.append(src)

        translated = translate_batch(sources, code, source_lang="en")
        for k, trans in zip(batch, translated):
            new_translations[k] = trans

        pct = int(idx / len(batches) * 100)
        sys.stdout.write(f"\r     [{pct}%] {len(new_translations)}/{len(missing_keys)} completed...")
        sys.stdout.flush()

    sys.stdout.write(f"\r     {GREEN}✔ Completed {len(new_translations)} keys for {name}!{NC}\n")
    return new_translations


def append_to_lang_sh(new_by_lang):
    """
    Appends the new translations organized by language block to modules/lang.sh.
    Creates a backup copy (lang.sh.bak) beforehand.
    """
    if not new_by_lang:
        return

    # Create backup
    backup_path = LANG_SH_PATH + ".bak"
    try:
        with open(LANG_SH_PATH, "r", encoding="utf-8") as f_in:
            with open(backup_path, "w", encoding="utf-8") as f_out:
                f_out.write(f_in.read())
        print(f"  {GREY}ℹ Backup saved to: {backup_path}{NC}")
    except Exception as e:
        print(f"  {YELLOW}Warning: Could not create backup: {e}{NC}")

    # Append new translations
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LANG_SH_PATH, "a", encoding="utf-8") as f:
        f.write(f"\n\n# ============================================================================\n")
        f.write(f"#  AUTO-GENERATED TRANSLATIONS — RAQIB Language Synchronizer\n")
        f.write(f"#  Generated on: {timestamp}\n")
        f.write(f"# ============================================================================\n\n")

        for code, kv in new_by_lang.items():
            if not kv:
                continue
            lc_upper = code.upper()
            name = LANG_CODE_TO_NAME.get(code, code)
            f.write(f"# ----- {name} ({lc_upper}) [{len(kv)} keys] -----\n")
            for k in sorted(kv.keys()):
                esc_val = escape_bash_string(kv[k])
                f.write(f'STR_{lc_upper}[{k}]="{esc_val}"\n')
            f.write("\n")

    print(f"  {GREEN}✔ Successfully updated {LANG_SH_PATH} with all missing translations!{NC}")


def save_to_cache(new_by_lang):
    """Saves new translations to modules/lang_cache/<CODE>.sh."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    for code, kv in new_by_lang.items():
        if not kv:
            continue
        lc_upper = code.upper()
        cache_file = os.path.join(CACHE_DIR, f"{code}.sh")
        with open(cache_file, "a", encoding="utf-8") as f:
            for k in sorted(kv.keys()):
                esc_val = escape_bash_string(kv[k])
                f.write(f'STR_{lc_upper}[{k}]="{esc_val}"\n')
        print(f"  {GREEN}✔ Cached {len(kv)} keys in: {cache_file}{NC}")


def main():
    parser = argparse.ArgumentParser(description="RAQIB Translation & Language Synchronizer")
    parser.add_argument("--status", action="store_true", help="Display language completeness status report")
    parser.add_argument("--all", action="store_true", help="Translate and complete missing keys for all languages")
    parser.add_argument("--lang", type=str, help="Target language code to complete (e.g. fr, es, tr, ku)")
    parser.add_argument("--cache-only", action="store_true", help="Save to lang_cache/ instead of modifying lang.sh")
    parser.add_argument("--single-key", nargs=2, metavar=("TEXT", "LANG"), help="Translate a single string and output result (for shell integration)")
    parser.add_argument("--batch-size", type=int, default=25, help="Number of strings per batch request (default: 25)")
    args = parser.parse_args()

    # Mode 1: Single key direct translation (for auto_translate.sh bridge)
    if args.single_key:
        text, target_lang = args.single_key
        res = translate_text(text, target_lang)
        print(res)
        return

    # Parse current state
    translations, all_keys = parse_lang_file()

    # Mode 2: Status report only
    if args.status:
        print_status_report(translations, all_keys)
        return

    # Mode 3: Translate all or specific language
    targets = []
    if args.all:
        targets = [code for code, _, _ in SUPPORTED_LANGUAGES if code not in ("ar", "en")]
    elif args.lang:
        code = args.lang.lower().strip()
        if code not in LANG_CODE_TO_GOOGLE:
            print(f"{RED}[!] Error: Unsupported language code '{code}'. Supported codes: {list(LANG_CODE_TO_GOOGLE.keys())}{NC}")
            sys.exit(1)
        targets = [code]
    else:
        # Default with no args: show status and guide
        print_status_report(translations, all_keys)
        print(f"{BOLD}Options to complete translations:{NC}")
        print(f"  {CYAN}python modules/update_translations.py --all{NC}         # Complete all 18 languages")
        print(f"  {CYAN}python modules/update_translations.py --lang fr{NC}     # Complete a single language")
        print(f"  {CYAN}python modules/update_translations.py --cache-only{NC}  # Save to lang_cache/ directory\n")
        return

    print(f"\n{BOLD}{CYAN}🚀 Starting RAQIB Translation Synchronizer...{NC}\n")
    new_by_lang = {}
    for code in targets:
        new_dict = update_language(code, translations, all_keys, batch_size=args.batch_size)
        if new_dict:
            new_by_lang[code] = new_dict

    total_translated = sum(len(d) for d in new_by_lang.values())
    print(f"\n{BOLD}Total translated strings:{NC} {GREEN}{total_translated}{NC}")

    if total_translated > 0:
        if args.cache_only:
            save_to_cache(new_by_lang)
        else:
            append_to_lang_sh(new_by_lang)

    print(f"\n{BOLD}{GREEN}✔ Done! All targeted languages are now synchronized.{NC}\n")


if __name__ == "__main__":
    main()
