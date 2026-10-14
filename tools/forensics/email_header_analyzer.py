#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =====================================================
#  Email Header Analyzer — محلّل ترويسات البريد (قراءة فقط)
#  Defensive phishing / spoofing triage for emails I received on my own domains.
#
#  Checks (heuristics only, every finding is explainable):
#    1. SPF / DKIM / DMARC verdicts parsed from Authentication-Results /
#       Received-SPF headers (no DNS lookups, no network)
#    2. Received chain: hop count, missing timestamps, out-of-order relays,
#       private/residential IPs in early hops
#    3. From vs Return-Path vs Reply-To domain mismatches
#    4. Display-name spoofing (a different domain inside the friendly name)
#    5. Free-mailer mismatch (From = gmail.com but Reply-To = other domain)
#
#  Usage:
#    python3 email_header_analyzer.py suspicious.eml
#    python3 email_header_analyzer.py --json suspicious.eml   (NDJSON findings on stdout)
#    python3 email_header_analyzer.py --help
#    python3 email_header_analyzer.py - < suspicious.eml       (stdin)
#
#  Exit codes: 0 = no suspicious findings | 1 = findings detected | 2 = usage/file error
#
#  Zero third-party dependencies (stdlib only). Read-only: the email file is
#  never modified, no network calls are made, nothing leaves the machine.
# =====================================================
import sys, json, re, socket, datetime

# Robust console output: never crash on non-UTF8 terminals (e.g. Windows cp1252)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, OSError):
    pass

TOOL = "email_header_analyzer"

USAGE = """Email Header Analyzer — defensive phishing/spoofing triage (read-only, stdlib only)

Checks: SPF/DKIM/DMARC verdicts (from headers, no DNS), Received chain anomalies,
From/Return-Path/Reply-To mismatches, display-name spoofing, free-mailer senders.

Usage:
  python3 email_header_analyzer.py suspicious.eml          human report
  python3 email_header_analyzer.py --json suspicious.eml   NDJSON findings on stdout
  python3 email_header_analyzer.py -                        read from stdin
  python3 email_header_analyzer.py --rules <file|dir>      extra resource lists
  python3 email_header_analyzer.py --help                   this help

Extensible resource lists (any file extension — the file NAME selects the list):
  tools/forensics/resources/email/free_mailers.*    → extra free-mailer domains
  tools/forensics/resources/email/lure_keywords.*   → extra subject lure keywords
  --rules <file|dir>                                → additional resource source
Format: one entry per line, '#' = comment. Entries merge with the built-in defaults.

Exit codes: 0 = no findings | 1 = findings detected | 2 = usage/file error
"""
EVENTS_FILE = None  # set in main() — same schema as modules/common.sh raqib_emit_event

def emit_event(sev, msg):
    """Append to RAQIB's existing .raqib_events.jsonl using the exact common.sh schema.
    Silently skipped when the file cannot be found/written — output above stays correct."""
    if not EVENTS_FILE:
        return
    try:
        line = json.dumps({
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "host": socket.gethostname() or "unknown",
            "severity": sev,
            "tool": TOOL,
            "message": msg,
            "operator": "unknown",
            "product": "RAQIB",
        }, ensure_ascii=False)
        with open(EVENTS_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass

JSON_MODE = False

def info(text):
    """Human-mode informational line ([+] pass lines). Suppressed in --json mode
    so the NDJSON stream on stdout stays clean."""
    if not JSON_MODE:
        print(text)

FINDINGS = []

# ─── Extensible resource lists ─────────────────────────────────────────────
# Built-in defaults + any file named <list>.* in resources/email/ + anything
# passed via --rules (file or dir). ANY extension works: the file's base name
# selects the list. Format: one entry per line, '#' = comment. Entries merge
# with the defaults and deduplicate case-insensitively.
import os
RESOURCES_DIRS = [os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources", "email")]

DEFAULT_FREE_MAILERS = ["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
                        "protonmail.com", "icloud.com", "live.com", "mail.com", "yandex.com"]
DEFAULT_LURE_KEYWORDS = ["urgent", "immediately", "suspend", "verify your account",
                         "unusual activity", "password expires", "click here",
                         "confirm your identity", "final warning", "wire transfer"]

def _parse_list_file(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip().strip("\r")
                if line:
                    out.append(line)
    except OSError:
        pass
    return out

def load_resource_list(list_name, defaults):
    """Return defaults + entries from every <list_name>.* file in resource dirs
    and the --rules path (file with matching base name, or a dir)."""
    entries, seen = [], set()
    roots = list(RESOURCES_DIRS)
    extra = RULES_EXTRA
    if extra:
        if not os.path.exists(extra):
            print(f"--rules path not found: {extra} — continuing with built-in lists", file=sys.stderr)
        elif os.path.isdir(extra):
            roots.append(extra)
        elif os.path.isfile(extra) and os.path.splitext(os.path.basename(extra))[0] == list_name:
            roots.append(os.path.dirname(os.path.abspath(extra)))
    for root in roots:
        if not os.path.isdir(root):
            continue
        for fn in sorted(os.listdir(root)):
            base, ext = os.path.splitext(fn)          # extension is IGNORED
            if base == list_name and ext != ".py":      # never import code, only data
                entries.extend(_parse_list_file(os.path.join(root, fn)))
    # defaults first, then file entries, deduplicated case-insensitively
    result, seen = [], set()
    for e in defaults + entries:
        if e.lower() not in seen:
            seen.add(e.lower())
            result.append(e)
    return result

def finding(sev, check, what, why, fix):
    """What was checked / what was found / why it matters / suggested fix."""
    FINDINGS.append({"tool": TOOL, "severity": sev, "check": check,
                     "finding": what, "impact": why, "fix": fix})
    emit_event(sev, f"{check}: {what}")

# ─── helpers ────────────────────────────────────────────────
RULES_EXTRA = ""  # set by --rules in main()

def domain_of(addr):
    """Return lowercase domain of an email address, or ''. Robust against junk."""
    if not addr or "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[1].strip().strip(">").strip().lower()

def addr_of(value):
    """Extract the bare address from 'Name <a@b>' style values using stdlib only."""
    # Use the LAST <...> group: trick From lines like
    #   "Name <fake@spoofed.com>" <real@attacker.com>
    # are parsed correctly (the real address is the last one).
    m = re.findall(r"<([^<>]+)>", value or "")
    if m:
        return m[-1].strip()
    return (value or "").strip()

def _ip_is_private(ip):
    try:
        n = int.from_bytes(socket.inet_aton(ip), "big")
        return ((n >> 24) in (10, 127) or (n >> 20) == 0xAC1 or (n >> 16) == 0xC0A8
                or (n >> 22) == 0x2E1 or (n >> 28) == 0xE or (n >> 28) == 0xF)
    except OSError:
        return False

# ─── 1. SPF / DKIM / DMARC verdicts from headers ─────────────
def check_auth(msg):
    auth_headers = msg.get_all("Authentication-Results") or []
    spf_headers = msg.get_all("Received-SPF") or []
    auth_text = " ".join(str(h) for h in auth_headers)
    spf_text = " ".join(str(h) for h in spf_headers)
    combined = (auth_text + " " + spf_text).lower()

    if not auth_headers and not spf_headers:
        finding("medium", "no_auth_headers",
                "No Authentication-Results / Received-SPF headers present",
                "Without SPF/DKIM/DMARC verdicts the message's authenticity cannot be verified from headers alone — common in direct-to-MX spam or misconfigured relays.",
                "Verify SPF/DMARC manually on the sending domain; if this is a normal mailbox, check whether your provider strips auth headers.")
        return

    # Per-mechanism verdict parsing (pass / fail / softfail / none / permerror ...)
    spf_m = re.search(r"\bspf=(\w+)", combined)
    dkim_m = re.search(r"\bdkim=(\w+)", combined)
    dmarc_m = re.search(r"\bdmarc=(\w+)", combined)

    if spf_m:
        v = spf_m.group(1)
        if v == "fail":
            finding("high", "spf_fail",
                    "SPF verdict: fail — the sending server is not authorized by the envelope domain",
                    "The sending server is not authorized by the envelope-domain's SPF record — spoofing or a misconfigured relay.",
                    "Treat as spoofed unless you can verify a legitimate sending path (e.g., a known forwarder breaking SPF); check DMARC verdict before trusting.")
        elif v in ("softfail", "permerror", "temperror"):
            finding("medium", f"spf_{v}",
                    f"SPF verdict: {v}",
                    "softfail = not authorized but not a hard reject; permerror/temperror = broken SPF setup or DNS failure — spammers often operate domains with broken SPF.",
                    "Check DMARC verdict: with DMARC pass, this is a forwarder artifact; without it, treat the sender as questionable.")
        elif v == "pass":
            info("  [+] SPF pass")
    else:
        finding("low", "spf_missing",
                "No SPF verdict in the authentication headers",
                "Your MTA evaluates SPF for every inbound message; a missing verdict means the header was stripped or the evaluation never ran.",
                "Compare with your MTA logs for this Message-ID before trusting the header set.")

    if dkim_m:
        v = dkim_m.group(1)
        if v == "fail":
            finding("high", "dkim_fail",
                    "DKIM verdict: fail — signature present but did not validate",
                    "The signature did not validate — the body or headers were altered in transit, or the signer is not who they claim.",
                    "Compare the DKIM d= domain with the From domain: a different d= domain is a strong spoofing indicator.")
        elif v == "none":
            finding("low", "dkim_none",
                    "DKIM verdict: none — message carries no DKIM signature",
                    "No cryptographic proof of content integrity exists for this message; combined with other mismatches it strengthens the phishing case.",
                    "Not a finding by itself; weigh it together with SPF/DMARC results and identity mismatches.")
        elif v == "pass":
            info("  [+] DKIM pass")

    if dmarc_m:
        v = dmarc_m.group(1)
        if v == "fail":
            finding("critical", "dmarc_fail",
                    "DMARC verdict: fail — From domain is neither SPF- nor DKIM-aligned",
                    "DMARC failure is the strongest header-based spoofing verdict available: alignment of the From domain to the authorized sender failed.",
                    "Do not trust the sender; report as phishing and block the sender domain at the gateway if policy allows.")
        elif v == "pass":
            info("  [+] DMARC pass")
        elif v in ("none", "temperror", "permerror"):
            finding("low", f"dmarc_{v}",
                    f"DMARC verdict: {v}",
                    "The From domain publishes no usable DMARC policy (or DNS failed) — no protection and no signal either way.",
                    "Not proof of phishing; rely on the other indicators in this report.")
    else:
        finding("low", "dmarc_missing",
                "No DMARC verdict in the authentication headers",
                "Without a DMARC verdict there is no alignment decision to lean on for this message.",
                "Weave the SPF/DKIM results and identity checks together instead.")

# ─── 2. Received chain analysis ─────────────────────────────
def check_received_chain(msg):
    recv = msg.get_all("Received") or []
    if not recv:
        finding("high", "no_received_chain",
                "No Received headers — the relay history has been stripped",
                "Every legitimate MTA adds a Received header; their absence means forged headers or a broken relay.",
                "Treat as hostile: verify via the raw SMTP envelope (Return-Path) and your own MTA logs.")
        return
    if len(recv) > 8:
        finding("low", "long_received_chain",
                f"Unusually long relay chain: {len(recv)} hops",
                "Long chains are typical of anonymizing relay chains or mailing lists; they also make origin tracing harder.",
                "Identify the earliest trustworthy hop (your own MTA) and ignore injected fake hops below it.")

    timestamps = []
    for i, h in enumerate(recv):
        hm = re.search(r";\s*(.+)$", str(h))
        if not hm:
            finding("low", "received_missing_timestamp",
                    f"Hop {i+1} has no timestamp",
                    "Received headers without timestamps are often hand-forged by phishers.",
                    f"Cross-check hop {i+1} against your MTA logs; forged hops usually appear below your own server's hop.")
        else:
            try:
                from email.utils import parsedate_to_datetime
                timestamps.append((i, parsedate_to_datetime(hm.group(1).strip())))
            except (TypeError, ValueError):
                finding("low", "received_unparseable_timestamp",
                        f"Hop {i+1} timestamp unparseable: {hm.group(1).strip()[:60]}",
                        "Unparseable timestamps are a header-forgery marker.",
                        "Verify this hop in your MTA logs before trusting anything below it.")

    # Out-of-order timestamps (later-appended hops should be *later* in time)
    seq = [t for _, t in timestamps]
    if len(seq) >= 2 and any(b < a for a, b in zip(seq, seq[1:])):
        finding("medium", "received_time_anomaly",
                "Received timestamps are out of chronological order",
                "MTAs append headers top-down with increasing times; decreasing times indicate injected/forged hops or severe clock skew.",
                "Trust only the hops your own infrastructure added (bottom of the chain); re-verify the rest from logs.")

    # Private/residential IP in an early (farthest) hop
    first = str(recv[-1])  # earliest hop
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", first)
    if ips and _ip_is_private(ips[0]):
        finding("low", "private_ip_origin",
                f"Earliest hop originated from private address {ips[0]}",
                "Direct-to-MX spam tools often run on compromised home machines (RFC1918 source at the first hop).",
                "Correlate with your gateway logs; the true public source may be in the adjacent hop.")

# ─── 3. From / Return-Path / Reply-To mismatches ────────────
def check_identity_mismatch(msg):
    free_mailers = set(load_resource_list("free_mailers", DEFAULT_FREE_MAILERS))
    from_raw = msg.get("From", "")
    envelope = addr_of(msg.get("Return-Path", "") or msg.get("Envelope-From", ""))
    reply_to = addr_of(msg.get("Reply-To", ""))
    from_addr = addr_of(from_raw)
    d_from, d_env, d_reply = domain_of(from_addr), domain_of(envelope), domain_of(reply_to)

    if not d_from:
        finding("high", "malformed_from",
                "From header missing or has no domain",
                "Mail without a valid From domain cannot be authenticated and is typically malicious.",
                "Discard; report as spam.")
        return

    if d_env and d_env != d_from:
        sev = "medium" if d_from in free_mailers else "high"
        finding(sev, "envelope_mismatch",
                f"From domain ({d_from}) differs from envelope Return-Path domain ({d_env})",
                "The message claims one sender but was sent from a different envelope address — classic spoofing/bec pattern, though mailing lists do this legitimately (hence lower severity for consumer mailers).",
                "Check whether the envelope domain has a published SPF record authorizing the From domain's systems; if not, treat as spoofed.")
    if d_reply and d_reply != d_from:
        sev = "high"
        if d_from in free_mailers and d_reply not in free_mailers:
            sev = "critical"
        finding(sev, "reply_to_mismatch",
                f"From domain ({d_from}) differs from Reply-To domain ({d_reply})",
                "Replies would be redirected to an unrelated domain — the signature move of CEO-fraud/BEC and account-takeover phishing.",
                "Contact the alleged sender through a known-good channel; block the Reply-To domain at the gateway.")

    # 4. Display-name spoof: a different domain embedded in the friendly name
    name_part = re.sub(r"<.*", "", from_raw or "").strip('" ')
    d_name = [d for d in re.findall(r"[\w.-]+\.[a-z]{2,}", name_part.lower())]
    if d_name and d_from not in free_mailers and d_name[0] != d_from:
        finding("high", "display_name_spoof",
                f"Friendly name contains domain '{d_name[0]}' but real From is '{from_addr}'",
                "The visible name impersonates a brand; only the hidden address shows the true sender — pure social engineering against inattentive readers.",
                "Train users / rewrite subject tags; block the real sender domain.")

    # 5. Free-mailer mismatch: From claims a corporate brand but address is a free mailer
    if d_from in free_mailers:
        finding("medium", "free_mailer_sender",
                f"Sender uses free mailer ({d_from}) — likely not the official domain of any claimed brand",
                "Businesses do not send invoices/security notices from gmail/hotmail; free-mailer From is a strong phish marker (not proof — small vendors do this).",
                "Verify the sender out-of-band; quarantine similar senders.")

# ─── 4. Single-header forgery signals ────────────────────────
def check_forgery_signals(msg):
    from email.utils import parsedate_to_datetime

    # (a) Message-ID domain should match the From domain
    d_from = domain_of(addr_of(msg.get("From", "")))
    mid = msg.get("Message-ID", "") or ""
    mid_domain = re.search(r"@([\w.-]+)", mid)
    if mid_domain and d_from and mid_domain.group(1).lower() != d_from:
        finding("medium", "message_id_mismatch",
                f"Message-ID domain ({mid_domain.group(1)}) differs from From domain ({d_from})",
                "The Message-ID is stamped by the sending software of the real origin; a domain different from From is a classic fingerprint of spoofed/bulk mail",
                "Combine with the other indicators — alone it can be a mailing list artifact; together with auth failures it confirms forgery.")

    # (b) Date header vs last-Received time skew (> 24h)
    recv = msg.get_all("Received") or []
    try:
        date_hdr = parsedate_to_datetime(msg.get("Date", ""))
        m = re.search(r";\s*(.+)$", str(recv[-1]) if recv else "")
        recv_time = parsedate_to_datetime(m.group(1).strip()) if m else None
        if date_hdr and recv_time:
            skew = abs((recv_time - date_hdr).total_seconds())
            if skew > 24 * 3600:
                finding("low", "date_received_skew",
                        f"Date header and delivery time differ by {int(skew / 3600)} hours",
                        "A large gap between the claimed send time and the actual delivery time means the Date header was hand-crafted or the message was massively delayed/resent by a spam run.",
                        "Check the Received chain timestamps for consistency; forged Date headers often appear together with other anomalies.")
    except (TypeError, ValueError):
        pass  # unparseable dates are reported by the Received-chain checks

    # (c) Topmost hop claims a localhost/loopback origin — forged internal relay
    if recv:
        top = str(recv[0])
        if re.search(r"from\s+(localhost|127\.0\.0\.1|\[::1\])", top, re.IGNORECASE):
            finding("medium", "forged_localhost_hop",
                    "The topmost Received header claims the mail came from localhost/127.0.0.1",
                    "Your own MTA stamps the true topmost hop; a fake chain injected above it starts with a loopback origin to look internal — phishers forge this to defeat naive filtering.",
                    "Find YOUR server's hop in the chain (the bottom-most one it stamped) and ignore everything above it as injected noise.")

    # (d) Null envelope sender with normal content
    rp = (msg.get("Return-Path") or "").strip()
    if rp == "<>":
        finding("low", "null_return_path",
                "Return-Path is the null sender '<>'",
                "Null-envelope mail is how bounces are sent; normal marketing/notification content arriving with a null envelope means the sender is trying to dodge bounce processing.",
                "Low severity alone; combine with other indicators — a phishing lure with null sender strengthens the case.")

    # (e) Subject social-engineering lure keywords (header-level heuristic)
    subj = (msg.get("Subject") or "").lower()
    lures = [k for k in load_resource_list("lure_keywords", DEFAULT_LURE_KEYWORDS)
             if k in subj]
    if len(lures) >= 2:
        finding("low", "social_engineering_subject",
                f"Subject matches multiple lure patterns: {', '.join(lures[:4])}",
                "Urgency + threat + action demand is the standard phishing pre-text; the header alone is not proof, which is why severity stays low.",
                "Correlate with the auth verdicts above: lure subject + auth failures = phishing with high confidence.")

# ─── main ────────────────────────────────────────────────────
def main():
    global EVENTS_FILE, JSON_MODE, RULES_EXTRA
    args = sys.argv[1:]
    json_mode = "--json" in args
    JSON_MODE = json_mode
    args = [a for a in args if a != "--json"]
    if "--rules" in args:
        i = args.index("--rules")
        if i + 1 < len(args):
            RULES_EXTRA = args[i + 1]
            del args[i:i + 2]
        else:
            print("--rules needs a path (try --help)", file=sys.stderr)
            return 2

    if "--help" in args or "-h" in args or not args:
        print(USAGE)
        return 0 if ("--help" in args or "-h" in args) else 2

    path = args[0]
    try:
        fh = sys.stdin if path == "-" else open(path, "r", encoding="utf-8", errors="replace")
        raw = fh.read()
        if fh is not sys.stdin:
            fh.close()
        if not raw.strip():
            raise ValueError("empty input")
    except (OSError, ValueError) as e:
        print(f"ERROR: cannot read email input: {e}", file=sys.stderr)
        return 2

    # Locate the existing RAQIB event log (same NDJSON schema as common.sh)
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "..", "..", ".raqib_events.jsonl"),
                 os.path.join(here, ".raqib_events.jsonl")):
        if os.path.exists(os.path.dirname(cand)):
            EVENTS_FILE = cand
            break

    from email import message_from_string
    msg = message_from_string(raw)

    if not json_mode:
        subj = msg.get("Subject", "(none)")
        print(f"Email Header Analyzer — Subject: {subj}")
        print("=" * 60)

    check_auth(msg)
    check_received_chain(msg)
    check_identity_mismatch(msg)
    check_forgery_signals(msg)

    if json_mode:
        for f in FINDINGS:
            print(json.dumps(f, ensure_ascii=False))
    else:
        if not FINDINGS:
            print("  [✓] No suspicious header indicators found.")
        for f in FINDINGS:
            print(f"  [{f['severity'].upper():<8}] {f['check']}")
            print(f"     └ found: {f['finding']}")
            print(f"     └ why:   {f['impact']}")
            print(f"     └ fix:   {f['fix']}")

    worst = max((f["severity"] for f in FINDINGS), key=lambda s: ["low","medium","high","critical"].index(s), default=None)
    return 1 if FINDINGS else 0

if __name__ == "__main__":
    sys.exit(main())
