#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║              RATELIMITER AUTOPWN  v4.0                   ║
║              by Robert Mwatua                            ║
║              Authorised security research only           ║
╚══════════════════════════════════════════════════════════╝

Just run:  python3 bypass_tester.py
Everything is interactive. No flags to memorise.
"""

import os, sys, time, json, random, hashlib, threading, socket, subprocess, re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from pathlib import Path

# ── dependency bootstrap ──────────────────────────────────────────────────────
def _install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"])

def _require(import_name, pip_name=None):
    try:
        return __import__(import_name)
    except ImportError:
        pip_name = pip_name or import_name
        print(f"  [~] Installing {pip_name}...")
        _install(pip_name)
        return __import__(import_name)

_require("rich")
_require("requests")

import requests
from rich.console  import Console
from rich.panel    import Panel
from rich.table    import Table
from rich.prompt   import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
from rich          import box

# optional anonymity libs
try:
    import socks
    from stem import Signal
    from stem.control import Controller
    TOR_OK = True
except ImportError:
    TOR_OK = False

try:
    from fake_useragent import UserAgent as _FUA
    _fua = _FUA()
    FUA_OK = True
except Exception:
    FUA_OK = False

# ── console ───────────────────────────────────────────────────────────────────
con = Console(highlight=False)

VERSION   = "4.0"
C_PRI     = "bright_green"
C_DIM     = "green"
C_ACC     = "red"
C_WARN    = "yellow"
C_INFO    = "cyan"
C_MUTED   = "bright_black"
C_WHITE   = "white"
C_VULN    = "bold red"
C_SAFE    = "bold green"

# ── constants ─────────────────────────────────────────────────────────────────
FALLBACK_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.4.1 Mobile Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/124.0.6367.82 Mobile Safari/537.36",
    "curl/8.7.1", "python-httpx/0.27.0", "Wget/1.21.4", "Go-http-client/2.0",
]

IP_HEADERS = [
    "X-Forwarded-For","X-Real-IP","X-Originating-IP","X-Remote-IP",
    "X-Client-IP","CF-Connecting-IP","True-Client-IP","X-Cluster-Client-IP",
    "Forwarded","X-ProxyUser-Ip",
]

REFERERS = [
    "https://www.google.com/","https://www.bing.com/","https://duckduckgo.com/",
    "https://t.co/","https://www.reddit.com/","https://github.com/",
]

TECHNIQUES = [
    ("1","IP Header Spoofing",       "Medium", "Rotate client IP across 10 proxy headers + RFC 7239 chains"),
    ("2","Jittered Timing",          "Medium", "Exponential jitter to evade fixed-window & token-bucket limiters"),
    ("3","UA Rotation",              "Medium", "Real browser UAs paired with matching platform hints"),
    ("4","Session Rotation",         "Medium", "Fresh SHA-256 session IDs, CSRF & Bearer tokens per request"),
    ("5","Concurrent Burst",         "Low",    "Race-condition attack — parallel threads before atomic updates"),
    ("6","Full Header Combo",        "High",   "All evasion headers simultaneously — most realistic fingerprint"),
    ("7","Adaptive Threshold Probe", "High",   "Feedback loop learns exact req/s limit via binary search"),
    ("8","Tor Circuit Routing",      "Maximum","New exit IP every N requests via Tor SOCKS5"),
    ("9","Request Fragmentation",    "Medium", "Vary Content-Type & payload size to confuse body-aware limiters"),
]

RECOMMENDATIONS = [
    ("Rate-limit by user ID, not IP",          "IPs are trivially spoofed via proxy headers"),
    ("Strip untrusted X-Forwarded-For",         "Trust only from known reverse-proxy CIDR ranges"),
    ("Use sliding-window / token-bucket",       "Fixed windows lose to timing attacks"),
    ("Distribute counters via Redis",           "In-process counters race under concurrent load"),
    ("Deploy adaptive WAF rules",              "Cloudflare / ModSecurity with behavioural scoring"),
    ("CAPTCHA after 3-5 violations",           "Step-up auth breaks automated bypass loops"),
    ("Alert on 429 spike patterns",            "Spikes signal active probing — notify SOC"),
    ("TLS / JA3 fingerprinting",               "Identifies tool traffic vs real browsers"),
    ("Per-key API quotas",                     "API keys with hard quotas prevent bulk abuse"),
    ("Device fingerprinting on browser flows", "Canvas/WebGL hash ties requests to device"),
]


# HELPERS

def rand_ip(private=False):
    if private:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    while True:
        a = random.randint(1, 223)
        if a not in (10, 127, 169, 172, 192):
            return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_ua():
    if FUA_OK:
        try: return _fua.random
        except: pass
    return random.choice(FALLBACK_UAS)

def rand_token(n=32):
    return hashlib.sha256(os.urandom(32)).hexdigest()[:n]

def count_statuses(lst):
    out = {}
    for s in lst:
        out[str(s)] = out.get(str(s), 0) + 1
    return out

def risk_level(results):
    if not results: return "UNKNOWN"
    v = sum(1 for r in results if r.get("vulnerable")) / len(results)
    if v == 0:  return "LOW"
    if v < 0.4: return "MEDIUM"
    if v < 0.7: return "HIGH"
    return "CRITICAL"

def risk_style(level):
    return {"LOW":C_SAFE,"MEDIUM":C_WARN,"HIGH":C_ACC,"CRITICAL":C_VULN}.get(level,C_WHITE)

def draw_bar(pct, width=22):
    filled = int(pct / 100 * width)
    col = C_ACC if pct > 65 else C_WARN if pct > 40 else C_DIM
    return f"[{col}]{'█'*filled}{'░'*(width-filled)}[/] [{col}]{pct:.0f}%[/]"

def status_badge(code):
    if code == 0:   return f"[{C_MUTED}]ERR[/]"
    if code < 300:  return f"[{C_SAFE}]{code}[/]"
    if code == 429: return f"[{C_ACC}]{code}[/]"
    if code < 500:  return f"[{C_WARN}]{code}[/]"
    return f"[{C_ACC}]{code}[/]"

# ── Advanced Features ─────────────────────────────────────────────────────────

def parse_ratelimit_headers(response):
    """Extract rate-limit info from response headers."""
    headers = response.headers if response else {}
    info = {
        "limit": None,
        "remaining": None,
        "reset": None,
        "retry_after": None,
        "raw_headers": {}
    }
    
    # Common patterns
    limit_keys = ["X-RateLimit-Limit", "X-Rate-Limit-Limit", "RateLimit-Limit"]
    remaining_keys = ["X-RateLimit-Remaining", "X-Rate-Limit-Remaining", "RateLimit-Remaining"]
    reset_keys = ["X-RateLimit-Reset", "X-Rate-Limit-Reset", "RateLimit-Reset"]
    retry_keys = ["Retry-After", "X-Retry-After"]
    
    for key in limit_keys:
        if key in headers:
            try: info["limit"] = int(headers[key]); break
            except: pass
    
    for key in remaining_keys:
        if key in headers:
            try: info["remaining"] = int(headers[key]); break
            except: pass
    
    for key in reset_keys:
        if key in headers:
            try: info["reset"] = int(headers[key]); break
            except: pass
    
    for key in retry_keys:
        if key in headers:
            info["retry_after"] = headers[key]; break
    
    # Store all rate-limit related headers
    for key, val in headers.items():
        if "rate" in key.lower() or "limit" in key.lower():
            info["raw_headers"][key] = val
    
    return info

def generate_html_report(results, tester, baseline=None):
    """Generate a comprehensive HTML report."""
    os.makedirs("results", exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"results/scan_{ts}.html"
    
    risk = risk_level(results)
    vuln = [r for r in results if r["vulnerable"]]
    safe = [r for r in results if not r["vulnerable"]]
    dur = str(datetime.now() - tester.start).split(".")[0]
    
    vh = "🔴" if risk == "CRITICAL" else "🟠" if risk == "HIGH" else "🟡" if risk == "MEDIUM" else "🟢"
    
    rows = ""
    for r in results:
        dist_html = " ".join(
            f'<span class="badge" style="background:{("#00cc00" if int(k) < 400 else "#ff0000")}">{k}×{v}</span>'
            for k, v in sorted(r["status_dist"].items())
        ) or "<em>—</em>"
        verdict = f'<span class="verdict vuln">VULNERABLE</span>' if r["vulnerable"] else '<span class="verdict safe">SECURE</span>'
        rows += f"""
        <tr>
            <td>{r['technique']}</td>
            <td><div class="bar"><div class="fill" style="width:{r['success_rate']}%"></div></div>{r['success_rate']:.1f}%</td>
            <td>{r['requests']}</td>
            <td>{dist_html}</td>
            <td>{r.get('notes', '')}</td>
            <td>{verdict}</td>
        </tr>
        """
    
    baseline_html = ""
    if baseline:
        baseline_html = f"""
        <h2>📊 Baseline Measurement</h2>
        <table class="results">
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Requests Sent</td><td>{baseline.get('requests', 'N/A')}</td></tr>
            <tr><td>Successful (2xx/3xx)</td><td>{baseline.get('successful', 'N/A')}</td></tr>
            <tr><td>Blocked (429)</td><td>{baseline.get('blocked', 'N/A')}</td></tr>
            <tr><td>Errors (5xx)</td><td>{baseline.get('errors', 'N/A')}</td></tr>
            <tr><td>Success Rate</td><td>{baseline.get('success_rate', 'N/A')}%</td></tr>
            <tr><td>Estimated Limit</td><td>{baseline.get('estimated_limit', 'N/A')} req/s</td></tr>
        </table>
        """
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Rate Limit Bypass Test Report</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #0d1117; color: #c9d1d9; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            h1 {{ color: #58a6ff; margin-top: 0; }}
            h2 {{ color: #79c0ff; margin-top: 30px; }}
            .header {{ background: #161b22; padding: 20px; border-radius: 6px; margin-bottom: 20px; }}
            .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
            .stat {{ background: #161b22; padding: 15px; border-radius: 6px; }}
            .stat-label {{ color: #8b949e; font-size: 12px; }}
            .stat-value {{ color: #79c0ff; font-size: 24px; font-weight: bold; }}
            table {{ width: 100%; border-collapse: collapse; background: #161b22; margin: 20px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #30363d; }}
            th {{ background: #0d1117; font-weight: bold; color: #79c0ff; }}
            .bar {{ height: 20px; background: #30363d; border-radius: 3px; overflow: hidden; margin-bottom: 5px; }}
            .fill {{ height: 100%; background: linear-gradient(90deg, #238636, #79c0ff); transition: width 0.3s; }}
            .badge {{ display: inline-block; padding: 2px 6px; margin: 2px; border-radius: 3px; color: white; font-size: 11px; }}
            .verdict {{ padding: 4px 8px; border-radius: 3px; font-weight: bold; }}
            .verdict.safe {{ background: #238636; }}
            .verdict.vuln {{ background: #da3633; }}
            .recommendations {{ background: #161b22; padding: 15px; border-radius: 6px; margin: 20px 0; }}
            .recommendation {{ padding: 10px; margin: 5px 0; border-left: 3px solid #58a6ff; }}
            .risk-badge {{ font-size: 20px; margin-right: 10px; }}
            code {{ background: #0d1117; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New'; color: #79c0ff; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Rate Limit Bypass Test Report</h1>
            
            <div class="header">
                <p><strong>Target:</strong> <code>{tester.url}</code></p>
                <p><strong>Host:</strong> {tester.host} | <strong>Scheme:</strong> {tester.scheme.upper()}</p>
                <p><strong>Started:</strong> {tester.start} | <strong>Duration:</strong> {dur}</p>
                <p><strong>Tor:</strong> {"✓ Active" if tester.tor and tester.tor.available else "✗ Disabled"}</p>
            </div>
            
            <div class="summary">
                <div class="stat">
                    <div class="stat-label">RISK LEVEL</div>
                    <div class="stat-value"><span class="risk-badge">{vh}</span> {risk}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">VULNERABLE</div>
                    <div class="stat-value" style="color: #da3633;">{len(vuln)}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">SECURE</div>
                    <div class="stat-value" style="color: #238636;">{len(safe)}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">TOTAL REQUESTS</div>
                    <div class="stat-value">{tester._total}</div>
                </div>
                <div class="stat">
                    <div class="stat-label">SUCCESS RATE</div>
                    <div class="stat-value">{round(tester._ok / tester._total * 100, 1) if tester._total else 0:.1f}%</div>
                </div>
            </div>
            
            {baseline_html}
            
            <h2>📋 Technique Results</h2>
            <table class="results">
                <tr>
                    <th>Technique</th>
                    <th>Success Rate</th>
                    <th>Requests</th>
                    <th>HTTP Codes</th>
                    <th>Notes</th>
                    <th>Verdict</th>
                </tr>
                {rows}
            </table>
            
            <h2>🛡️ Remediation Recommendations</h2>
            <div class="recommendations">
                {"".join(f'<div class="recommendation"><strong>{i}. {rec[0]}</strong><br><em>{rec[1]}</em></div>' for i, rec in enumerate(RECOMMENDATIONS, 1))}
            </div>
            
            <p style="color: #8b949e; font-size: 12px; margin-top: 40px;">
                Report generated by RateLimiter AutoPwn v{VERSION} on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
                Authorized security testing only. Unauthorized access is illegal.
            </p>
        </div>
    </body>
    </html>
    """
    
    with open(path, "w") as f:
        f.write(html)
    return path

def load_config(config_path):
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        con.print(f"[{C_ACC}]Error loading config: {e}[/]")
        return None

def save_config_template():
    """Create a sample config file template."""
    template = {
        "url": "https://api.example.com/endpoint",
        "timeout": 5,
        "requests_per_technique": 20,
        "use_tor": False,
        "proxy": "",
        "techniques": ["1", "2", "3", "4", "5", "6", "7"],
        "verbose": False,
        "run_baseline": True,
        "save_requests_log": True
    }
    path = "config_template.json"
    with open(path, "w") as f:
        json.dump(template, f, indent=2)
    return path

# ─────────────────────────────────────────────────────────────────────────────
# TOR MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class TorManager:
    def __init__(self, password=""):
        self.available = False
        self.password  = password
        if not TOR_OK: return
        try:
            s = socket.create_connection(("127.0.0.1", 9050), timeout=2)
            s.close()
            self.available = True
        except OSError:
            pass

    def new_circuit(self):
        if not self.available: return
        try:
            with Controller.from_port(port=9051) as c:
                c.authenticate(password=self.password)
                c.signal(Signal.NEWNYM)
            time.sleep(1)
        except: pass

    def session(self):
        s = requests.Session()
        if self.available:
            s.proxies = {"http":"socks5h://127.0.0.1:9050","https":"socks5h://127.0.0.1:9050"}
        return s

    @property
    def exit_ip(self):
        try: return self.session().get("https://api.ipify.org", timeout=8).text.strip()
        except: return "unknown"

# ─────────────────────────────────────────────────────────────────────────────
# CORE TESTER
# ─────────────────────────────────────────────────────────────────────────────

class Tester:
    def __init__(self, url, timeout=5, n=20, use_tor=False, proxy="", verbose=False, save_log=False):
        self.url     = url
        self.timeout = timeout
        self.n       = n
        self.verbose = verbose
        self.proxy   = proxy
        self.save_log = save_log
        self.lock    = threading.Lock()
        self._total  = 0
        self._ok     = 0
        self.results = []
        self.start   = datetime.now()
        self.tor     = TorManager() if use_tor else None
        parsed       = urlparse(url)
        self.host    = parsed.netloc
        self.scheme  = parsed.scheme
        self.request_log = []
        self.rate_limit_info = None

    def _session(self):
        s = (self.tor.session() if self.tor and self.tor.available
             else requests.Session())
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        return s

    def _send(self, headers=None, method="GET", data=None, cookies=None):
        try:
            r = self._session().request(
                method.upper(), self.url,
                headers=headers or {}, json=data, cookies=cookies,
                timeout=self.timeout, allow_redirects=True, verify=True,
            )
            with self.lock:
                self._total += 1
                if r.status_code < 400: self._ok += 1
                if r.status_code != 429 and not self.rate_limit_info:
                    self.rate_limit_info = parse_ratelimit_headers(r)
            
            if self.save_log:
                self.request_log.append({
                    "timestamp": datetime.now().isoformat(),
                    "method": method.upper(),
                    "status": r.status_code,
                    "headers": dict(r.headers),
                })
            
            return r
        except Exception as e:
            with self.lock: self._total += 1
            if self.save_log:
                self.request_log.append({
                    "timestamp": datetime.now().isoformat(),
                    "method": method.upper(),
                    "error": str(e),
                })
            return None

    def run_baseline(self, prog, task):
        """Measure normal endpoint behavior without evasion."""
        ok, st, blocked = 0, [], 0
        for i in range(self.n):
            r = self._send()
            sc = r.status_code if r else 0
            st.append(sc)
            if sc and sc < 400: ok += 1
            if sc == 429: blocked += 1
            prog.advance(task)
            time.sleep(0.1)
        
        errors = sum(1 for s in st if s >= 500)
        return {
            "requests": self.n,
            "successful": ok,
            "blocked": blocked,
            "errors": errors,
            "success_rate": round((ok / self.n * 100) if self.n else 0, 1),
            "estimated_limit": round(self.n / (self.n * 0.1), 1) if self.n > 0 else 0,
            "status_codes": count_statuses(st),
        }

    def _result(self, name, ok, total, statuses, notes="", threshold=65):
        rate = round((ok / total * 100) if total else 0, 1)
        return {
            "technique":    name,
            "success_rate": rate,
            "vulnerable":   rate > threshold,
            "requests":     total,
            "status_dist":  count_statuses(statuses),
            "notes":        notes,
        }

    # ── 9 techniques ─────────────────────────────────────────────────────────

    def t_ip_spoofing(self, prog, task):
        ok, st = 0, []
        for _ in range(self.n):
            ip = rand_ip(private=random.random() < 0.15)
            hdrs = {h: ip for h in IP_HEADERS}
            hdrs["X-Forwarded-For"] = f"{rand_ip()}, {rand_ip()}, {ip}"
            hdrs["Forwarded"] = f"for={ip};proto={self.scheme};host={self.host}"
            r = self._send(headers=hdrs); sc = r.status_code if r else 0
            st.append(sc)
            if sc and sc < 400: ok += 1
            prog.advance(task); time.sleep(random.uniform(0.04, 0.15))
        return self._result("IP Header Spoofing", ok, self.n, st,
            "Injected IPs across 10 headers + RFC 7239 Forwarded chain", 65)

    def t_timing(self, prog, task):
        ok, st, base = 0, [], 0.8
        for _ in range(self.n):
            r = self._send(); sc = r.status_code if r else 0
            st.append(sc)
            if sc and sc < 400: ok += 1
            time.sleep(random.uniform(0, base)); base = min(base * 1.08, 4.0)
            prog.advance(task)
        return self._result("Jittered Timing", ok, self.n, st,
            "Exponential jitter stays below fixed-window detection", 70)

    def t_ua_rotation(self, prog, task):
        ok, st = 0, []
        for _ in range(self.n):
            ua = rand_ua()
            plat = "Win32" if "Windows" in ua else "MacIntel" if "Mac" in ua else "Linux x86_64"
            hdrs = {
                "User-Agent": ua,
                "Accept-Language": random.choice(["en-US,en;q=0.9","en-GB,en;q=0.8","fr-FR,fr;q=0.7"]),
                "Sec-Ch-Ua-Platform": f'"{plat}"',
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
            }
            r = self._send(headers=hdrs); sc = r.status_code if r else 0
            st.append(sc)
            if sc and sc < 400: ok += 1
            prog.advance(task); time.sleep(0.08)
        return self._result("UA Rotation", ok, self.n, st,
            "Paired UAs with matching platform hints + content negotiation", 60)

    def t_session_rotation(self, prog, task):
        ok, st = 0, []
        for _ in range(self.n):
            sid = rand_token(32)
            hdrs = {
                "Authorization": f"Bearer {rand_token(32)}",
                "X-Session-Token": sid,
                "X-Request-ID": rand_token(16),
                "X-Correlation-ID": rand_token(16),
            }
            cookies = {"sessionid": sid, "PHPSESSID": rand_token(16), "_csrf_token": rand_token(24)}
            r = self._send(headers=hdrs, cookies=cookies); sc = r.status_code if r else 0
            st.append(sc)
            if sc and sc < 400: ok += 1
            prog.advance(task); time.sleep(0.08)
        return self._result("Session Rotation", ok, self.n, st,
            "Fresh SHA-256 session / CSRF / Bearer tokens per request", 65)

    def t_concurrent_burst(self, prog, task):
        threads = min(self.n * 2, 50); ok_ref = [0]
        def _req():
            r = self._send()
            if r and r.status_code < 400:
                with self.lock: ok_ref[0] += 1
            prog.advance(task)
        with ThreadPoolExecutor(max_workers=threads) as ex:
            list(as_completed([ex.submit(_req) for _ in range(threads)]))
        return self._result("Concurrent Burst", ok_ref[0], threads, [],
            f"Race condition — {threads} parallel threads fired simultaneously", 50)

    def t_header_combo(self, prog, task):
        ok, st = 0, []
        for _ in range(self.n):
            ip = rand_ip()
            hdrs = {
                "X-Forwarded-For": f"{rand_ip()}, {rand_ip()}, {ip}",
                "X-Real-IP": ip, "CF-Connecting-IP": ip,
                "User-Agent": rand_ua(),
                "Referer": random.choice(REFERERS),
                "Origin": f"{self.scheme}://{self.host}",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": random.choice(["en-US,en;q=0.9","de-DE,de;q=0.8"]),
                "Accept-Encoding": "gzip, deflate, br",
                "Cache-Control": "no-cache", "Pragma": "no-cache",
                "X-Request-ID": rand_token(16), "DNT": "1",
            }
            r = self._send(headers=hdrs); sc = r.status_code if r else 0
            st.append(sc)
            if sc and sc < 400: ok += 1
            prog.advance(task); time.sleep(0.06)
        return self._result("Full Header Combo", ok, self.n, st,
            "All evasion layers simultaneously — most realistic fingerprint", 60)

    def t_adaptive(self, prog, task):
        ok, st, delay, hits = 0, [], 0.5, 0
        for _ in range(self.n):
            r = self._send(); sc = r.status_code if r else 0
            st.append(sc)
            if sc in (429, 503): hits += 1; delay = min(delay * 2.0, 10.0)
            elif sc and sc < 400: ok += 1; delay = max(delay * 0.85, 0.05)
            else: delay = min(delay * 1.3, 10.0)
            time.sleep(delay); prog.advance(task)
        est = round(1 / max(delay, 0.01), 1)
        return self._result("Adaptive Threshold Probe", ok, self.n, st,
            f"Discovered ~{est} req/s threshold | {hits} rate-limit hits | final delay {round(delay,2)}s", 65)

    def t_tor_routing(self, prog, task):
        if not self.tor or not self.tor.available:
            for _ in range(self.n): prog.advance(task)
            return self._result("Tor Circuit Routing", 0, self.n, [],
                "Tor not running — start with: sudo systemctl start tor", 70)
        ok, st = 0, []
        for i in range(self.n):
            if i % 5 == 0: self.tor.new_circuit()
            r = self._send(headers={"User-Agent": rand_ua()}); sc = r.status_code if r else 0
            st.append(sc)
            if sc and sc < 400: ok += 1
            prog.advance(task); time.sleep(0.3)
        return self._result("Tor Circuit Routing", ok, self.n, st,
            "Traffic via Tor SOCKS5 — circuit rotated every 5 requests", 70)

    def t_fragmentation(self, prog, task):
        ok, st = 0, []
        cts = ["application/json","application/x-www-form-urlencoded","text/plain","multipart/form-data"]
        for _ in range(self.n):
            size = random.randint(0, 512)
            hdrs = {"Content-Type": random.choice(cts), "User-Agent": rand_ua(), "X-Forwarded-For": rand_ip()}
            r = self._send(headers=hdrs, method="POST", data={"d": "A" * size}); sc = r.status_code if r else 0
            st.append(sc)
            if sc and sc < 400: ok += 1
            prog.advance(task); time.sleep(0.08)
        return self._result("Request Fragmentation", ok, self.n, st,
            "Varied Content-Type + payload sizes to confuse body-aware limiters", 60)

    DISPATCH = {
        "1": t_ip_spoofing, "2": t_timing,    "3": t_ua_rotation,
        "4": t_session_rotation,               "5": t_concurrent_burst,
        "6": t_header_combo,"7": t_adaptive,  "8": t_tor_routing,
        "9": t_fragmentation,
    }

    def run(self, keys, run_baseline=False):
        self.results = []
        baseline = None
        
        with Progress(
            SpinnerColumn(spinner_name="dots", style=C_PRI),
            TextColumn("[bold green]{task.description}[/]", justify="right"),
            BarColumn(bar_width=26, style=C_MUTED, complete_style=C_PRI, finished_style=C_DIM),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=con, transient=False,
        ) as prog:
            # Run baseline if requested
            if run_baseline:
                task = prog.add_task("Baseline Measurement   ", total=self.n)
                baseline = self.run_baseline(prog, task)
                con.print(f"  [{C_DIM}]Baseline:[/] {baseline['successful']}/{self.n} ok, {baseline['blocked']} blocked, ~{baseline['estimated_limit']} req/s\n")
            
            # Run techniques
            for k in keys:
                fn = self.DISPATCH.get(k)
                if not fn: continue
                name = next((t[1] for t in TECHNIQUES if t[0] == k), k)
                n_reqs = self.n * 2 if k == "5" else self.n
                task = prog.add_task(f"{name:<30}", total=n_reqs)
                self.results.append(fn(self, prog, task))
        
        return self.results, baseline

    def save(self, baseline=None, html=True):
        os.makedirs("results", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"results/scan_{ts}.json"
        with open(path, "w") as f:
            json.dump({
                "meta": {
                    "tool": f"RateLimiter AutoPwn v{VERSION}",
                    "author": "Robert Mwatua",
                    "target": self.url,
                    "started": self.start.isoformat(),
                    "finished": datetime.now().isoformat(),
                    "requests_sent": self._total,
                    "requests_ok":   self._ok,
                    "tor_used": bool(self.tor and self.tor.available),
                    "rate_limit_headers": self.rate_limit_info or {},
                },
                "baseline": baseline,
                "results": self.results,
                "summary": {
                    "risk": risk_level(self.results),
                    "vulnerable": [r["technique"] for r in self.results if r["vulnerable"]],
                    "secure":     [r["technique"] for r in self.results if not r["vulnerable"]],
                    "recommendations": [{"fix": r[0], "reason": r[1]} for r in RECOMMENDATIONS],
                }
            }, f, indent=2)
        
        # Save HTML report
        html_path = None
        if html:
            html_path = generate_html_report(self.results, self, baseline)
        
        # Save request log if enabled
        log_path = None
        if self.save_log and self.request_log:
            log_path = f"results/requests_{ts}.jsonl"
            with open(log_path, "w") as f:
                for entry in self.request_log:
                    f.write(json.dumps(entry) + "\n")
        
        return {"json": path, "html": html_path, "log": log_path}


# ─────────────────────────────────────────────────────────────────────────────
# SCREENS
# ─────────────────────────────────────────────────────────────────────────────

def clear():
    os.system("clear" if os.name != "nt" else "cls")

def banner():
    clear()
    art = r"""
 ██████╗  █████╗ ████████╗███████╗██╗     ██╗███╗   ███╗██╗████████╗
 ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║     ██║████╗ ████║██║╚══██╔══╝
 ██████╔╝███████║   ██║   █████╗  ██║     ██║██╔████╔██║██║   ██║
 ██╔══██╗██╔══██║   ██║   ██╔══╝  ██║     ██║██║╚██╔╝██║██║   ██║
 ██║  ██║██║  ██║   ██║   ███████╗███████╗██║██║ ╚═╝ ██║██║   ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝╚═╝     ╚═╝╚═╝   ╚═╝"""
    con.print(f"[{C_PRI}]{art}[/]")
    con.print(f"[{C_MUTED}]{'─'*70}[/]")
    con.print(
        f"  [{C_DIM}]AUTOPWN[/] [{C_MUTED}]v{VERSION}[/]"
        f"  [{C_MUTED}]│[/]  [{C_MUTED}]by Robert Mwatua[/]"
        f"  [{C_MUTED}]│[/]  [{C_WARN}]authorised testing only[/]"
    )
    con.print(f"[{C_MUTED}]{'─'*70}[/]\n")

def screen_target():
    con.print(f"[{C_PRI}]TARGET SETUP[/]\n")
    
    # Option to load config
    use_config = Confirm.ask(
        f"  [{C_DIM}]>[/] [{C_WHITE}]Load from config file?[/] [{C_MUTED}](yes/no)[/]", default=False)
    
    if use_config:
        config_file = Prompt.ask(
            f"  [{C_DIM}]>[/] [{C_WHITE}]Config file path[/] [{C_MUTED}](JSON)[/]", default="config.json")
        config = load_config(config_file)
        if config:
            return (config.get("url", ""), config.get("timeout", 5), 
                   config.get("requests_per_technique", 20), config.get("use_tor", False),
                   config.get("proxy", ""), config.get("run_baseline", True),
                   config.get("save_requests_log", False), config.get("techniques", []))
    
    while True:
        url = Prompt.ask(f"  [{C_DIM}]>[/] [{C_WHITE}]Target URL[/]")
        if url.startswith(("http://","https://")): break
        con.print(f"  [{C_ACC}]✗[/] Must start with http:// or https://")

    parsed = urlparse(url)
    con.print(f"\n  [{C_MUTED}]Host   :[/] [{C_INFO}]{parsed.netloc}[/]")
    con.print(f"  [{C_MUTED}]Scheme :[/] [{C_INFO}]{parsed.scheme.upper()}[/]")
    con.print(f"  [{C_MUTED}]Path   :[/] [{C_INFO}]{parsed.path or '/'}[/]\n")

    timeout = int(Prompt.ask(
        f"  [{C_DIM}]>[/] [{C_WHITE}]Timeout per request[/] [{C_MUTED}](seconds)[/]", default="5"))
    n = int(Prompt.ask(
        f"  [{C_DIM}]>[/] [{C_WHITE}]Requests per technique[/] [{C_MUTED}](10=fast  20=balanced  40=deep)[/]", default="20"))

    con.print(f"\n  [{C_PRI}]ANONYMITY[/]")
    use_tor = Confirm.ask(
        f"  [{C_DIM}]>[/] [{C_WHITE}]Route through Tor?[/] [{C_MUTED}](sudo systemctl start tor)[/]", default=False)
    proxy = ""
    if Confirm.ask(f"  [{C_DIM}]>[/] [{C_WHITE}]Use upstream proxy?[/] [{C_MUTED}](Burp / mitmproxy)[/]", default=False):
        proxy = Prompt.ask(f"  [{C_DIM}]>[/] [{C_WHITE}]Proxy URL[/]", default="http://127.0.0.1:8080")

    con.print(f"\n  [{C_PRI}]ADVANCED OPTIONS[/]")
    run_baseline = Confirm.ask(
        f"  [{C_DIM}]>[/] [{C_WHITE}]Run baseline measurement first?[/] [{C_MUTED}](measure normal behavior)[/]", default=True)
    save_log = Confirm.ask(
        f"  [{C_DIM}]>[/] [{C_WHITE}]Save request log?[/] [{C_MUTED}](for compliance/audit)[/]", default=False)

    return url, timeout, n, use_tor, proxy, run_baseline, save_log, None

def screen_consent(url):
    con.print()
    con.print(Panel(
        f"  [{C_WARN}]You are about to send automated requests to:[/]\n\n"
        f"  [{C_WHITE}]{url}[/]\n\n"
        f"  [{C_MUTED}]Unauthorised use is illegal under the Computer Misuse Act,\n"
        f"  CFAA, and equivalent laws worldwide.[/]",
        border_style=C_WARN, title=f"[{C_WARN}]  LEGAL NOTICE[/]", padding=(0, 2)
    ))
    if not Confirm.ask(f"\n  [{C_DIM}]>[/] [{C_WHITE}]I have explicit written permission to test this target[/]"):
        con.print(f"\n  [{C_ACC}]Aborted.[/]"); sys.exit(0)

def screen_techniques():
    con.print(f"\n[{C_PRI}]SELECT TECHNIQUES[/]\n")
    t = Table(show_header=True, box=box.SIMPLE, padding=(0,1), header_style=f"bold {C_MUTED}")
    t.add_column("#",           style=C_PRI,   width=4)
    t.add_column("Technique",   style=C_WHITE,  min_width=26)
    t.add_column("OPSEC",       width=10)
    t.add_column("What it does", style=C_MUTED)
    opsec_col = {"Maximum":C_ACC,"High":C_WARN,"Medium":C_DIM,"Low":C_MUTED}
    for num, name, opsec, desc in TECHNIQUES:
        t.add_row(num, name, f"[{opsec_col[opsec]}]{opsec}[/]", desc)
    con.print(t)
    con.print(f"\n  [{C_MUTED}]Comma-separated numbers  or  A for all[/]")
    raw = Prompt.ask(f"  [{C_DIM}]>[/] [{C_WHITE}]Techniques[/]", default="A")
    valid = [t[0] for t in TECHNIQUES]
    return valid if raw.strip().upper() == "A" else [x.strip() for x in raw.split(",") if x.strip() in valid]

def screen_results(results, tester, baseline=None):
    clear(); banner()
    risk   = risk_level(results)
    rs     = risk_style(risk)
    vuln   = [r for r in results if r["vulnerable"]]
    safe   = [r for r in results if not r["vulnerable"]]
    dur    = str(datetime.now() - tester.start).split(".")[0]

    # Summary strip
    sg = Table.grid(padding=(0,5))
    for _ in range(5): sg.add_column(justify="center")
    sg.add_row(
        f"[{C_MUTED}]TECHNIQUES\n[/][{C_WHITE}]{len(results)}[/]",
        f"[{C_MUTED}]VULNERABLE\n[/][{C_ACC if vuln else C_SAFE}]{len(vuln)}[/]",
        f"[{C_MUTED}]SECURE\n[/][{C_SAFE}]{len(safe)}[/]",
        f"[{C_MUTED}]REQUESTS\n[/][{C_WHITE}]{tester._total}[/]",
        f"[{C_MUTED}]DURATION\n[/][{C_WHITE}]{dur}[/]",
    )
    con.print(Panel(sg, border_style=rs, title=f"[{rs}]  RISK: {risk}[/]", padding=(0,2)))

    # Baseline info if available
    if baseline:
        con.print(f"\n[{C_PRI}]BASELINE[/]  [{C_MUTED}]{baseline['successful']}/{baseline['requests']} ok  │  {baseline['blocked']} blocked  │  ~{baseline['estimated_limit']} req/s[/]\n")

    # Per-technique table
    con.print(f"\n[{C_PRI}]RESULTS[/]\n")
    rt = Table(show_header=True, box=box.SIMPLE_HEAVY, padding=(0,1), header_style=f"bold {C_MUTED}")
    rt.add_column("Technique",    style=C_WHITE,  min_width=26)
    rt.add_column("Success rate", min_width=30)
    rt.add_column("Reqs",         justify="right", style=C_MUTED, width=6)
    rt.add_column("HTTP codes",   style=C_MUTED,   min_width=18)
    rt.add_column("Verdict",      justify="center", width=12)
    for r in results:
        dist = "  ".join(
            f"{status_badge(int(k))}[{C_MUTED}]×{v}[/]"
            for k, v in sorted(r["status_dist"].items())
        ) or f"[{C_MUTED}]—[/]"
        verdict = f"[{C_VULN}]VULNERABLE[/]" if r["vulnerable"] else f"[{C_SAFE}]SECURE[/]"
        rt.add_row(r["technique"], draw_bar(r["success_rate"]), str(r["requests"]), dist, verdict)
    con.print(rt)

    # Findings notes
    notes_exist = any(r.get("notes") for r in results)
    if notes_exist:
        con.print(f"\n[{C_PRI}]FINDINGS[/]\n")
        for r in results:
            if r.get("notes"):
                icon = f"[{C_ACC}]⚠[/]" if r["vulnerable"] else f"[{C_MUTED}]·[/]"
                con.print(f"  {icon}  [{C_MUTED}]{r['technique']}:[/]  {r['notes']}")

    # Rate-limit headers info
    if tester.rate_limit_info and any(tester.rate_limit_info.get(k) for k in ["limit", "remaining", "reset"]):
        con.print(f"\n[{C_PRI}]RATE-LIMIT HEADERS DETECTED[/]\n")
        if tester.rate_limit_info.get("limit"):
            con.print(f"  [{C_DIM}]Limit:[/]     {tester.rate_limit_info['limit']} requests")
        if tester.rate_limit_info.get("remaining"):
            con.print(f"  [{C_DIM}]Remaining:[/] {tester.rate_limit_info['remaining']} requests")
        if tester.rate_limit_info.get("reset"):
            con.print(f"  [{C_DIM}]Reset:[/]     {tester.rate_limit_info['reset']} (epoch)")
        if tester.rate_limit_info.get("retry_after"):
            con.print(f"  [{C_DIM}]Retry-After:[/] {tester.rate_limit_info['retry_after']}")

    # Remediation
    if vuln:
        con.print(f"\n[{C_PRI}]REMEDIATION[/]\n")
        rct = Table(show_header=False, box=None, padding=(0,1))
        rct.add_column("#",   style=C_ACC,   width=4)
        rct.add_column("Fix", style=C_WHITE, min_width=34)
        rct.add_column("Reason", style=C_MUTED)
        for i, (fix, why) in enumerate(RECOMMENDATIONS, 1):
            rct.add_row(str(i), fix, why)
        con.print(rct)

    # Next actions
    con.print(f"\n[{C_PRI}]NEXT[/]\n")
    na = Table(show_header=False, box=None, padding=(0,1))
    na.add_column(style=C_DIM,   width=4)
    na.add_column(style=C_WHITE, min_width=28)
    na.add_column(style=C_MUTED)
    na.add_row("S", "Save reports (JSON + HTML)",  "results/scan_<ts>.{json,html}")
    na.add_row("R", "Run again",                   "start a new scan")
    na.add_row("Q", "Quit",                        "")
    con.print(na)
    con.print()

    action = Prompt.ask(
        f"  [{C_DIM}]>[/] [{C_WHITE}]Action[/]",
        choices=["S","R","Q","s","r","q"], default="S"
    ).upper()

    if action == "S":
        paths = tester.save(baseline=baseline, html=True)
        con.print(f"\n  [{C_PRI}]✓[/] Saved reports:")
        con.print(f"    JSON: [{C_INFO}]{paths['json']}[/]")
        if paths['html']:
            con.print(f"    HTML: [{C_INFO}]{paths['html']}[/]")
        if paths['log']:
            con.print(f"    Log:  [{C_INFO}]{paths['log']}[/]")
    elif action == "R":
        main(); return

    con.print(f"\n  [{C_MUTED}]Session complete. Stay legal.[/]\n")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    banner()
    result = screen_target()
    
    # Unpack based on whether config was used or manual input
    if len(result) == 8:
        url, timeout, n, use_tor, proxy, run_baseline, save_log, preselected_techs = result
    else:
        url, timeout, n, use_tor, proxy = result
        run_baseline, save_log, preselected_techs = True, False, None
    
    screen_consent(url)
    
    # Use preselected techniques from config or ask user
    if preselected_techs:
        keys = preselected_techs
    else:
        keys = screen_techniques()

    if not keys:
        con.print(f"  [{C_ACC}]No valid techniques selected.[/]"); sys.exit(0)

    tester = Tester(url, timeout=timeout, n=n, use_tor=use_tor, proxy=proxy, save_log=save_log)

    con.print(f"\n[{C_PRI}]RUNNING[/]  [{C_MUTED}]{len(keys)} technique(s)  │  {n} req each  │  timeout {timeout}s[/]\n")

    if tester.tor and tester.tor.available:
        con.print(f"  [{C_DIM}][Tor][/] [{C_PRI}]Active[/]  [{C_MUTED}]exit IP:[/] [{C_INFO}]{tester.tor.exit_ip}[/]\n")
    elif use_tor:
        con.print(f"  [{C_DIM}][Tor][/] [{C_ACC}]Not reachable[/]  [{C_MUTED}]sudo systemctl start tor[/]\n")

    results, baseline = tester.run(keys, run_baseline=run_baseline)
    screen_results(results, tester, baseline)


if __name__ == "__main__":
    try:
        # CLI argument support
        if len(sys.argv) > 1:
            if sys.argv[1] == "--template":
                # Generate config template
                path = save_config_template()
                print(f"✓ Config template saved to {path}")
                print(f"  Edit it and run: python3 bypass_tester.py --config {path}")
                sys.exit(0)
            elif sys.argv[1] == "--config" and len(sys.argv) > 2:
                # Load config and run non-interactively
                config_path = sys.argv[2]
                config = load_config(config_path)
                if not config:
                    sys.exit(1)
                
                banner()
                screen_consent(config.get("url", ""))
                
                url = config.get("url", "")
                timeout = config.get("timeout", 5)
                n = config.get("requests_per_technique", 20)
                use_tor = config.get("use_tor", False)
                proxy = config.get("proxy", "")
                run_baseline = config.get("run_baseline", True)
                save_log = config.get("save_requests_log", False)
                techniques = config.get("techniques", [])
                
                tester = Tester(url, timeout=timeout, n=n, use_tor=use_tor, proxy=proxy, save_log=save_log)
                
                con.print(f"\n[{C_PRI}]RUNNING[/]  [{C_MUTED}]{len(techniques)} technique(s)  │  {n} req each  │  timeout {timeout}s[/]\n")
                
                if tester.tor and tester.tor.available:
                    con.print(f"  [{C_DIM}][Tor][/] [{C_PRI}]Active[/]  [{C_MUTED}]exit IP:[/] [{C_INFO}]{tester.tor.exit_ip}[/]\n")
                elif use_tor:
                    con.print(f"  [{C_DIM}][Tor][/] [{C_ACC}]Not reachable[/]  [{C_MUTED}]sudo systemctl start tor[/]\n")
                
                results, baseline = tester.run(techniques, run_baseline=run_baseline)
                screen_results(results, tester, baseline)
                sys.exit(0)
        
        # Interactive mode
        main()
    except KeyboardInterrupt:
        con.print(f"\n\n  [{C_WARN}]Interrupted.[/]  [{C_MUTED}]Partial results not saved.[/]\n")
        sys.exit(0)