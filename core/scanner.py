#!/usr/bin/env python3
import argparse
import os
import re
import shutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        RESET = RESET_ALL = ""

    Fore = Style = _NoColor()

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, **kwargs):
        return iterable

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
from core.payload_manager import PayloadManager
from core.report_generator import ReportGenerator
from core.request_handler import RequestHandler
from core.utils import Utils


@dataclass
class PhaseSpec:
    id: int
    name: str
    key: str
    method: str
    detect: str
    severity: str
    param: str = "q"
    seed_paths: tuple = ("/",)
    payload_as_path: bool = False


class AuroseScanner:
    def __init__(self, max_payloads=40, threads=8, hidden_limit=120):
        self.target = ""
        self.max_payloads = max_payloads
        self.threads = max(1, threads)
        self.hidden_limit = max(20, hidden_limit)
        self.results = []
        self.start = None
        self.end = None
        self.utils = Utils()
        self.payloads = PayloadManager()
        self.req = RequestHandler()
        self.reporter = ReportGenerator()
        self.discovered_paths = {"/"}
        self.discovered_params = {}
        self.phase_specs = self._build_phase_specs()
        self.total_phases = len(self.phase_specs)
        self.term_width = max(76, min(120, shutil.get_terminal_size((100, 24)).columns))
        self.inner_width = self.term_width - 4
        self.use_color = bool(getattr(sys.stdout, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR")
        encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
        self.use_unicode = "utf" in encoding and os.environ.get("TERM", "") != "dumb"
        self.total_findings = 0
        self.ui = (
            {
                "h": "─",
                "v": "│",
                "tl": "┌",
                "tr": "┐",
                "bl": "└",
                "br": "┘",
                "ok": "✓",
                "warn": "▲",
                "scan": "◉",
                "bolt": "⚡",
                "dot": "•",
                "bar_full": "█",
                "bar_empty": "░",
            }
            if self.use_unicode
            else {
                "h": "-",
                "v": "|",
                "tl": "+",
                "tr": "+",
                "bl": "+",
                "br": "+",
                "ok": "OK",
                "warn": "!",
                "scan": "*",
                "bolt": ">",
                "dot": "-",
                "bar_full": "#",
                "bar_empty": ".",
            }
        )

    def _build_phase_specs(self):
        return [
            PhaseSpec(1, "Cross-Site Scripting", "xss", "GET", "reflected", "HIGH", "q", ("/search", "/", "/query")),
            PhaseSpec(2, "SQL Injection", "sqli", "GET", "sqli", "CRITICAL", "id", ("/product", "/item", "/api/item")),
            PhaseSpec(3, "Local File Inclusion", "lfi", "GET", "lfi", "HIGH", "file", ("/file", "/download", "/view")),
            PhaseSpec(4, "Server-Side Request Forgery", "ssrf", "GET", "ssrf", "HIGH", "url", ("/fetch", "/proxy", "/api/fetch")),
            PhaseSpec(5, "XML External Entity", "xxe", "POST", "xxe", "HIGH", "xml", ("/xml", "/api/xml", "/import")),
            PhaseSpec(6, "Server-Side Template Injection", "ssti", "GET", "ssti", "HIGH", "name", ("/render", "/template", "/")),
            PhaseSpec(7, "Command Injection", "cmd", "GET", "cmd", "CRITICAL", "ip", ("/ping", "/exec", "/diagnostic")),
            PhaseSpec(8, "Open Redirect", "openredirect", "GET", "open_redirect", "MEDIUM", "next", ("/redirect", "/login", "/out")),
            PhaseSpec(9, "CSRF Weakness", "csrf", "GET", "csrf", "MEDIUM", "noop", ("/", "/profile", "/account")),
            PhaseSpec(10, "IDOR", "idor", "GET", "idor", "HIGH", "id", ("/user", "/account", "/api/user")),
            PhaseSpec(11, "JWT Weakness", "jwt", "GET", "jwt", "HIGH", "token", ("/api/profile", "/api/me", "/api/user")),
            PhaseSpec(12, "NoSQL Injection", "nosqli", "GET", "nosqli", "CRITICAL", "username", ("/api/user", "/api/login", "/search")),
            PhaseSpec(13, "Header Injection", "header", "GET", "header_injection", "MEDIUM", "q", ("/", "/search")),
            PhaseSpec(14, "CORS Misconfiguration", "cors", "GET", "cors", "MEDIUM", "noop", ("/", "/api", "/graphql")),
            PhaseSpec(15, "Race Condition Indicator", "race", "POST", "race", "MEDIUM", "id", ("/api/transfer", "/checkout", "/api/pay")),
            PhaseSpec(16, "HTTP Smuggling Indicator", "smuggling", "GET", "smuggling", "HIGH", "q", ("/", "/api")),
            PhaseSpec(17, "Cache Poisoning", "cache", "GET", "cache", "MEDIUM", "q", ("/", "/index", "/home")),
            PhaseSpec(18, "Prototype Pollution", "prototype", "GET", "prototype", "HIGH", "__proto__[polluted]", ("/api", "/api/user")),
            PhaseSpec(19, "GraphQL Exposure", "graphql", "POST", "graphql", "MEDIUM", "query", ("/graphql", "/api/graphql")),
            PhaseSpec(20, "WebSocket Exposure", "websocket", "GET", "websocket", "MEDIUM", "noop", ("/", "/ws", "/socket")),
            PhaseSpec(21, "API Leakage", "api", "GET", "api", "MEDIUM", "noop", ("/api", "/swagger", "/openapi.json")),
            PhaseSpec(22, "Cloud Misconfiguration", "cloud", "GET", "cloud", "HIGH", "noop", ("/", "/.well-known", "/metadata")),
            PhaseSpec(23, "WordPress Exposure", "wordpress", "GET", "wordpress", "HIGH", "noop", ("/wp-admin", "/wp-login.php", "/"), True),
            PhaseSpec(24, "Laravel Exposure", "laravel", "GET", "laravel", "HIGH", "noop", ("/.env", "/_ignition/health-check", "/"), True),
            PhaseSpec(25, "Deserialization", "deserialize", "POST", "deserialize", "CRITICAL", "payload", ("/api/import", "/import", "/deserialize")),
            PhaseSpec(26, "DNS Leakage", "dns", "GET", "dns", "MEDIUM", "host", ("/dns", "/lookup", "/api/dns")),
            PhaseSpec(27, "SSL/TLS Weakness", "ssl", "GET", "ssl", "MEDIUM", "noop", ("/",)),
            PhaseSpec(28, "Sensitive Data Exposure", "sensitive", "GET", "sensitive", "HIGH", "noop", ("/.git/config", "/.env", "/"), True),
            PhaseSpec(29, "Default Credentials", "defaultcreds", "GET", "defaultcreds", "CRITICAL", "noop", ("/admin", "/login", "/"), True),
            PhaseSpec(30, "Information Disclosure", "infodisclose", "GET", "infodisclose", "LOW", "noop", ("/", "/error", "/debug")),
            PhaseSpec(31, "HTTP Parameter Pollution", "hpp", "GET", "hpp", "MEDIUM", "id", ("/item", "/api/item")),
            PhaseSpec(32, "LDAP Injection", "ldap", "GET", "ldap", "HIGH", "user", ("/search", "/auth", "/api/search")),
            PhaseSpec(33, "XPath Injection", "xpath", "GET", "xpath", "HIGH", "name", ("/search", "/xml/search")),
            PhaseSpec(34, "Mail Header Injection", "mailheader", "POST", "mailheader", "MEDIUM", "email", ("/contact", "/support", "/api/contact")),
            PhaseSpec(35, "CRLF Injection", "crlf", "GET", "crlf", "MEDIUM", "q", ("/", "/redirect", "/download")),
            PhaseSpec(36, "HTTP Response Splitting", "responsesplit", "GET", "responsesplit", "MEDIUM", "q", ("/", "/redirect")),
            PhaseSpec(37, "Session Fixation", "sessionfix", "GET", "sessionfix", "HIGH", "sid", ("/", "/login", "/auth")),
            PhaseSpec(38, "Clickjacking", "clickjacking", "GET", "clickjacking", "MEDIUM", "noop", ("/", "/login", "/dashboard")),
            PhaseSpec(39, "Server Misconfiguration", "servermis", "GET", "servermis", "HIGH", "noop", ("/", "/server-status", "/status"), True),
            PhaseSpec(40, "Database Exposure", "dbexpose", "GET", "dbexpose", "HIGH", "noop", ("/phpmyadmin", "/adminer.php", "/"), True),
            PhaseSpec(41, "Backup Files", "backup", "GET", "backup", "HIGH", "noop", ("/backup.zip", "/db.sql", "/"), True),
            PhaseSpec(42, "Directory Listing", "dirlist", "GET", "dirlist", "MEDIUM", "noop", ("/uploads/", "/images/", "/backup/"), True),
            PhaseSpec(43, "Debug Mode", "debug", "GET", "debug", "MEDIUM", "noop", ("/debug", "/_debugbar", "/"), True),
            PhaseSpec(44, "CSP Weakness", "csp", "GET", "csp", "MEDIUM", "noop", ("/", "/login", "/dashboard")),
            PhaseSpec(45, "Subdomain Takeover Indicator", "subdomain", "GET", "subdomain", "HIGH", "host", ("/",)),
            PhaseSpec(46, "Email Harvesting", "emailharvest", "GET", "emailharvest", "LOW", "noop", ("/", "/about", "/contact")),
            PhaseSpec(47, "Fingerprint Leakage", "fingerprint", "GET", "fingerprint", "LOW", "noop", ("/", "/api")),
            PhaseSpec(48, "WAF Detection", "waf", "GET", "waf", "LOW", "noop", ("/", "/api", "/login")),
            PhaseSpec(49, "Rate Limiting Weakness", "ratelimit", "GET", "ratelimit", "MEDIUM", "id", ("/api", "/login", "/search")),
            PhaseSpec(50, "Business Logic Indicator", "business", "POST", "business", "HIGH", "amount", ("/checkout", "/api/checkout", "/pay")),
        ]

    def _fmt(self, text, color):
        if self.use_color:
            return f"{color}{text}{Style.RESET_ALL}"
        return text

    def _clear_screen(self):
        if getattr(sys.stdout, "isatty", lambda: False)() and os.environ.get("TERM"):
            print("\033[2J\033[H", end="")

    def _box_border(self, color=Fore.CYAN, top=True):
        left = self.ui["tl"] if top else self.ui["bl"]
        right = self.ui["tr"] if top else self.ui["br"]
        print(self._fmt(f"{left}{self.ui['h'] * (self.term_width - 2)}{right}", color))

    def _box_line(self, text="", color=Fore.CYAN):
        text = text or ""
        if len(text) > self.inner_width:
            text = text[: self.inner_width - 1] + "..."
        print(self._fmt(f"{self.ui['v']} {text:<{self.inner_width}} {self.ui['v']}", color))

    def _progress_bar(self, ratio, width=26):
        ratio = max(0.0, min(1.0, ratio))
        fill = int(width * ratio)
        return f"{self.ui['bar_full'] * fill}{self.ui['bar_empty'] * (width - fill)}"

    def banner(self):
        self._clear_screen()
        title = f"{self.ui['bolt']} AUROSE SCANNER"
        subtitle = "Real-Engine Vulnerability Assessment CLI"
        chips = f"[50 phases]  [{self.threads} threads]  [payload-driven]  [linux + termux]"

        self._box_border(Fore.CYAN, top=True)
        self._box_line(title, Fore.RED)
        self._box_line(subtitle, Fore.CYAN)
        self._box_line(chips, Fore.WHITE)
        self._box_border(Fore.CYAN, top=False)

    def header(self, num, name, targets, payloads):
        print()
        ratio = num / self.total_phases
        jobs = targets * payloads
        phase_label = f"PHASE {num:02d}/{self.total_phases:02d}  {name.upper()}"
        progress = f"{self._progress_bar(ratio)} {int(ratio * 100):>3d}%"
        meta = f"{self.ui['dot']} targets={targets}  {self.ui['dot']} payloads={payloads}  {self.ui['dot']} jobs~{jobs}"
        self._box_border(Fore.MAGENTA, top=True)
        self._box_line(phase_label, Fore.MAGENTA)
        self._box_line(progress, Fore.BLUE)
        self._box_line(meta, Fore.WHITE)
        self._box_border(Fore.MAGENTA, top=False)

    def footer(self, count, elapsed=0.0, skipped=False):
        if skipped:
            status = f"{self.ui['warn']} skipped (no matching target)"
            color = Fore.YELLOW
        elif count == 0:
            status = f"{self.ui['ok']} clean"
            color = Fore.GREEN
        else:
            status = f"{self.ui['warn']} findings: {count}"
            color = Fore.YELLOW
        summary = f"{status}  {self.ui['dot']} elapsed={elapsed:.2f}s  {self.ui['dot']} total_findings={self.total_findings}"
        self._box_border(Fore.MAGENTA, top=True)
        self._box_line(summary, color)
        self._box_border(Fore.MAGENTA, top=False)

    def _target_domain(self):
        return urlparse(self.target).netloc.lower()

    def _join_url(self, path):
        if not path:
            return self.target
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(self.target.rstrip("/") + "/", path.lstrip("/"))

    def _normalize_path(self, raw):
        if not raw:
            return None
        raw = raw.strip()
        if raw.startswith(("javascript:", "mailto:", "tel:", "#")):
            return None
        parsed = urlparse(raw)
        if parsed.scheme and parsed.netloc:
            if parsed.netloc.lower() != self._target_domain():
                return None
            path = parsed.path or "/"
        else:
            path = urlparse(urljoin(self.target, raw)).path or "/"
        return path if path.startswith("/") else f"/{path}"

    def _extract_paths_and_params(self, text):
        links = re.findall(r"(?:href|src|action)=[\"']([^\"']+)[\"']", text, flags=re.IGNORECASE)
        for link in links:
            norm = self._normalize_path(link)
            if norm:
                self.discovered_paths.add(norm)
            parsed = urlparse(urljoin(self.target, link))
            if parsed.netloc and parsed.netloc.lower() != self._target_domain():
                continue
            params = parse_qs(parsed.query)
            if params:
                p = parsed.path or "/"
                self.discovered_params.setdefault(p, set()).update(params.keys())

    def _discover_from_robots(self):
        res = self.req.get(self._join_url("/robots.txt"))
        if not res.ok:
            return
        for line in res.body.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key.lower().strip() in {"allow", "disallow"}:
                norm = self._normalize_path(value.strip())
                if norm:
                    self.discovered_paths.add(norm)

    def _discover_from_sitemap(self):
        res = self.req.get(self._join_url("/sitemap.xml"))
        if not res.ok:
            return
        for loc in re.findall(r"<loc>(.*?)</loc>", res.body, flags=re.IGNORECASE)[:500]:
            norm = self._normalize_path(loc)
            if norm:
                self.discovered_paths.add(norm)

    def _discover_hidden_candidates(self):
        candidates = []
        candidates.extend(self.payloads.get("dirlist", limit=self.hidden_limit))
        candidates.extend(self.payloads.get("backup", limit=self.hidden_limit // 2))
        candidates.extend(self.payloads.get("sensitive", limit=self.hidden_limit // 2))
        for c in candidates:
            c = c.strip()
            if not c or c.startswith(("http://", "https://")):
                continue
            if " " in c and "/" not in c:
                continue
            self.discovered_paths.add(c if c.startswith("/") else f"/{c}")

    def discover_surface(self):
        seed = self.req.get(self.target)
        if seed.ok and seed.body:
            self._extract_paths_and_params(seed.body)
        self._discover_from_robots()
        self._discover_from_sitemap()
        self._discover_hidden_candidates()
        first_wave = list(self.discovered_paths)[:120]
        for p in first_wave:
            if p.count("/") > 4:
                continue
            res = self.req.get(self._join_url(p))
            if res.ok and res.body:
                self._extract_paths_and_params(res.body)

    def _payloads_for(self, key):
        loaded = self.payloads.get(key) or ["test", "' OR '1'='1", "<script>alert(1)</script>", "../../../../etc/passwd", "${7*7}"]
        if self.max_payloads > 0:
            loaded = loaded[: self.max_payloads]
        variants = []
        for p in loaded:
            variants.extend([p, quote_plus(p)])
            if "%" in p:
                variants.append(quote_plus(p.replace("%", "%25")))
            if " " in p:
                variants.append(p.replace(" ", "/**/"))
        seen, dedup = set(), []
        for v in variants:
            if v and v not in seen:
                seen.add(v)
                dedup.append(v)
        return dedup[: max(1, len(loaded) * 3)]

    def _path_keywords(self, key):
        mapping = {
            "xss": ["search", "query", "q"],
            "sqli": ["id", "product", "item", "api"],
            "lfi": ["file", "download", "view"],
            "ssrf": ["url", "fetch", "proxy"],
            "cmd": ["ping", "exec", "cmd"],
            "openredirect": ["redirect", "next", "return"],
            "graphql": ["graphql"],
            "api": ["api", "swagger", "openapi"],
            "backup": ["backup", "bak", "old", "zip", "sql"],
            "dbexpose": ["phpmyadmin", "adminer", "db"],
            "debug": ["debug", "trace", "status"],
            "sensitive": [".env", ".git", "config", "secret"],
            "wordpress": ["wp"],
            "laravel": ["ignition", "laravel", ".env"],
        }
        return mapping.get(key, [key])

    def _select_targets(self, spec):
        selected = set(spec.seed_paths)
        keys = self._path_keywords(spec.key)
        for p in self.discovered_paths:
            if any(k in p.lower() for k in keys):
                selected.add(p)
        for p, params in self.discovered_params.items():
            if spec.param in params:
                selected.add(p)
        if spec.payload_as_path:
            for p in list(self.discovered_paths)[: self.hidden_limit]:
                if p.count("/") <= 4:
                    selected.add(p)
        return sorted([x for x in selected if x], key=lambda x: (len(x), x))[:15]

    def _baseline(self, spec, target_path):
        url = self._join_url(target_path)
        if spec.method == "POST":
            data = {spec.param: "baseline"} if spec.param != "noop" else None
            return self.req.request("POST", url, data=data)
        params = {spec.param: "baseline"} if spec.param != "noop" else None
        return self.req.request("GET", url, params=params, allow_redirects=False)

    def _build_request(self, spec, target_path, payload):
        headers = {}
        url = self._join_url(target_path)
        if spec.payload_as_path and spec.param == "noop":
            extra = payload if payload.startswith("/") else f"/{payload}"
            url = self._join_url(extra)
        if spec.detect == "header_injection":
            headers["X-Forwarded-For"] = payload
        elif spec.detect == "cors":
            headers["Origin"] = "https://evil.example"
        elif spec.detect == "jwt":
            headers["Authorization"] = f"Bearer {payload}"
        if spec.detect == "graphql":
            headers["Content-Type"] = "application/json"
            return self.req.request("POST", url, json={"query": payload}, headers=headers)
        if spec.method == "POST":
            data = {spec.param: payload} if spec.param != "noop" else None
            return self.req.request("POST", url, data=data, headers=headers)
        if spec.detect == "hpp":
            params = {spec.param: [payload, "2"]}
        else:
            params = {spec.param: payload} if spec.param != "noop" else None
        return self.req.request("GET", url, params=params, headers=headers, allow_redirects=False)

    def _score(self, detector, baseline, probe, payload):
        if not probe.ok:
            return None
        if probe.status_code == 404:
            return None
        body = probe.body or ""
        body_l = body.lower()
        base_l = (baseline.body or "").lower() if baseline and baseline.ok else ""
        hdr = {k.lower(): str(v).lower() for k, v in (probe.headers or {}).items()}
        score = 0
        evidence = []

        def add(points, msg):
            nonlocal score
            score += points
            evidence.append(msg)

        if detector == "reflected":
            if payload.lower() in body_l and payload.lower() not in base_l:
                add(85, "payload reflected in response")
            if re.search(r"<script|onerror=|onload=", body_l):
                add(10, "js sink pattern present")
        elif detector in {"sqli", "nosqli", "ldap", "xpath"}:
            signs = ["sql syntax", "mysql", "odbc", "postgres", "sqlite", "mongodb", "ldap", "xpath", "syntax error"]
            hits = [s for s in signs if s in body_l and s not in base_l]
            if hits:
                add(80, f"new backend error signature: {', '.join(hits[:3])}")
            if baseline and baseline.ok and abs(probe.elapsed - baseline.elapsed) > 2.5:
                add(15, "timing anomaly vs baseline")
        elif detector == "lfi" and any(x in body_l for x in ["root:x:0:0", "[extensions]", "boot loader", "windows\\win.ini"]):
            add(90, "file disclosure signature")
        elif detector == "ssrf" and any(x in body_l for x in ["169.254.169.254", "instance-id", "metadata", "ami-id"]):
            add(85, "internal metadata signature")
        elif detector == "xxe":
            if probe.status_code in {400, 415, 422, 500, 502, 503} and any(
                x in body_l for x in ["xml parser", "external entity", "failed to parse xml", "doctype"]
            ):
                add(80, "xml parser entity behavior")
        elif detector == "ssti" and any(x in body_l for x in ["49", "{{7*7}}", "jinja", "twig"]):
            add(70, "template expression output")
        elif detector == "cmd" and any(x in body_l for x in ["uid=", "gid=", "bin/bash", "windows\\system32"]):
            add(90, "command execution signature")
        elif detector == "open_redirect":
            loc = hdr.get("location", "")
            if "evil" in loc and ("http://" in loc or "https://" in loc or "//" in loc):
                add(85, f"location header external redirect: {loc[:120]}")
        elif detector == "csrf":
            if "<form" in body_l and not re.search(r"csrf|xsrf|_token", body_l):
                add(70, "form without anti-csrf token indicators")
        elif detector == "idor":
            if probe.status_code == 200 and baseline and baseline.status_code in {401, 403}:
                add(80, "id-based resource accessible while baseline blocked")
        elif detector == "header_injection" and any(x in body_l for x in ["x-forwarded-for", "set-cookie", "injected"]):
            add(70, "header value reflected")
        elif detector == "cors":
            acao = hdr.get("access-control-allow-origin", "")
            acac = hdr.get("access-control-allow-credentials", "")
            if acao == "*" or "evil.example" in acao:
                add(75, f"insecure access-control-allow-origin: {acao}")
            if acac == "true" and acao:
                add(15, "credentials allowed with permissive origin")
        elif detector in {"race", "smuggling", "cache", "hpp", "crlf", "responsesplit", "business"}:
            if baseline and baseline.ok and probe.status_code >= 500 > baseline.status_code:
                add(65, "server parser anomaly after payload")
            if baseline and baseline.ok and abs(len(body) - len(baseline.body or "")) > 700:
                add(20, "response length drift vs baseline")
        elif detector == "prototype" and any(x in body_l for x in ["__proto__", "constructor", "polluted"]):
            add(70, "prototype pollution indicator")
        elif detector == "graphql" and any(x in body_l for x in ["graphql", "__schema", "introspection", "errors"]):
            add(70, "graphql endpoint behavior exposed")
        elif detector == "websocket" and "upgrade" in hdr and "websocket" in hdr.get("upgrade", ""):
            add(75, "websocket upgrade exposed")
        elif detector == "api" and any(x in body_l for x in ["swagger", "openapi", "api key", "authorization"]):
            add(70, "api documentation/secret leakage")
        elif detector == "cloud" and any(x in body_l for x in ["amazonaws", "azure", "gcp", "bucket", "x-amz"]):
            add(70, "cloud artifact exposure")
        elif detector == "wordpress" and any(x in body_l for x in ["wp-content", "wp-json", "wordpress"]):
            add(75, "wordpress footprint")
        elif detector == "laravel" and any(x in body_l for x in ["laravel", "ignition", "whoops", "app_key"]):
            add(75, "laravel debug/config leakage")
        elif detector == "deserialize" and any(x in body_l for x in ["unserialize", "deserialize", "pickle", "java.io"]):
            add(70, "deserialization parser response")
        elif detector == "dns" and any(x in body_l for x in ["dns", "resolver", "nameserver", "dig"]):
            add(60, "dns output exposed")
        elif detector == "ssl":
            if self.target.startswith("http://"):
                add(85, "plaintext http transport")
            if "strict-transport-security" not in hdr:
                add(15, "missing HSTS header")
        elif detector == "sensitive" and any(x in body_l for x in ["private key", "aws_secret", "password=", "-----begin", "root:x:0:0"]):
            add(90, "sensitive secret signature")
        elif detector == "defaultcreds":
            if probe.status_code == 200 and any(x in body_l for x in ["admin", "dashboard", "control panel"]):
                add(70, "admin panel exposed without explicit auth gate")
        elif detector == "infodisclose" and any(x in body_l for x in ["traceback", "stack trace", "exception", "internal server error"]):
            add(70, "verbose internal error")
        elif detector == "mailheader" and any(x in body_l for x in ["bcc:", "cc:", "subject:"]):
            add(65, "mail header injection echo")
        elif detector == "sessionfix":
            set_cookie = hdr.get("set-cookie", "")
            if "session" in set_cookie and ("httponly" not in set_cookie or "secure" not in set_cookie):
                add(75, "weak session cookie flags")
        elif detector == "clickjacking":
            if probe.status_code < 400 and "x-frame-options" not in hdr and "content-security-policy" not in hdr:
                add(80, "missing anti-clickjacking headers")
        elif detector == "servermis":
            if any(x in hdr for x in ["server", "x-powered-by", "x-aspnet-version"]):
                add(60, "technology banner disclosure")
            if "index of /" in body_l:
                add(25, "directory autoindex enabled")
        elif detector == "dbexpose" and any(x in body_l for x in ["phpmyadmin", "adminer", "mongo express", "dbadmin"]):
            add(80, "database panel exposure")
        elif detector == "backup":
            if probe.status_code == 200 and any(x in probe.url.lower() for x in [".zip", ".tar", ".gz", ".sql", ".bak", ".old"]):
                add(85, "backup file publicly accessible")
        elif detector == "dirlist" and ("index of /" in body_l or "parent directory" in body_l):
            add(85, "directory listing enabled")
        elif detector == "debug" and any(x in body_l for x in ["debug", "trace", "profiler", "developer mode"]):
            add(75, "debug endpoint leakage")
        elif detector == "csp":
            csp = hdr.get("content-security-policy", "")
            if probe.status_code < 400 and not csp:
                add(80, "missing csp header")
            elif "unsafe-inline" in csp or "unsafe-eval" in csp:
                add(70, "weak csp directive")
        elif detector == "subdomain" and any(x in body_l for x in ["there isn't a github pages site here", "no such app", "no such bucket"]):
            add(75, "dangling-host fingerprint")
        elif detector == "emailharvest":
            mails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[A-Za-z]{2,}", body))
            if len(mails) >= 3:
                add(70, f"public email leakage ({len(mails)})")
        elif detector == "fingerprint":
            fp = [h for h in ["server", "x-powered-by", "x-runtime"] if h in hdr]
            if probe.status_code < 400 and fp:
                add(70, f"fingerprint headers: {', '.join(fp)}")
        elif detector == "waf":
            if not any(h in hdr for h in ["cf-ray", "x-sucuri-id", "x-akamai", "x-waf"]):
                add(55, "no clear waf signature")
        elif detector == "ratelimit":
            if baseline and baseline.ok and baseline.status_code in {200, 201, 202, 204}:
                burst = []
                for i in range(8):
                    r = self.req.request("GET", probe.url.split("?")[0], params={"burst": str(i)})
                    burst.append(r.status_code)
                if 429 not in burst and 503 not in burst:
                    add(75, "burst requests not throttled")

        if score >= 70:
            return {"type": f"{detector.upper()} Vulnerability", "confidence": min(score, 100), "evidence": "; ".join(evidence[:4])}
        return None

    def _record(self, spec, probe, payload, det):
        self.results.append(
            {
                "phase": spec.key.upper(),
                "phase_id": spec.id,
                "name": spec.name,
                "type": det["type"],
                "url": probe.url,
                "severity": spec.severity,
                "payload": payload[:260],
                "status_code": probe.status_code,
                "elapsed": probe.elapsed,
                "confidence": det["confidence"],
                "evidence": det["evidence"],
            }
        )

    def run_phase(self, spec):
        phase_start = time.perf_counter()
        targets = self._select_targets(spec)
        payloads = self._payloads_for(spec.key)
        self.header(spec.id, spec.name, len(targets), len(payloads))
        if not targets:
            self.footer(0, 0.0, skipped=True)
            return

        baselines = {t: self._baseline(spec, t) for t in targets}
        jobs = [(t, p) for t in targets for p in payloads]
        findings = 0
        seen = set()

        def worker(target_path, payload):
            probe = self._build_request(spec, target_path, payload)
            det = self._score(spec.detect, baselines.get(target_path), probe, payload)
            if not det:
                return None
            dedup = (spec.id, probe.url, det["type"], det["evidence"])
            return probe, payload, det, dedup

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = [ex.submit(worker, t, p) for t, p in jobs]
            for fut in tqdm(as_completed(futures), total=len(futures), desc=f"P{spec.id:02d} {spec.key.upper()}", leave=False):
                result = fut.result()
                if not result:
                    continue
                probe, payload, det, dedup = result
                if dedup in seen:
                    continue
                seen.add(dedup)
                self._record(spec, probe, payload, det)
                findings += 1
        self.total_findings += findings
        self.footer(findings, time.perf_counter() - phase_start)

    def run(self):
        self.utils.ensure_folders()
        self.banner()
        self.start = time.time()
        self._box_border(Fore.CYAN, top=True)
        self._box_line(f"{self.ui['scan']} target: {self.target}", Fore.WHITE)
        self._box_line(
            f"{self.ui['dot']} max_payloads={self.max_payloads if self.max_payloads > 0 else 'ALL'}  {self.ui['dot']} hidden_limit={self.hidden_limit}",
            Fore.WHITE,
        )
        self._box_border(Fore.CYAN, top=False)
        print(self._fmt(f"{self.ui['scan']} discovering hidden attack surface...", Fore.CYAN))
        self.discover_surface()
        print(
            self._fmt(
                f"{self.ui['ok']} discovered paths={len(self.discovered_paths)} | parameterized endpoints={len(self.discovered_params)}",
                Fore.CYAN,
            )
        )
        for spec in self.phase_specs:
            self.run_phase(spec)
            time.sleep(0.02)
        self.end = time.time()
        report_file = self.reporter.generate(self.target, self.results, self.start, self.end)
        self.reporter.summary(self.results)
        total_elapsed = self.end - self.start
        self._box_border(Fore.GREEN, top=True)
        self._box_line(f"{self.ui['ok']} scan completed in {total_elapsed:.2f}s", Fore.GREEN)
        self._box_line(f"{self.ui['dot']} findings={self.total_findings}  {self.ui['dot']} report={report_file}", Fore.GREEN)
        self._box_border(Fore.GREEN, top=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL")
    parser.add_argument("--max-payloads", type=int, default=40, help="Max payloads per phase. 0 = all")
    parser.add_argument("--threads", type=int, default=8, help="Worker threads per phase")
    parser.add_argument("--hidden-limit", type=int, default=120, help="Hidden path candidates for discovery")
    args = parser.parse_args()
    scanner = AuroseScanner(max_payloads=args.max_payloads, threads=args.threads, hidden_limit=args.hidden_limit)
    scanner.target = scanner.utils.validate_url(args.target)
    scanner.run()


if __name__ == "__main__":
    main()
