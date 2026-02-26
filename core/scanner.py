#!/usr/bin/env python3
import argparse
import os
import random
import re
import shutil
import sys
import textwrap
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
from core.request_handler import RequestHandler, ResponseMeta
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
    def __init__(
        self,
        max_payloads=40,
        threads=8,
        hidden_limit=120,
        include_paths=None,
        exclude_paths=None,
        max_requests=0,
        max_runtime=0,
        delay_jitter=0.0,
    ):
        self.target = ""
        self.max_payloads = max_payloads
        self.threads = max(1, threads)
        self.hidden_limit = max(20, hidden_limit)
        self.include_paths = [x.strip().lower() for x in (include_paths or []) if x and x.strip()]
        self.exclude_paths = [x.strip().lower() for x in (exclude_paths or []) if x and x.strip()]
        self.max_requests = max(0, int(max_requests or 0))
        self.max_runtime = max(0, int(max_runtime or 0))
        self.delay_jitter = max(0.0, float(delay_jitter or 0.0))
        self.request_count = 0
        self.scan_aborted = False
        self.scan_abort_reason = ""
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
        self.term_width = max(58, min(140, shutil.get_terminal_size((100, 24)).columns))
        self.inner_width = self.term_width - 4
        self.use_color = bool(getattr(sys.stdout, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR")
        encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
        self.use_unicode = "utf" in encoding and os.environ.get("TERM", "") != "dumb"
        self.total_findings = 0
        self.ui = (
            {
                "h": "\u2500",
                "v": "\u2502",
                "tl": "\u256d",
                "tr": "\u256e",
                "bl": "\u2570",
                "br": "\u256f",
                "ok": "\u2713",
                "warn": "\u26a0",
                "scan": "\u25c9",
                "bolt": "\u26a1",
                "dot": "\u2022",
                "bar_full": "\u2588",
                "bar_empty": "\u2591",
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
        self.c_border = Fore.GREEN
        self.c_title = Fore.GREEN
        self.c_meta = Fore.YELLOW
        self.c_info = Fore.CYAN
        self.c_warn = Fore.RED
        self._wrap_request_layer()

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

    def _wrap_request_layer(self):
        base_request = self.req.request

        def wrapped_request(method, url, **kwargs):
            if self.scan_aborted:
                return ResponseMeta(
                    ok=False,
                    status_code=0,
                    url=url,
                    headers={},
                    body="",
                    elapsed=0.0,
                    error=self.scan_abort_reason or "Pemindaian dihentikan.",
                )
            if self.max_runtime > 0 and self.start:
                if (time.time() - self.start) >= self.max_runtime:
                    self.scan_aborted = True
                    self.scan_abort_reason = "Batas waktu pemindaian tercapai."
                    return ResponseMeta(False, 0, url, {}, "", 0.0, self.scan_abort_reason)
            if self.max_requests > 0 and self.request_count >= self.max_requests:
                self.scan_aborted = True
                self.scan_abort_reason = "Batas total request tercapai."
                return ResponseMeta(False, 0, url, {}, "", 0.0, self.scan_abort_reason)

            path_l = (urlparse(url).path or "/").lower()
            if self.include_paths and not any(x in path_l for x in self.include_paths):
                return ResponseMeta(False, 0, url, {}, "", 0.0, "Di luar cakupan include.")
            if self.exclude_paths and any(x in path_l for x in self.exclude_paths):
                return ResponseMeta(False, 0, url, {}, "", 0.0, "Termasuk pola exclude.")

            if self.delay_jitter > 0:
                time.sleep(random.uniform(0.0, self.delay_jitter))
            self.request_count += 1
            return base_request(method, url, **kwargs)

        self.req.request = wrapped_request
        self.req.get = lambda url, **kwargs: wrapped_request("GET", url, **kwargs)
        self.req.post = lambda url, **kwargs: wrapped_request("POST", url, **kwargs)

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
        wrapped = textwrap.wrap(text, width=self.inner_width) or [""]
        for line in wrapped:
            print(self._fmt(f"{self.ui['v']} {line:<{self.inner_width}} {self.ui['v']}", color))

    def _inner_block(self, title, rows, color=Fore.GREEN):
        inner_w = self.inner_width
        top = f"{self.ui['tl']}{self.ui['h'] * (inner_w - 2)}{self.ui['tr']}"
        sep = f"{self.ui['v']}{self.ui['h'] * (inner_w - 2)}{self.ui['v']}"
        bot = f"{self.ui['bl']}{self.ui['h'] * (inner_w - 2)}{self.ui['br']}"
        self._box_line(top, self.c_border)
        label = f"[{title.upper()}]"
        self._box_line(f"{self.ui['v']} {label:<{inner_w - 4}} {self.ui['v']}", color)
        self._box_line(sep, self.c_border)
        for r in rows:
            line = textwrap.shorten(r, width=inner_w - 4, placeholder="...")
            self._box_line(f"{self.ui['v']} {line:<{inner_w - 4}} {self.ui['v']}", Fore.WHITE)
        self._box_line(bot, self.c_border)

    def _badge(self, text):
        return f"[{text}]"

    def _progress_bar(self, ratio, width=26):
        ratio = max(0.0, min(1.0, ratio))
        fill = int(width * ratio)
        return f"{self.ui['bar_full'] * fill}{self.ui['bar_empty'] * (width - fill)}"

    def banner(self):
        self._clear_screen()
        title = f"{self.ui['bolt']} AUROSE SCANNER"
        subtitle = "UI RETRO MODERN  |  ANALISIS KERENTANAN BERBASIS REQUEST NYATA"
        chips = f"{self._badge('50 FASE')}  {self._badge(f'{self.threads} THREAD')}  {self._badge('LINUX/TERMUX')}"

        self._box_border(self.c_border, top=True)
        self._box_line(title, self.c_title)
        self._box_line(subtitle, self.c_meta)
        self._box_line(chips, self.c_info)
        self._box_line("Pilih mode aman: --max-requests / --max-runtime / --include / --exclude", Fore.WHITE)
        self._box_border(self.c_border, top=False)

    def header(self, num, name, targets, payloads):
        print()
        ratio = num / self.total_phases
        jobs = targets * payloads
        phase_label = f"FASE {num:02d}/{self.total_phases:02d}  {self._nama_fase_indonesia(name).upper()}"
        progress = f"[{self._progress_bar(ratio)}] {int(ratio * 100):>3d}%"
        meta = f"{self._badge('TARGET')} {targets}   {self._badge('PAYLOAD')} {payloads}   {self._badge('PEKERJAAN')} ~{jobs}"
        self._box_border(self.c_border, top=True)
        self._box_line(phase_label, self.c_title)
        self._box_line(progress, self.c_info)
        self._box_line(meta, self.c_meta)
        self._inner_block(
            "RINGKASAN FASE",
            [
                f"Nama       : {self._nama_fase_indonesia(name)}",
                f"Progress   : {int(ratio * 100)}% ({num}/{self.total_phases})",
                f"Target     : {targets}",
                f"Payload    : {payloads}",
                f"Pekerjaan  : {jobs}",
            ],
            self.c_meta,
        )
        self._box_border(self.c_border, top=False)

    def footer(self, count, elapsed=0.0, skipped=False):
        if skipped:
            status = f"{self.ui['warn']} DILEWATI"
            color = self.c_warn
        elif count == 0:
            status = f"{self.ui['ok']} BERSIH"
            color = self.c_title
        else:
            status = f"{self.ui['warn']} TEMUAN {count}"
            color = self.c_warn
        summary = f"{status}  {self.ui['dot']} durasi={elapsed:.2f}s  {self.ui['dot']} ditemukan={self.total_findings}"
        self._box_border(self.c_border, top=True)
        self._inner_block(
            "STATUS FASE",
            [
                summary,
                f"Request total : {self.request_count}",
                f"Status scan   : {'AKTIF' if not self.scan_aborted else 'DIHENTIKAN'}",
            ],
            color,
        )
        self._box_border(self.c_border, top=False)

    def _target_domain(self):
        return urlparse(self.target).netloc.lower()

    def _is_target_url(self, url):
        try:
            host = (urlparse(url).netloc or "").lower()
        except Exception:
            return False
        return host == self._target_domain()

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

    def _file_audit_candidates(self):
        common = {
            "/.env",
            "/.env.local",
            "/.git/config",
            "/config.php",
            "/wp-config.php.bak",
            "/database.sql",
            "/db.sql",
            "/backup.zip",
            "/dump.sql",
            "/.DS_Store",
            "/.htaccess",
            "/phpinfo.php",
            "/server-status",
            "/swagger.json",
            "/openapi.json",
            "/actuator/env",
            "/actuator/heapdump",
            "/actuator/configprops",
        }
        for key in ("sensitive", "backup", "api", "dbexpose", "debug"):
            for p in self.payloads.get(key, limit=120):
                if not p:
                    continue
                path = p.strip()
                if not path or path.startswith(("http://", "https://")):
                    continue
                common.add(path if path.startswith("/") else f"/{path}")

        # prioritize file-like paths and known sensitive endpoints
        file_like = []
        extensions = (".env", ".ini", ".conf", ".json", ".xml", ".yaml", ".yml", ".sql", ".bak", ".zip", ".tar", ".gz", ".log")
        for p in sorted(common.union(self.discovered_paths)):
            l = p.lower()
            if (
                any(ext in l for ext in extensions)
                or any(x in l for x in [".git", "backup", "dump", "config", "secret", "token", "key", "debug", "swagger", "openapi"])
            ):
                file_like.append(p)
        return file_like[: max(80, self.hidden_limit * 2)]

    def _leak_signatures(self, body):
        if not body:
            return []
        patterns = [
            ("PRIVATE_KEY", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
            ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
            ("GCP_API_KEY", r"AIza[0-9A-Za-z\\-_]{35}"),
            ("GENERIC_API_KEY", r"(?i)(api[_-]?key|secret|token)[\"'\\s:=]{1,6}[A-Za-z0-9_\\-]{12,}"),
            ("DB_PASSWORD", r"(?i)(db_password|database_password|mysql_password|postgres_password|password)[\"'\\s:=]{1,6}[^\\s\"']{4,}"),
            ("JWT_TOKEN", r"eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}\\.[A-Za-z0-9._-]{10,}"),
            ("CLOUD_CREDENTIAL", r"(?i)(aws_secret_access_key|xox[baprs]-[0-9A-Za-z-]{10,}|ghp_[0-9A-Za-z]{20,})"),
        ]
        hits = []
        for name, pattern in patterns:
            if re.search(pattern, body):
                hits.append(name)
        return hits

    def run_file_leakage_audit(self):
        candidates = self._file_audit_candidates()
        if not candidates:
            return
        print(self._fmt(f"{self.ui['scan']} audit file terbuka dan pola kebocoran data...", self.c_info))
        findings = 0
        seen = set()
        for path in candidates:
            probe = self.req.get(self._join_url(path), allow_redirects=False)
            if not probe.ok or probe.status_code in {404, 429}:
                continue
            if not self._is_target_url(probe.url):
                continue
            access_state, status_label, status_explanation = self._status_details(probe.status_code)
            body_l = (probe.body or "").lower()
            url_l = probe.url.lower()

            # exposed file indicators
            file_exposed = (
                probe.status_code in {200, 206}
                and any(x in url_l for x in [".env", ".sql", ".bak", ".zip", ".tar", ".gz", ".log", ".git/config", "heapdump"])
            )
            signatures = self._leak_signatures(probe.body or "")
            if "index of /" in body_l and ("parent directory" in body_l or "last modified" in body_l):
                signatures.append("DIRECTORY_INDEX")
            if any(x in body_l for x in ["swagger", "openapi", "\"paths\":", "\"openapi\""]):
                signatures.append("API_SCHEMA_EXPOSURE")

            if not file_exposed and not signatures:
                continue

            evidence_parts = []
            if file_exposed:
                evidence_parts.append("public sensitive/backup file path accessible")
            if signatures:
                evidence_parts.append(f"leak signatures: {', '.join(sorted(set(signatures))[:4])}")
            evidence = "; ".join(evidence_parts)
            dedup = (probe.url, evidence)
            if dedup in seen:
                continue
            seen.add(dedup)

            confidence = 90 if file_exposed else 80
            self.results.append(
                {
                    "phase": "FILEAUDIT",
                    "phase_id": 0,
                    "name": "Audit File Terbuka & Kebocoran Data",
                    "type": "Kerentanan KEBOCORAN_DATA",
                    "url": probe.url,
                    "domain_target": self._target_domain(),
                    "severity": "TINGGI" if file_exposed else "SEDANG",
                    "payload": path[:260],
                    "status_code": probe.status_code,
                    "status_label": status_label,
                    "access_state": access_state,
                    "status_explanation": status_explanation,
                    "elapsed": probe.elapsed,
                    "confidence": confidence,
                    "evidence": evidence,
                }
            )
            findings += 1
        self.total_findings += findings
        print(self._fmt(f"{self.ui['ok']} temuan audit file={findings}", self.c_info))

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
        if not self._is_target_url(probe.url):
            return
        access_state, status_label, status_explanation = self._status_details(probe.status_code)
        self.results.append(
            {
                "phase": spec.key.upper(),
                "phase_id": spec.id,
                "name": self._nama_fase_indonesia(spec.name),
                "type": self._tipe_indonesia(det["type"]),
                "url": probe.url,
                "domain_target": self._target_domain(),
                "severity": self._severity_indonesia(spec.severity),
                "payload": payload[:260],
                "status_code": probe.status_code,
                "status_label": status_label,
                "access_state": access_state,
                "status_explanation": status_explanation,
                "elapsed": probe.elapsed,
                "confidence": det["confidence"],
                "evidence": self._teks_indonesia(det["evidence"]),
            }
        )

    def _nama_fase_indonesia(self, name):
        kamus = {
            "Cross-Site Scripting": "Cross-Site Scripting",
            "SQL Injection": "Injeksi SQL",
            "Local File Inclusion": "Inklusi File Lokal",
            "Server-Side Request Forgery": "Pemalsuan Request Sisi Server",
            "XML External Entity": "Entitas Eksternal XML",
            "Server-Side Template Injection": "Injeksi Template Sisi Server",
            "Command Injection": "Injeksi Perintah",
            "Open Redirect": "Redirect Terbuka",
            "CSRF Weakness": "Kelemahan CSRF",
            "IDOR": "IDOR",
            "JWT Weakness": "Kelemahan JWT",
            "NoSQL Injection": "Injeksi NoSQL",
            "Header Injection": "Injeksi Header",
            "CORS Misconfiguration": "Salah Konfigurasi CORS",
            "Race Condition Indicator": "Indikator Race Condition",
            "HTTP Smuggling Indicator": "Indikator HTTP Smuggling",
            "Cache Poisoning": "Cache Poisoning",
            "Prototype Pollution": "Prototype Pollution",
            "GraphQL Exposure": "Eksposur GraphQL",
            "WebSocket Exposure": "Eksposur WebSocket",
            "API Leakage": "Kebocoran API",
            "Cloud Misconfiguration": "Salah Konfigurasi Cloud",
            "WordPress Exposure": "Eksposur WordPress",
            "Laravel Exposure": "Eksposur Laravel",
            "Deserialization": "Deserialisasi Berbahaya",
            "DNS Leakage": "Kebocoran DNS",
            "SSL/TLS Weakness": "Kelemahan SSL/TLS",
            "Sensitive Data Exposure": "Eksposur Data Sensitif",
            "Default Credentials": "Kredensial Bawaan",
            "Information Disclosure": "Pengungkapan Informasi",
            "HTTP Parameter Pollution": "Polusi Parameter HTTP",
            "LDAP Injection": "Injeksi LDAP",
            "XPath Injection": "Injeksi XPath",
            "Mail Header Injection": "Injeksi Header Email",
            "CRLF Injection": "Injeksi CRLF",
            "HTTP Response Splitting": "Pemisahan Respons HTTP",
            "Session Fixation": "Session Fixation",
            "Clickjacking": "Clickjacking",
            "Server Misconfiguration": "Salah Konfigurasi Server",
            "Database Exposure": "Eksposur Database",
            "Backup Files": "File Backup Terbuka",
            "Directory Listing": "Listing Direktori",
            "Debug Mode": "Mode Debug Terbuka",
            "CSP Weakness": "Kelemahan CSP",
            "Subdomain Takeover Indicator": "Indikator Pengambilalihan Subdomain",
            "Email Harvesting": "Pengambilan Email",
            "Fingerprint Leakage": "Kebocoran Fingerprint",
            "WAF Detection": "Deteksi WAF",
            "Rate Limiting Weakness": "Kelemahan Pembatasan Laju",
            "Business Logic Indicator": "Indikator Logika Bisnis",
            "File Exposure & Data Leakage Audit": "Audit File Terbuka & Kebocoran Data",
        }
        return kamus.get(name, name)

    def _tipe_indonesia(self, tipe):
        return tipe.replace("Vulnerability", "Kerentanan")

    def _severity_indonesia(self, sev):
        return {"CRITICAL": "KRITIS", "HIGH": "TINGGI", "MEDIUM": "SEDANG", "LOW": "RENDAH"}.get(sev, sev)

    def _teks_indonesia(self, teks):
        ganti = {
            "payload reflected in response": "payload terefleksi di respons",
            "js sink pattern present": "terdapat pola sink JavaScript",
            "timing anomaly vs baseline": "anomali waktu dibanding baseline",
            "file disclosure signature": "indikasi kebocoran file",
            "internal metadata signature": "indikasi metadata internal",
            "xml parser entity behavior": "perilaku parser XML terkait entity",
            "template expression output": "output ekspresi template terdeteksi",
            "command execution signature": "indikasi eksekusi perintah",
            "form without anti-csrf token indicators": "form tanpa indikator token anti-CSRF",
            "header value reflected": "nilai header terefleksi",
            "server parser anomaly after payload": "anomali parser server setelah payload",
            "response length drift vs baseline": "perubahan panjang respons vs baseline",
            "graphql endpoint behavior exposed": "perilaku endpoint GraphQL terekspos",
            "api documentation/secret leakage": "kebocoran dokumentasi API/rahasia",
            "cloud artifact exposure": "artefak cloud terekspos",
            "sensitive secret signature": "indikasi data rahasia sensitif",
            "verbose internal error": "pesan error internal terlalu detail",
            "missing anti-clickjacking headers": "header anti-clickjacking tidak ada",
            "missing csp header": "header CSP tidak ada",
            "weak csp directive": "direktif CSP lemah",
            "directory listing enabled": "listing direktori aktif",
            "technology banner disclosure": "banner teknologi terekspos",
            "public email leakage": "kebocoran email publik",
            "fingerprint headers": "header fingerprint",
            "burst requests not throttled": "burst request tidak dibatasi",
            "public sensitive/backup file path accessible": "jalur file sensitif/backup bisa diakses publik",
            "leak signatures": "indikasi kebocoran",
        }
        out = teks or ""
        for k, v in ganti.items():
            out = out.replace(k, v)
        return out

    def _status_details(self, status_code):
        mapping = {
            0: ("tidak_terjangkau", "ERROR_JARINGAN", "Tidak ada respons HTTP. Koneksi gagal, timeout, atau masalah DNS/jaringan."),
            200: ("dapat_diakses", "OK", "Request berhasil. Endpoint bisa diakses dan mengembalikan konten."),
            201: ("dapat_diakses", "DIBUAT", "Request berhasil dan membuat resource."),
            202: ("dapat_diakses", "DITERIMA", "Request diterima untuk diproses (umumnya async)."),
            204: ("dapat_diakses", "TANPA_KONTEN", "Request berhasil tanpa body respons."),
            301: ("dialihkan", "DIPINDAH_PERMANEN", "Resource dipindah permanen ke lokasi lain."),
            302: ("dialihkan", "DITEMUKAN", "Dialihkan sementara ke lokasi lain."),
            307: ("dialihkan", "REDIRECT_SEMENTARA", "Redirect sementara dengan method tetap."),
            308: ("dialihkan", "REDIRECT_PERMANEN", "Redirect permanen dengan method tetap."),
            400: ("error_request", "REQUEST_TIDAK_VALID", "Server menolak request yang tidak valid."),
            401: ("terlindungi", "PERLU_OTENTIKASI", "Membutuhkan autentikasi."),
            403: ("ditolak", "DILARANG", "Endpoint ada tetapi akses ditolak."),
            404: ("tidak_ditemukan", "TIDAK_DITEMUKAN", "Endpoint/path tidak ditemukan."),
            405: ("terlindungi", "METHOD_TIDAK_DIIZINKAN", "Endpoint ada tetapi method HTTP tidak diizinkan."),
            408: ("error_request", "WAKTU_REQUEST_HABIS", "Server timeout menunggu request."),
            429: ("dibatasi", "TERLALU_BANYAK_REQUEST", "Rate limit aktif."),
            500: ("error_server", "ERROR_SERVER_INTERNAL", "Terjadi kegagalan umum di sisi server."),
            502: ("error_server", "BAD_GATEWAY", "Gateway/proxy menerima respons upstream tidak valid."),
            503: ("error_server", "LAYANAN_TIDAK_TERSEDIA", "Layanan sementara tidak tersedia/overload."),
            504: ("error_server", "GATEWAY_TIMEOUT", "Gateway/proxy timeout menunggu upstream."),
        }
        if status_code in mapping:
            return mapping[status_code]
        if 200 <= status_code < 300:
            return ("dapat_diakses", "BERHASIL", "Request berhasil.")
        if 300 <= status_code < 400:
            return ("dialihkan", "REDIRECT", "Request dialihkan ke lokasi lain.")
        if 400 <= status_code < 500:
            return ("error_klien", "ERROR_KLIEN", "Masalah pada request sisi klien atau pembatasan akses.")
        if 500 <= status_code < 600:
            return ("error_server", "ERROR_SERVER", "Kegagalan di sisi server.")
        return ("tidak_diketahui", "TIDAK_DIKETAHUI", "Status code belum dipetakan.")

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
            for fut in tqdm(as_completed(futures), total=len(futures), desc=f"F{spec.id:02d} {spec.key.upper()}", leave=False):
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
        self._box_border(self.c_border, top=True)
        self._box_line(f"{self.ui['scan']} sasaran: {self.target}", Fore.WHITE)
        self._box_line(
            f"{self.ui['dot']} maks_payload={self.max_payloads if self.max_payloads > 0 else 'SEMUA'}  {self.ui['dot']} batas_hidden={self.hidden_limit}",
            Fore.WHITE,
        )
        self._box_line(
            f"{self.ui['dot']} maks_request={self.max_requests if self.max_requests > 0 else 'tak terbatas'}  {self.ui['dot']} maks_waktu={self.max_runtime if self.max_runtime > 0 else 'tak terbatas'} dtk",
            Fore.WHITE,
        )
        self._box_border(self.c_border, top=False)
        print(self._fmt(f"{self.ui['scan']} menemukan permukaan serangan tersembunyi...", self.c_info))
        self.discover_surface()
        print(
            self._fmt(
                f"{self.ui['ok']} path ditemukan={len(self.discovered_paths)} | endpoint ber-parameter={len(self.discovered_params)}",
                self.c_info,
            )
        )
        self.run_file_leakage_audit()
        for spec in self.phase_specs:
            if self.scan_aborted:
                break
            self.run_phase(spec)
            time.sleep(0.02)
        self.end = time.time()
        report_file = self.reporter.generate(self.target, self.results, self.start, self.end)
        self.reporter.summary(self.results)
        total_elapsed = self.end - self.start
        self._box_border(self.c_border, top=True)
        self._box_line(f"{self.ui['ok']} pemindaian selesai dalam {total_elapsed:.2f} detik", self.c_title)
        self._box_line(f"{self.ui['dot']} temuan={self.total_findings}  {self.ui['dot']} request={self.request_count}  {self.ui['dot']} laporan={report_file}", self.c_title)
        if self.scan_aborted:
            self._box_line(f"{self.ui['warn']} dihentikan otomatis: {self.scan_abort_reason}", self.c_warn)
        self._box_border(self.c_border, top=False)


def main():
    parser = argparse.ArgumentParser(description="Pemindai kerentanan web berbasis payload.")
    parser.add_argument("target", help="URL target")
    parser.add_argument("--max-payloads", type=int, default=40, help="Maks payload per fase. 0 = semua")
    parser.add_argument("--threads", type=int, default=8, help="Jumlah thread pekerja per fase")
    parser.add_argument("--hidden-limit", type=int, default=120, help="Batas kandidat path tersembunyi")
    parser.add_argument("--include", default="", help="Filter path yang diizinkan (pisahkan dengan koma)")
    parser.add_argument("--exclude", default="", help="Filter path yang dikecualikan (pisahkan dengan koma)")
    parser.add_argument("--max-requests", type=int, default=0, help="Batas total request (0 = tak terbatas)")
    parser.add_argument("--max-runtime", type=int, default=0, help="Batas durasi scan dalam detik (0 = tak terbatas)")
    parser.add_argument("--delay-jitter", type=float, default=0.0, help="Delay acak tambahan per request (detik)")
    args = parser.parse_args()
    include_paths = [x.strip() for x in args.include.split(",") if x.strip()]
    exclude_paths = [x.strip() for x in args.exclude.split(",") if x.strip()]
    scanner = AuroseScanner(
        max_payloads=args.max_payloads,
        threads=args.threads,
        hidden_limit=args.hidden_limit,
        include_paths=include_paths,
        exclude_paths=exclude_paths,
        max_requests=args.max_requests,
        max_runtime=args.max_runtime,
        delay_jitter=args.delay_jitter,
    )
    scanner.target = scanner.utils.validate_url(args.target)
    scanner.run()


if __name__ == "__main__":
    main()
