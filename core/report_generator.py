import json
import os
import shutil
import sys
import textwrap
from datetime import datetime
from urllib.parse import urlparse

try:
    from colorama import Fore, Style
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        RESET = RESET_ALL = ""

    Fore = Style = _NoColor()


class ReportGenerator:
    def __init__(self):
        self.report_dir = "reports"
        self.term_width = max(58, min(140, shutil.get_terminal_size((100, 24)).columns))
        self.inner_width = self.term_width - 4
        encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
        self.use_unicode = "utf" in encoding
        self.ui = (
            {"h": "\u2500", "v": "\u2502", "tl": "\u256d", "tr": "\u256e", "bl": "\u2570", "br": "\u256f", "dot": "\u2022"}
            if self.use_unicode
            else {"h": "-", "v": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+", "dot": "-"}
        )

    def _border(self, top=True):
        left = self.ui["tl"] if top else self.ui["bl"]
        right = self.ui["tr"] if top else self.ui["br"]
        print(f"{Fore.GREEN}{left}{self.ui['h'] * (self.term_width - 2)}{right}{Style.RESET_ALL}")

    def _line(self, text, color=Fore.WHITE):
        wrapped = textwrap.wrap(text, width=self.inner_width) or [""]
        for line in wrapped:
            print(f"{color}{self.ui['v']} {line:<{self.inner_width}} {self.ui['v']}{Style.RESET_ALL}")

    def _nama_file_domain(self, target):
        domain = (urlparse(target).netloc or "").lower()
        if not domain:
            domain = "target_tidak_diketahui"
        aman = "".join(ch if ch.isalnum() or ch in ".-_" else "_" for ch in domain)
        return f"{self.report_dir}/{aman}.json", domain

    def generate(self, target, vulns, start, end):
        fname, domain = self._nama_file_domain(target)
        report = {"target": target, "domain_target": domain, "total": 0, "vulnerabilities": [], "riwayat_scan": []}

        if os.path.exists(fname):
            try:
                with open(fname, "r", encoding="utf-8") as f:
                    data_lama = json.load(f)
                if isinstance(data_lama, dict):
                    report.update(data_lama)
            except (OSError, json.JSONDecodeError):
                pass

        data_vuln = report.get("vulnerabilities", [])
        if not isinstance(data_vuln, list):
            data_vuln = []
        data_vuln.extend(vulns)
        report["vulnerabilities"] = data_vuln
        report["total"] = len(data_vuln)
        report["target"] = target
        report["domain_target"] = domain
        report["scan_start"] = start
        report["scan_end"] = end
        report["duration"] = end - start

        riwayat = report.get("riwayat_scan", [])
        if not isinstance(riwayat, list):
            riwayat = []
        riwayat.append(
            {
                "waktu": datetime.now().isoformat(),
                "scan_start": start,
                "scan_end": end,
                "durasi": end - start,
                "temuan_baru": len(vulns),
                "total_setelah_scan": report["total"],
            }
        )
        report["riwayat_scan"] = riwayat

        with open(fname, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return fname

    def summary(self, vulns):
        if not vulns:
            print(f"{Fore.GREEN}[OK] Tidak ada kerentanan ditemukan.{Style.RESET_ALL}")
            return

        sev = {"KRITIS": 0, "TINGGI": 0, "SEDANG": 0, "RENDAH": 0}
        access = {
            "dapat_diakses": 0,
            "dialihkan": 0,
            "terlindungi": 0,
            "ditolak": 0,
            "tidak_ditemukan": 0,
            "dibatasi": 0,
            "error_server": 0,
            "lainnya": 0,
        }
        for v in vulns:
            sev[v["severity"]] = sev.get(v["severity"], 0) + 1
            key = v.get("access_state", "lainnya")
            access[key if key in access else "lainnya"] += 1

        print()
        self._border(top=True)
        self._line("RINGKASAN KERENTANAN", Fore.GREEN)
        self._line(
            f"total={len(vulns)}  {self.ui['dot']} kritis={sev['KRITIS']}  {self.ui['dot']} tinggi={sev['TINGGI']}  {self.ui['dot']} sedang={sev['SEDANG']}  {self.ui['dot']} rendah={sev['RENDAH']}",
            Fore.WHITE,
        )
        self._line(
            f"dapat_diakses={access['dapat_diakses']}  {self.ui['dot']} dialihkan={access['dialihkan']}  {self.ui['dot']} terlindungi={access['terlindungi'] + access['ditolak']}  {self.ui['dot']} tidak_ditemukan={access['tidak_ditemukan']}  {self.ui['dot']} error_server={access['error_server']}",
            Fore.WHITE,
        )
        self._border(top=False)
