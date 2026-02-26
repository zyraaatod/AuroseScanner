import json
import shutil
import sys
from datetime import datetime

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
        self.term_width = max(76, min(120, shutil.get_terminal_size((100, 24)).columns))
        self.inner_width = self.term_width - 4
        encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
        self.use_unicode = "utf" in encoding
        self.ui = (
            {"h": "─", "v": "│", "tl": "┌", "tr": "┐", "bl": "└", "br": "┘", "dot": "•"}
            if self.use_unicode
            else {"h": "-", "v": "|", "tl": "+", "tr": "+", "bl": "+", "br": "+", "dot": "-"}
        )

    def _border(self, top=True):
        left = self.ui["tl"] if top else self.ui["bl"]
        right = self.ui["tr"] if top else self.ui["br"]
        print(f"{Fore.CYAN}{left}{self.ui['h'] * (self.term_width - 2)}{right}{Style.RESET_ALL}")

    def _line(self, text, color=Fore.WHITE):
        if len(text) > self.inner_width:
            text = text[: self.inner_width - 1] + "..."
        print(f"{color}{self.ui['v']} {text:<{self.inner_width}} {self.ui['v']}{Style.RESET_ALL}")

    def generate(self, target, vulns, start, end):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"{self.report_dir}/scan_{ts}.json"
        report = {
            "target": target,
            "scan_start": start,
            "scan_end": end,
            "duration": end - start,
            "total": len(vulns),
            "vulnerabilities": vulns,
        }
        with open(fname, "w") as f:
            json.dump(report, f, indent=2)
        return fname

    def summary(self, vulns):
        if not vulns:
            print(f"{Fore.GREEN}[OK] No vulnerabilities found!{Style.RESET_ALL}")
            return

        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for v in vulns:
            sev[v["severity"]] = sev.get(v["severity"], 0) + 1

        print()
        self._border(top=True)
        self._line("VULNERABILITY SUMMARY", Fore.CYAN)
        self._line(
            f"total={len(vulns)}  {self.ui['dot']} critical={sev['CRITICAL']}  {self.ui['dot']} high={sev['HIGH']}  {self.ui['dot']} medium={sev['MEDIUM']}  {self.ui['dot']} low={sev['LOW']}",
            Fore.WHITE,
        )
        self._border(top=False)
