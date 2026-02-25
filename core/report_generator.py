import json
from datetime import datetime

try:
    from tabulate import tabulate
except ImportError:
    def tabulate(rows, headers=None, tablefmt=None):
        head = " | ".join(headers) if headers else ""
        body = "\n".join(" | ".join(str(c) for c in r) for r in rows)
        return f"{head}\n{body}" if head else body

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

        print(f"\n{Fore.CYAN}+{'-'*60}+{Style.RESET_ALL}")
        print(f"{Fore.CYAN}|{Fore.WHITE} VULNERABILITY SUMMARY {' '*38}{Fore.CYAN}|{Style.RESET_ALL}")
        print(f"{Fore.CYAN}+{'-'*60}+{Style.RESET_ALL}")
        tbl = [
            [f"{Fore.RED}CRITICAL{Style.RESET_ALL}", sev["CRITICAL"]],
            [f"{Fore.YELLOW}HIGH{Style.RESET_ALL}", sev["HIGH"]],
            [f"{Fore.BLUE}MEDIUM{Style.RESET_ALL}", sev["MEDIUM"]],
            [f"{Fore.GREEN}LOW{Style.RESET_ALL}", sev["LOW"]],
        ]
        print(tabulate(tbl, headers=["Severity", "Count"], tablefmt="grid"))
        print(f"{Fore.CYAN}+{'-'*60}+{Style.RESET_ALL}")
