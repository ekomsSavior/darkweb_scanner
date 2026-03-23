#!/usr/bin/env python3
"""
DarkWeb Vulnerability Scanner - Lite Edition (6 checks)

Stripped-down version of the full scanner for quick recon.
Only includes: security headers, fingerprinting, sensitive files,
directory listing, Com764 detection, and session ID tracking.
"""

import cmd
import csv
import json
import os
import re

from config.logging_config import setup_logging
from config.settings import REPORT_DIR
from core.tor_session import TorSession
from core.target_manager import TargetManager
from core.scan_engine import ScanEngine
from core.report_builder import ReportBuilder
from checks import (
    SecurityHeadersCheck,
    SensitiveFilesCheck,
    Com764Detector,
    FingerprintCheck,
    DirectoryListingCheck,
    SessionIDTracker,
)

setup_logging()

LITE_CHECKS = [
    SecurityHeadersCheck,
    FingerprintCheck,
    lambda: SensitiveFilesCheck(wordlist_path="wordlists/sensitive_paths.txt"),
    DirectoryListingCheck,
    lambda: Com764Detector(wordlist_path="wordlists/com764_keywords.txt"),
    SessionIDTracker,
]

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{MAGENTA}{BOLD}
 DARKWEB SCANNER LITE (6 checks)
{RESET}"""


def _build_checks():
    checks = []
    for factory in LITE_CHECKS:
        checks.append(factory() if callable(factory) and not isinstance(factory, type) else factory())
    return checks


class LiteCLI(cmd.Cmd):
    prompt = f"{GREEN}lite>{RESET} "

    def __init__(self):
        super().__init__()
        print(f"{YELLOW}[*] Initializing lite scanner...{RESET}")
        self.tor_session = TorSession()
        self.target_manager = TargetManager()
        self.report_builder = ReportBuilder(report_dir=REPORT_DIR)
        self.scan_engine = ScanEngine(
            self.tor_session, self.target_manager, self.report_builder
        )
        self.scan_engine.register_checks(_build_checks())
        print(BANNER)

    # -- Target management --

    def do_targets(self, arg):
        """Show all loaded targets"""
        targets = self.target_manager.get_targets()
        if not targets:
            print(f"{YELLOW}No targets loaded{RESET}")
            return
        for i, target in enumerate(targets, 1):
            print(f"  {i}. {target}")

    def do_add(self, arg):
        """Add a target - usage: add <url>"""
        if not arg:
            print(f"{RED}Usage: add <url>{RESET}")
            return
        self.target_manager.add_target(arg.strip())
        print(f"{GREEN}[+] Added: {arg.strip()}{RESET}")

    def do_load(self, arg):
        """Load targets from a text file (one per line)"""
        if not arg or not os.path.exists(arg):
            print(f"{RED}Usage: load <file>  (file not found){RESET}")
            return
        self.target_manager.load_from_file(arg)
        print(f"{GREEN}[+] {self.target_manager.get_count()} targets loaded{RESET}")

    def do_upload(self, arg):
        """Load targets from JSON or CSV file (auto-detect by extension)"""
        if not arg or not os.path.exists(arg):
            print(f"{RED}Usage: upload <file.json|file.csv>{RESET}")
            return
        try:
            if arg.endswith(".json"):
                self._load_json(arg)
            elif arg.endswith(".csv"):
                self._load_csv(arg)
            else:
                print(f"{RED}Unsupported format. Use .json or .csv{RESET}")
                return
            print(f"{GREEN}[+] {self.target_manager.get_count()} targets loaded from {arg}{RESET}")
        except Exception as exc:
            print(f"{RED}Error: {exc}{RESET}")

    def _load_json(self, path):
        with open(path) as fh:
            data = json.load(fh)
        urls = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    urls.append(item)
                elif isinstance(item, dict):
                    urls.append(item.get("url") or item.get("domain") or item.get("onion", ""))
        elif isinstance(data, dict):
            for key in ("urls", "targets", "domains", "sites", "onions"):
                if key in data and isinstance(data[key], list):
                    urls.extend(str(u) for u in data[key] if u)
                    break
            else:
                urls = [f"http://{m}" for m in re.findall(r"[a-z2-7]{56}\.onion", json.dumps(data))]
        for url in urls:
            if url and url.strip():
                self.target_manager.add_target(url.strip())

    def _load_csv(self, path):
        with open(path) as fh:
            for row in csv.reader(fh):
                if row and row[0].strip() and not row[0].startswith("#"):
                    self.target_manager.add_target(row[0].strip())

    def do_remove(self, arg):
        """Remove target by number"""
        try:
            idx = int(arg) - 1
            targets = self.target_manager.get_targets()
            if 0 <= idx < len(targets):
                self.target_manager.remove_target(targets[idx])
                print(f"{GREEN}[+] Removed{RESET}")
            else:
                print(f"{RED}Invalid number{RESET}")
        except (ValueError, IndexError):
            print(f"{RED}Usage: remove <number>{RESET}")

    def do_clear(self, arg):
        """Clear all targets"""
        self.target_manager.clear()
        print(f"{GREEN}[+] Cleared{RESET}")

    # -- Check management --

    def do_checks(self, arg):
        """List available checks"""
        for i, check in enumerate(self.scan_engine.checks, 1):
            status = f"{GREEN}ON{RESET}" if check.enabled else f"{RED}OFF{RESET}"
            print(f"  {i}. [{status}] {check.name}")

    def do_enable(self, arg):
        """Enable a check by number or 'all'"""
        if arg.lower() == "all":
            for check in self.scan_engine.checks:
                check.enabled = True
            print(f"{GREEN}[+] All enabled{RESET}")
            return
        try:
            self.scan_engine.checks[int(arg) - 1].enabled = True
            print(f"{GREEN}[+] Enabled{RESET}")
        except (ValueError, IndexError):
            print(f"{RED}Usage: enable <number|all>{RESET}")

    def do_disable(self, arg):
        """Disable a check by number or 'all'"""
        if arg.lower() == "all":
            for check in self.scan_engine.checks:
                check.enabled = False
            print(f"{YELLOW}[-] All disabled{RESET}")
            return
        try:
            self.scan_engine.checks[int(arg) - 1].enabled = False
            print(f"{YELLOW}[-] Disabled{RESET}")
        except (ValueError, IndexError):
            print(f"{RED}Usage: disable <number|all>{RESET}")

    # -- Config --

    def do_config(self, arg):
        """Show scan configuration"""
        for key, value in self.scan_engine.scan_config.items():
            print(f"  {key}: {value}")

    def do_set(self, arg):
        """Set config value - usage: set <key> <value>"""
        parts = arg.split()
        if len(parts) != 2:
            print(f"{RED}Usage: set <key> <value>{RESET}")
            return
        key, value = parts
        try:
            if key in ("delay", "threads", "timeout", "rotate_circuit_every", "max_depth"):
                value = int(value)
            elif key in ("follow_redirects", "check_https", "verify_ssl"):
                value = value.lower() in ("true", "1", "yes")
            self.scan_engine.set_config(**{key: value})
            print(f"{GREEN}[+] {key} = {value}{RESET}")
        except (ValueError, TypeError, KeyError):
            print(f"{RED}Error setting {key}{RESET}")

    # -- Scanning --

    def do_scan(self, arg):
        """Scan all loaded targets"""
        if self.target_manager.get_count() == 0:
            print(f"{RED}No targets loaded{RESET}")
            return
        self.report_builder.start_scan()
        self.scan_engine.scan_all()
        self.report_builder.end_scan()
        summary = self.report_builder.get_summary()
        print(f"\n{GREEN}[+] Done - {summary['total_findings']} findings across {summary['targets_with_findings']} targets{RESET}")

    def do_report(self, arg):
        """Generate report - usage: report [json|text|csv|md|all]"""
        fmt = arg.strip().lower() or "text"
        exporters = {
            "json": self.report_builder.export_json,
            "text": self.report_builder.export_text,
            "csv": self.report_builder.export_csv,
            "md": self.report_builder.export_markdown,
        }
        if fmt == "all":
            for fn in exporters.values():
                fn()
        elif fmt in exporters:
            exporters[fmt]()
        else:
            print(f"{RED}Formats: json, text, csv, md, all{RESET}")

    # -- Misc --

    def do_rotate(self, arg):
        """Rotate Tor circuit"""
        ok = self.tor_session.rotate_circuit()
        print(f"{GREEN}[+] Rotated{RESET}" if ok else f"{RED}[-] Failed{RESET}")

    def do_status(self, arg):
        """Show scanner status"""
        print(f"  Targets : {self.target_manager.get_count()}")
        print(f"  Checks  : {len(self.scan_engine.checks)}")
        print(f"  Requests: {self.tor_session.circuit_count}")

    def do_exit(self, arg):
        """Exit"""
        self.tor_session.close()
        return True

    do_quit = do_exit

    def default(self, line):
        print(f"{RED}Unknown: {line}. Type help.{RESET}")


if __name__ == "__main__":
    try:
        LiteCLI().cmdloop()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Bye{RESET}")
