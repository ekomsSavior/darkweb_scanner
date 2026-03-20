#!/usr/bin/env python3
"""
DarkWeb Vulnerability Scanner v2.0 - INTERACTIVE CLI + BATCH MODE
"""

import cmd
import sys
import os
import argparse
from datetime import datetime

# Import config
from config.settings import TOR_PROXY_PORT, TOR_CONTROL_PORT, TOR_PASSWORD, DEFAULT_SCAN_CONFIG, REPORT_DIR

# Import core modules
from core.tor_session import TorSession
from core.target_manager import TargetManager
from core.scan_engine import ScanEngine
from core.report_builder import ReportBuilder

# Import checks
from checks import (
    SiteChecker,
    SecurityHeadersCheck,
    SensitiveFilesCheck,
    Com764Detector,
    FingerprintCheck,
    TechStackCheck,
    DirectoryListingCheck,
    SessionIDTracker,
    IdentityExtractorCheck,
    LinkCrawlerCheck,
    RobotsSitemapCheck,
    JSExtractorCheck,
    FormDetectorCheck,
    CookieAnalyzerCheck,
    WAFDetectorCheck,
    PageMetadataCheck,
    SSLAnalyzerCheck,
    HTTPMethodCheck,
    CORSCheck,
    OpenRedirectCheck,
    CloneDetectorCheck,
    PGPExtractorCheck,
)

# Colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

def build_checks():
    """Build and return all check instances — 21 checks"""
    return [
        SiteChecker(),
        CloneDetectorCheck(),
        PageMetadataCheck(),
        SecurityHeadersCheck(),
        SSLAnalyzerCheck(),
        FingerprintCheck(),
        TechStackCheck(),
        CookieAnalyzerCheck(),
        WAFDetectorCheck(),
        HTTPMethodCheck(),
        CORSCheck(),
        RobotsSitemapCheck(),
        SensitiveFilesCheck(wordlist_path="wordlists/sensitive_paths.txt"),
        DirectoryListingCheck(),
        OpenRedirectCheck(),
        FormDetectorCheck(),
        JSExtractorCheck(),
        LinkCrawlerCheck(),
        Com764Detector(wordlist_path="wordlists/com764_keywords.txt"),
        SessionIDTracker(),
        IdentityExtractorCheck(),
        PGPExtractorCheck(),
    ]


class DarkWebScannerCLI(cmd.Cmd):
    prompt = f'{GREEN}vulnscan>{RESET} '

    def __init__(self):
        super().__init__()

        print(f"{YELLOW}[*] Initializing scanner...{RESET}")

        self.tor_session = TorSession(
            proxy_port=TOR_PROXY_PORT,
            control_port=TOR_CONTROL_PORT,
            password=TOR_PASSWORD
        )
        self.target_manager = TargetManager()
        self.report_builder = ReportBuilder(report_dir=REPORT_DIR)
        self.scan_engine = ScanEngine(
            self.tor_session,
            self.target_manager,
            self.report_builder
        )

        self.scan_engine.register_checks(build_checks())

        self.show_banner()

        # Check for interrupted scans
        if self.scan_engine.has_interrupted_scan():
            info = self.scan_engine.get_interrupted_scan_info()
            print(f"{YELLOW}[!] Interrupted scan detected from {info['timestamp']}{RESET}")
            print(f"    {info['completed']}/{info['total']} targets completed, {info['remaining']} remaining")
            resume = input(f"{YELLOW}    Resume? (y/n): {RESET}")
            if resume.lower() == 'y':
                self.report_builder.start_scan()
                self.scan_engine.resume_scan()
                self.report_builder.end_scan()
                summary = self.report_builder.get_summary()
                print(f"\n{GREEN}[+] Resumed scan complete!{RESET}")
                print(f"  Targets with findings: {summary['targets_with_findings']}")
                print(f"  Total findings: {summary['total_findings']}")
            else:
                self.scan_engine.scan_state.clear()
                print(f"{YELLOW}    Interrupted scan discarded{RESET}")

    def show_banner(self):
        print(f"""{RED}
  ██▓ █    ██  ██▓     ███▄    █   ██████  ▄████▄   ▄▄▄       ███▄    █
 ▓██▒ ██  ▓██▒▓██▒     ██ ▀█   █ ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █
 ▒██▒▓██  ▒██░▒██░    ▓██  ▀█ ██▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
 ░██░▓▓█  ░██░▒██░    ▓██▒  ▐▌██▒  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
 ░██░▒▒█████▓ ░██████▒▒██░   ▓██░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
 ░▓  ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒
  ▒ ░░░▒░ ░ ░ ░ ░ ▒  ░░ ░░   ░ ▒░░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
  ▒ ░ ░░░ ░ ░   ░ ░      ░   ░ ░ ░  ░  ░  ░          ░   ▒      ░   ░ ░
  ░     ░         ░  ░         ░       ░  ░ ░              ░  ░         ░
                                          ░{RESET}
{CYAN}{BOLD}  ╔═══════════════════════════════════════════════════╗
  ║   DARKWEB VULNERABILITY SCANNER v2.0               ║
  ║   22 checks · crawler · batch mode · crash recovery  ║
  ╚═══════════════════════════════════════════════════════╝{RESET}
        """)

    # === Target management ===
    def do_targets(self, arg):
        """Show all loaded targets"""
        targets = self.target_manager.get_targets()
        if not targets:
            print(f"{YELLOW}No targets loaded{RESET}")
            return
        print(f"\n{CYAN}Loaded targets ({len(targets)}):{RESET}")
        for i, t in enumerate(targets, 1):
            print(f"  {i}. {t}")
        print()

    def do_add(self, arg):
        """Add a target - usage: add <url>"""
        if not arg:
            print(f"{RED}Error: Specify a URL{RESET}")
            return
        self.target_manager.add_target(arg)
        print(f"{GREEN}[+] Added: {arg}{RESET}")

    def do_load(self, arg):
        """Load targets from file - usage: load <filename>"""
        if not arg:
            print(f"{RED}Error: Specify filename{RESET}")
            return
        if not os.path.exists(arg):
            print(f"{RED}Error: File not found: {arg}{RESET}")
            return
        self.target_manager.load_from_file(arg)
        print(f"{GREEN}[+] Loaded {self.target_manager.get_count()} targets{RESET}")

    def do_remove(self, arg):
        """Remove target by number - usage: remove <number>"""
        try:
            idx = int(arg) - 1
            targets = self.target_manager.get_targets()
            if 0 <= idx < len(targets):
                target = targets[idx]
                self.target_manager.remove_target(target)
                print(f"{GREEN}[+] Removed target {arg}{RESET}")
            else:
                print(f"{RED}Error: Invalid number{RESET}")
        except:
            print(f"{RED}Error: Invalid number{RESET}")

    def do_clear(self, arg):
        """Clear all targets"""
        confirm = input(f"{YELLOW}Clear all targets? (y/n): {RESET}")
        if confirm.lower() == 'y':
            self.target_manager.clear()
            print(f"{GREEN}[+] All targets cleared{RESET}")

    # === Check management ===
    def do_checks(self, arg):
        """List all available checks"""
        print(f"\n{CYAN}Available checks ({len(self.scan_engine.checks)}):{RESET}")
        for i, check in enumerate(self.scan_engine.checks, 1):
            status = f"{GREEN}ON {RESET}" if check.enabled else f"{RED}OFF{RESET}"
            print(f"  {DIM}{i:2d}.{RESET} [{status}] {BOLD}{check.name}{RESET}")
            print(f"      {DIM}{check.description}{RESET}")
        print()

    def do_enable(self, arg):
        """Enable check(s) - usage: enable <n> or enable all"""
        if arg.lower() == 'all':
            for check in self.scan_engine.checks:
                check.enabled = True
            print(f"{GREEN}[+] All checks enabled{RESET}")
            return
        try:
            idx = int(arg) - 1
            self.scan_engine.checks[idx].enabled = True
            print(f"{GREEN}[+] Enabled {self.scan_engine.checks[idx].name}{RESET}")
        except:
            print(f"{RED}Error: Invalid number{RESET}")

    def do_disable(self, arg):
        """Disable check(s) - usage: disable <n> or disable all"""
        if arg.lower() == 'all':
            for check in self.scan_engine.checks:
                check.enabled = False
            print(f"{YELLOW}[-] All checks disabled{RESET}")
            return
        try:
            idx = int(arg) - 1
            self.scan_engine.checks[idx].enabled = False
            print(f"{YELLOW}[-] Disabled {self.scan_engine.checks[idx].name}{RESET}")
        except:
            print(f"{RED}Error: Invalid number{RESET}")

    def do_only(self, arg):
        """Enable ONLY specific checks - usage: only 1,5,7"""
        try:
            indices = [int(x.strip()) - 1 for x in arg.split(',')]
            for check in self.scan_engine.checks:
                check.enabled = False
            for idx in indices:
                if 0 <= idx < len(self.scan_engine.checks):
                    self.scan_engine.checks[idx].enabled = True
            enabled = [c.name for c in self.scan_engine.checks if c.enabled]
            print(f"{GREEN}[+] Enabled only: {', '.join(enabled)}{RESET}")
        except:
            print(f"{RED}Usage: only 1,5,7{RESET}")

    # === Configuration ===
    def do_config(self, arg):
        """Show current configuration"""
        print(f"\n{CYAN}Current configuration:{RESET}")
        for key, value in self.scan_engine.scan_config.items():
            print(f"  {key}: {value}")
        print()

    def do_set(self, arg):
        """Set config value - usage: set <key> <value>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{RED}Usage: set delay 2{RESET}")
            print(f"{DIM}Available keys: delay, threads, timeout, rotate_circuit_every, max_depth, follow_redirects{RESET}")
            return
        key, value = args
        try:
            if key in ['delay', 'threads', 'timeout', 'rotate_circuit_every', 'max_depth']:
                value = int(value)
            elif key in ['follow_redirects', 'check_https', 'verify_ssl']:
                value = value.lower() in ('true', '1', 'yes')
            self.scan_engine.set_config(**{key: value})
            print(f"{GREEN}[+] {key} = {value}{RESET}")
        except:
            print(f"{RED}Error setting {key}{RESET}")

    # === Scanning ===
    def do_scan(self, arg):
        """Start scanning all targets"""
        if self.target_manager.get_count() == 0:
            print(f"{RED}Error: No targets loaded{RESET}")
            return

        enabled_count = sum(1 for c in self.scan_engine.checks if c.enabled)
        print(f"\n{YELLOW}Ready to scan {self.target_manager.get_count()} targets with {enabled_count} checks{RESET}")
        confirm = input(f"{YELLOW}Start scan? (y/n): {RESET}")
        if confirm.lower() != 'y':
            print(f"{YELLOW}Scan cancelled{RESET}")
            return

        self.report_builder.start_scan()
        self.scan_engine.scan_all()
        self.report_builder.end_scan()

        summary = self.report_builder.get_summary()
        print(f"\n{GREEN}[+] Scan complete!{RESET}")
        print(f"  Targets with findings: {summary['targets_with_findings']}")
        print(f"  Total findings: {summary['total_findings']}")
        for sev, count in summary['severity_counts'].items():
            if count > 0:
                print(f"  {sev.capitalize()}: {count}")

    def do_quickscan(self, arg):
        """Quick scan a single target - usage: quickscan <url>"""
        if not arg:
            print(f"{RED}Usage: quickscan <url>{RESET}")
            return

        self.target_manager.clear()
        self.target_manager.add_target(arg)
        self.report_builder.clear()
        self.report_builder.start_scan()
        self.scan_engine.scan_all()
        self.report_builder.end_scan()

        summary = self.report_builder.get_summary()
        print(f"\n{GREEN}[+] Quick scan complete: {summary['total_findings']} findings{RESET}")

    def do_resume(self, arg):
        """Resume an interrupted scan"""
        if not self.scan_engine.has_interrupted_scan():
            print(f"{YELLOW}No interrupted scan to resume{RESET}")
            return

        info = self.scan_engine.get_interrupted_scan_info()
        print(f"\n{CYAN}Interrupted scan: {info['completed']}/{info['total']} targets done{RESET}")
        confirm = input(f"{YELLOW}Resume? (y/n): {RESET}")
        if confirm.lower() != 'y':
            discard = input(f"{YELLOW}Discard interrupted scan? (y/n): {RESET}")
            if discard.lower() == 'y':
                self.scan_engine.scan_state.clear()
                print(f"{GREEN}[+] Interrupted scan discarded{RESET}")
            return

        self.report_builder.start_scan()
        self.scan_engine.resume_scan()
        self.report_builder.end_scan()

        summary = self.report_builder.get_summary()
        print(f"\n{GREEN}[+] Resumed scan complete!{RESET}")
        print(f"  Targets with findings: {summary['targets_with_findings']}")
        print(f"  Total findings: {summary['total_findings']}")

    # === Reporting ===
    def do_report(self, arg):
        """Generate report - usage: report [json|text|csv|md|all]"""
        if not arg:
            arg = 'md'

        if arg == 'all':
            self.report_builder.export_json()
            self.report_builder.export_text()
            self.report_builder.export_csv()
            self.report_builder.export_markdown()
        elif arg == 'json':
            self.report_builder.export_json()
        elif arg == 'text':
            self.report_builder.export_text()
        elif arg == 'csv':
            self.report_builder.export_csv()
        elif arg in ('md', 'markdown'):
            self.report_builder.export_markdown()
        else:
            print(f"{RED}Error: Use json, text, csv, md, or all{RESET}")

    def do_identifiers(self, arg):
        """Show all extracted identifiers across scanned targets"""
        found_any = False
        for check in self.scan_engine.checks:
            if hasattr(check, 'get_all_identifiers'):
                ids = check.get_all_identifiers()
                if not ids:
                    continue
                found_any = True
                print(f"\n{CYAN}Extracted Identifiers:{RESET}")
                for id_type, values in ids.items():
                    display = id_type.replace('_', ' ').title()
                    print(f"\n  {GREEN}{display} ({len(values)}):{RESET}")
                    for value, urls in values.items():
                        cross = f" {RED}[CROSS-SITE: {len(urls)} sites]{RESET}" if len(urls) > 1 else ""
                        print(f"    {value[:60]}{cross}")

            if hasattr(check, 'get_cross_site_report'):
                report = check.get_cross_site_report()
                if report:
                    found_any = True
                    print(f"\n{CYAN}Cross-site Session IDs:{RESET}")
                    for sid, urls in report.items():
                        print(f"  {sid[:20]}... -> {', '.join(urls)}")

            if hasattr(check, 'get_all_onions'):
                onions = check.get_all_onions()
                if onions:
                    found_any = True
                    print(f"\n{CYAN}Discovered .onion domains ({len(onions)}):{RESET}")
                    for onion in sorted(onions):
                        print(f"  {onion}")

        if not found_any:
            print(f"{YELLOW}No identifiers extracted yet. Run a scan first.{RESET}")

    # === OPSEC ===
    def do_rotate(self, arg):
        """Rotate Tor circuit"""
        if self.tor_session.rotate_circuit():
            print(f"{GREEN}[+] Circuit rotated (new IP){RESET}")
        else:
            print(f"{RED}[-] Rotation failed — controller not available{RESET}")

    def do_status(self, arg):
        """Show scanner status"""
        enabled = sum(1 for c in self.scan_engine.checks if c.enabled)
        total = len(self.scan_engine.checks)
        print(f"\n{CYAN}Scanner Status:{RESET}")
        print(f"  Targets loaded: {self.target_manager.get_count()}")
        print(f"  Checks: {enabled}/{total} enabled")
        print(f"  Tor circuits used: {self.tor_session.circuit_count}")
        print(f"  Tor controller: {'connected' if self.tor_session.tor_available else 'not available'}")
        if self.scan_engine.has_interrupted_scan():
            info = self.scan_engine.get_interrupted_scan_info()
            print(f"  {YELLOW}Interrupted scan: {info['remaining']} targets remaining{RESET}")
        if self.report_builder.findings:
            summary = self.report_builder.get_summary()
            print(f"  Findings in memory: {summary['total_findings']}")
        print()

    # === Help ===
    def do_help(self, arg):
        """Show available commands"""
        print(f"""
{CYAN}{BOLD}Target Management:{RESET}
  {GREEN}targets{RESET}             Show loaded targets
  {GREEN}add <url>{RESET}           Add a target
  {GREEN}load <file>{RESET}         Load targets from file
  {GREEN}remove <n>{RESET}          Remove target by number
  {GREEN}clear{RESET}               Clear all targets

{CYAN}{BOLD}Check Control:{RESET}
  {GREEN}checks{RESET}              List all checks with status
  {GREEN}enable <n|all>{RESET}      Enable check(s)
  {GREEN}disable <n|all>{RESET}     Disable check(s)
  {GREEN}only <1,5,7>{RESET}        Enable ONLY listed checks

{CYAN}{BOLD}Configuration:{RESET}
  {GREEN}config{RESET}              Show configuration
  {GREEN}set <key> <val>{RESET}     Set config value

{CYAN}{BOLD}Scanning:{RESET}
  {GREEN}scan{RESET}                Scan all targets
  {GREEN}quickscan <url>{RESET}     Quick scan a single target
  {GREEN}resume{RESET}              Resume interrupted scan

{CYAN}{BOLD}Reports & Intel:{RESET}
  {GREEN}report [fmt]{RESET}        Generate report (json/text/csv/md/all)
  {GREEN}identifiers{RESET}         Show extracted identifiers

{CYAN}{BOLD}OPSEC:{RESET}
  {GREEN}rotate{RESET}              Rotate Tor circuit
  {GREEN}status{RESET}              Show scanner status

{CYAN}{BOLD}General:{RESET}
  {GREEN}exit{RESET}                Exit scanner
        """)

    def do_exit(self, arg):
        """Exit the scanner"""
        print(f"{YELLOW}Shutting down...{RESET}")
        self.tor_session.close()
        print(f"{GREEN}Goodbye!{RESET}")
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)

    def default(self, line):
        print(f"{RED}Unknown command: {line}{RESET}")
        print(f"{CYAN}Type 'help' for available commands{RESET}")


def run_batch(args):
    """Run scanner in non-interactive batch mode"""
    print(f"{YELLOW}[*] Batch mode — initializing...{RESET}")

    tor = TorSession(proxy_port=TOR_PROXY_PORT, control_port=TOR_CONTROL_PORT, password=TOR_PASSWORD)
    tm = TargetManager()
    rb = ReportBuilder(report_dir=REPORT_DIR)
    engine = ScanEngine(tor, tm, rb)
    engine.register_checks(build_checks())

    # Load targets
    if args.targets:
        tm.load_from_file(args.targets)
    elif args.target:
        tm.add_target(args.target)

    if tm.get_count() == 0:
        print(f"{RED}[-] No targets loaded{RESET}")
        sys.exit(1)

    # Apply config
    if args.depth:
        engine.set_config(max_depth=args.depth)
    if args.delay:
        engine.set_config(delay=args.delay)
    if args.timeout:
        engine.set_config(timeout=args.timeout)

    print(f"{GREEN}[+] Loaded {tm.get_count()} targets{RESET}")
    print(f"{GREEN}[+] {sum(1 for c in engine.checks if c.enabled)} checks enabled{RESET}")

    # Scan
    rb.start_scan()
    engine.scan_all()
    rb.end_scan()

    # Report
    formats = args.report.split(',') if args.report else ['json', 'md']
    for fmt in formats:
        fmt = fmt.strip()
        if fmt == 'json':
            rb.export_json()
        elif fmt == 'text':
            rb.export_text()
        elif fmt == 'csv':
            rb.export_csv()
        elif fmt in ('md', 'markdown'):
            rb.export_markdown()
        elif fmt == 'all':
            rb.export_json()
            rb.export_text()
            rb.export_csv()
            rb.export_markdown()

    summary = rb.get_summary()
    print(f"\n{GREEN}[+] Batch scan complete: {summary['total_findings']} findings across {summary['targets_with_findings']} targets{RESET}")

    tor.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DarkWeb Vulnerability Scanner v2.0')
    parser.add_argument('-t', '--target', help='Single target URL')
    parser.add_argument('-T', '--targets', help='Target list file')
    parser.add_argument('-d', '--depth', type=int, help='Crawl depth (default: 1)')
    parser.add_argument('--delay', type=int, help='Delay between requests in seconds')
    parser.add_argument('--timeout', type=int, help='Request timeout in seconds')
    parser.add_argument('-r', '--report', default='json,md', help='Report format(s): json,text,csv,md,all')
    parser.add_argument('--batch', action='store_true', help='Run in non-interactive batch mode')

    args = parser.parse_args()

    # If any batch arguments provided, run batch mode
    if args.batch or args.target or args.targets:
        try:
            run_batch(args)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Interrupted{RESET}")
    else:
        try:
            DarkWebScannerCLI().cmdloop()
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Interrupted{RESET}")
