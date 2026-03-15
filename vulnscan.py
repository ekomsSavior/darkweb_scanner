#!/usr/bin/env python3
"""
DarkWeb Vulnerability Scanner - INTERACTIVE CLI
"""

import cmd
import sys
import os
from datetime import datetime

# Import core modules
from core.tor_session import TorSession
from core.target_manager import TargetManager
from core.scan_engine import ScanEngine
from core.report_builder import ReportBuilder

# Import checks
from checks import (
    SecurityHeadersCheck,
    SensitiveFilesCheck,
    Com764Detector,
    FingerprintCheck,
    DirectoryListingCheck,
    SessionIDTracker,
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

class DarkWebScannerCLI(cmd.Cmd):
    prompt = f'{GREEN}vulnscan>{RESET} '
    
    def __init__(self):
        super().__init__()
        
        print(f"{YELLOW}[*] Initializing scanner...{RESET}")
        
        self.tor_session = TorSession()
        self.target_manager = TargetManager()
        self.report_builder = ReportBuilder()
        self.scan_engine = ScanEngine(
            self.tor_session,
            self.target_manager,
            self.report_builder
        )
        
        # Register checks
        checks = [
            SecurityHeadersCheck(),
            FingerprintCheck(),
            SensitiveFilesCheck(wordlist_path="wordlists/sensitive_paths.txt"),
            DirectoryListingCheck(),
            Com764Detector(wordlist_path="wordlists/com764_keywords.txt"),
            SessionIDTracker(),
        ]
        self.scan_engine.register_checks(checks)
        
        self.show_banner()
    
    def show_banner(self):
        print(f"""{MAGENTA}{BOLD}
╔════════════════════════════════════════════╗
║    DARKWEB VULNERABILITY SCANNER v1.0     ║
║         INTERACTIVE THREAT INTEL           ║
╚════════════════════════════════════════════╝{RESET}
        """)
    
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
        # Just add it, no validation
        self.target_manager.add_target(arg)
        print(f"{GREEN}[+] Added: {arg}{RESET}")
    
    def do_load(self, arg):
        """Load targets from file - usage: load <filename>"""
        if not arg:
            print(f"{RED}Error: Specify filename{RESET}")
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
    
    def do_checks(self, arg):
        """List all available checks"""
        print(f"\n{CYAN}Available checks:{RESET}")
        for i, check in enumerate(self.scan_engine.checks, 1):
            status = f"{GREEN}[ON]{RESET}" if check.enabled else f"{RED}[OFF]{RESET}"
            print(f"  {i}. {status} {check.name}")
            print(f"     {check.description}")
        print()
    
    def do_enable(self, arg):
        """Enable a check by number - usage: enable <number>"""
        try:
            idx = int(arg) - 1
            self.scan_engine.checks[idx].enabled = True
            print(f"{GREEN}[+] Enabled {self.scan_engine.checks[idx].name}{RESET}")
        except:
            print(f"{RED}Error: Invalid number{RESET}")
    
    def do_disable(self, arg):
        """Disable a check by number - usage: disable <number>"""
        try:
            idx = int(arg) - 1
            self.scan_engine.checks[idx].enabled = False
            print(f"{YELLOW}[-] Disabled {self.scan_engine.checks[idx].name}{RESET}")
        except:
            print(f"{RED}Error: Invalid number{RESET}")
    
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
            return
        key, value = args
        try:
            if key in ['delay', 'threads', 'timeout']:
                value = int(value)
            self.scan_engine.set_config(**{key: value})
            print(f"{GREEN}[+] {key} = {value}{RESET}")
        except:
            print(f"{RED}Error setting {key}{RESET}")
    
    def do_scan(self, arg):
        """Start scanning all targets"""
        if self.target_manager.get_count() == 0:
            print(f"{RED}Error: No targets loaded{RESET}")
            return
        
        print(f"\n{YELLOW}Ready to scan {self.target_manager.get_count()} targets{RESET}")
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
    
    def do_report(self, arg):
        """Generate report - usage: report [json|text|csv]"""
        if not arg:
            arg = 'text'
        
        if arg == 'json':
            self.report_builder.export_json()
        elif arg == 'text':
            self.report_builder.export_text()
        elif arg == 'csv':
            self.report_builder.export_csv()
        else:
            print(f"{RED}Error: Use json, text, or csv{RESET}")
    
    def do_clear(self, arg):
        """Clear all targets"""
        confirm = input(f"{YELLOW}Clear all targets? (y/n): {RESET}")
        if confirm.lower() == 'y':
            self.target_manager.clear()
            print(f"{GREEN}[+] All targets cleared{RESET}")
    
    def do_rotate(self, arg):
        """Rotate Tor circuit"""
        if self.tor_session.rotate_circuit():
            print(f"{GREEN}[+] Circuit rotated{RESET}")
        else:
            print(f"{RED}[-] Rotation failed{RESET}")
    
    def do_status(self, arg):
        """Show scanner status"""
        print(f"\n{CYAN}Scanner Status:{RESET}")
        print(f"  Targets: {self.target_manager.get_count()}")
        print(f"  Checks: {len(self.scan_engine.checks)}")
        print(f"  Tor circuits: {self.tor_session.circuit_count}")
        print()
    
    def do_help(self, arg):
        """Show available commands"""
        print(f"""
{CYAN}Available commands:{RESET}
  {GREEN}targets{RESET}          - Show loaded targets
  {GREEN}add <url>{RESET}        - Add a target
  {GREEN}load <file>{RESET}      - Load targets from file
  {GREEN}remove <n>{RESET}       - Remove target by number
  {GREEN}checks{RESET}           - List available checks
  {GREEN}enable <n>{RESET}       - Enable a check
  {GREEN}disable <n>{RESET}      - Disable a check
  {GREEN}config{RESET}           - Show configuration
  {GREEN}set <key> <val>{RESET}  - Set config value
  {GREEN}scan{RESET}             - Start scanning
  {GREEN}report [fmt]{RESET}     - Generate report (text/json/csv)
  {GREEN}clear{RESET}            - Clear all targets
  {GREEN}rotate{RESET}           - Rotate Tor circuit
  {GREEN}status{RESET}           - Show scanner status
  {GREEN}exit{RESET}             - Exit scanner
        """)
    
    def do_exit(self, arg):
        """Exit the scanner"""
        print(f"{YELLOW}Shutting down...{RESET}")
        self.tor_session.close()
        print(f"{GREEN}Goodbye!{RESET}")
        return True
    
    def do_quit(self, arg):
        """Exit the scanner"""
        return self.do_exit(arg)
    
    def default(self, line):
        print(f"{RED}Unknown command: {line}{RESET}")
        print(f"{CYAN}Type 'help' for available commands{RESET}")

if __name__ == '__main__':
    try:
        DarkWebScannerCLI().cmdloop()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Interrupted{RESET}")
