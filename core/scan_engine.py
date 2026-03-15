from typing import List, Dict, Any
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from core.tor_session import TorSession
from checks.base_check import BaseCheck

logger = logging.getLogger(__name__)

class ScanEngine:
    def __init__(self, tor_session, target_manager, report_builder):
        self.tor_session = tor_session
        self.target_manager = target_manager
        self.report_builder = report_builder
        self.checks = []
        self.scan_config = {
            'delay': 1,
            'threads': 1,
            'timeout': 15,
            'rotate_circuit_every': 10,
            'max_depth': 1,
            'follow_redirects': True
        }
        self.stats = {
            'targets_scanned': 0,
            'checks_run': 0,
            'findings_count': 0,
            'start_time': None,
            'end_time': None
        }
        self.scan_in_progress = False
        self.results = {}
        
    def register_check(self, check: 'BaseCheck'):
        """Register a vulnerability check"""
        self.checks.append(check)
        logger.info(f"Registered check: {check.name}")
    
    def register_checks(self, checks: list):
        """Register multiple checks"""
        self.checks.extend(checks)
        logger.info(f"Registered {len(checks)} checks")
    
    def scan_target(self, target: str) -> Dict[str, Any]:
        """Scan a single target with all registered checks"""
        findings = []
        
        print(f"\n[*] Scanning: {target}")
        
        for check in self.checks:
            if hasattr(check, 'enabled') and not check.enabled:
                continue
                
            try:
                print(f"  └─ Running {check.name}...")
                
                if self.scan_config['delay'] > 0:
                    time.sleep(self.scan_config['delay'])
                
                check_findings = check.run(target, self.tor_session, config=self.scan_config)
                
                if check_findings:
                    findings.extend(check_findings)
                    for f in check_findings:
                        severity = f.get('severity', 'info').upper()
                        print(f"    [{severity}] {f.get('finding', 'No details')}")
                
                self.stats['checks_run'] += 1
                logger.info(f"{check.name} completed on {target}")
                
            except Exception as e:
                logger.error(f"Check {check.name} failed on {target}: {e}")
                findings.append({
                    'check': check.name,
                    'severity': 'error',
                    'finding': f"Check failed: {str(e)}"
                })
        
        # Add findings to report builder
        self.report_builder.add_findings(target, findings)
        
        self.stats['targets_scanned'] += 1
        self.stats['findings_count'] += len(findings)
        
        return {
            'target': target,
            'timestamp': time.time(),
            'findings': findings
        }
    
    def scan_all(self):
        """Scan all targets from target manager - NO PARAMETERS NEEDED"""
        self.scan_in_progress = True
        self.stats['start_time'] = time.time()
        
        targets = self.target_manager.get_targets()
        if not targets:
            print("[!] No targets to scan")
            self.scan_in_progress = False
            return {}
        
        print(f"\n[*] Starting scan of {len(targets)} targets")
        print(f"[*] Configuration: {self.scan_config}")
        
        self.results = {
            'scan_id': int(time.time()),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'targets_scanned': len(targets),
            'results': {}
        }
        
        # Sequential scan (threads=1)
        for target in targets:
            if not self.scan_in_progress:
                print("[!] Scan stopped by user")
                break
            result = self.scan_target(target)
            self.results['results'][target] = result
        
        self.stats['end_time'] = time.time()
        duration = self.stats['end_time'] - self.stats['start_time']
        
        print(f"\n[+] Scan complete!")
        print(f"    Targets scanned: {self.stats['targets_scanned']}")
        print(f"    Checks run: {self.stats['checks_run']}")
        print(f"    Findings: {self.stats['findings_count']}")
        print(f"    Duration: {duration:.2f} seconds")
        
        self.scan_in_progress = False
        return self.results
    
    def scan_all_parallel(self, max_workers: int = 5):
        """Scan all targets in parallel (use with caution)"""
        self.scan_in_progress = True
        self.stats['start_time'] = time.time()
        
        targets = self.target_manager.get_targets()
        if not targets:
            print("[!] No targets to scan")
            self.scan_in_progress = False
            return {}
        
        print(f"\n[*] Starting PARALLEL scan of {len(targets)} targets with {max_workers} threads")
        print(f"[*] Configuration: {self.scan_config}")
        
        self.results = {
            'scan_id': int(time.time()),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'targets_scanned': len(targets),
            'results': {}
        }
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(self.scan_target, target): target for target in targets}
            for future in as_completed(future_to_target):
                if not self.scan_in_progress:
                    print("[!] Scan stopped by user")
                    executor.shutdown(wait=False)
                    break
                target = future_to_target[future]
                try:
                    result = future.result()
                    self.results['results'][target] = result
                except Exception as e:
                    logger.error(f"Scan failed for {target}: {e}")
        
        self.stats['end_time'] = time.time()
        duration = self.stats['end_time'] - self.stats['start_time']
        
        print(f"\n[+] Parallel scan complete!")
        print(f"    Targets scanned: {self.stats['targets_scanned']}")
        print(f"    Checks run: {self.stats['checks_run']}")
        print(f"    Findings: {self.stats['findings_count']}")
        print(f"    Duration: {duration:.2f} seconds")
        
        self.scan_in_progress = False
        return self.results
    
    def stop_scan(self):
        """Stop ongoing scan"""
        self.scan_in_progress = False
        logger.info("Scan stopped by user")
        print("[!] Scan stopping...")
