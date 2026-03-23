from typing import Dict, Any
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from checks.base_check import BaseCheck
from config.settings import DEFAULT_SCAN_CONFIG
from core.scan_state import ScanState

logger = logging.getLogger(__name__)

class ScanEngine:
    def __init__(self, tor_session, target_manager, report_builder):
        self.tor_session = tor_session
        self.target_manager = target_manager
        self.report_builder = report_builder
        self.checks = []
        self.scan_config = dict(DEFAULT_SCAN_CONFIG)
        self.stats = {
            'targets_scanned': 0,
            'checks_run': 0,
            'findings_count': 0,
            'start_time': None,
            'end_time': None
        }
        self.scan_in_progress = False
        self.results = {}
        self.scan_state = ScanState()
        # FIX: Lock for thread-safe access to shared state during parallel scans.
        # Without this, scan_all_parallel() corrupts self.stats, self.results,
        # and report_builder.findings because multiple threads write concurrently.
        self._lock = threading.Lock()

    def register_check(self, check: 'BaseCheck'):
        """Register a vulnerability check"""
        self.checks.append(check)
        logger.info(f"Registered check: {check.name}")

    def register_checks(self, checks: list):
        """Register multiple checks"""
        self.checks.extend(checks)
        logger.info(f"Registered {len(checks)} checks")

    def set_config(self, **kwargs):
        """Update scan configuration values"""
        for key, value in kwargs.items():
            if key in self.scan_config:
                self.scan_config[key] = value
                logger.info(f"Config updated: {key} = {value}")
            else:
                logger.warning(f"Unknown config key: {key}")

    def has_interrupted_scan(self):
        """Check if there's an interrupted scan to resume"""
        return self.scan_state.has_pending()

    def get_interrupted_scan_info(self):
        """Get info about the interrupted scan"""
        state = self.scan_state.load()
        if state:
            return {
                'scan_id': state.get('scan_id'),
                'timestamp': state.get('timestamp'),
                'completed': len(state.get('completed_targets', [])),
                'remaining': len(state.get('remaining_targets', [])),
                'total': len(state.get('all_targets', []))
            }
        return None

    def resume_scan(self):
        """Resume an interrupted scan"""
        state = self.scan_state.load()
        if not state:
            print("[!] No interrupted scan to resume")
            return {}

        remaining = state.get('remaining_targets', [])
        completed = state.get('completed_targets', [])
        all_targets = state.get('all_targets', [])

        print(f"\n[*] Resuming scan {state.get('scan_id')}")
        print(f"[*] {len(completed)} already done, {len(remaining)} remaining")

        # Restore previous findings into report builder
        prev_findings = state.get('findings', {})
        for target, findings in prev_findings.items():
            self.report_builder.add_findings(target, findings)

        self.scan_in_progress = True
        self.stats['start_time'] = time.time()

        self.results = {
            'scan_id': state.get('scan_id', int(time.time())),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'targets_scanned': len(all_targets),
            'results': {}
        }

        for target in remaining:
            if not self.scan_in_progress:
                print("[!] Scan stopped by user")
                break
            result = self.scan_target(target)
            self.results['results'][target] = result
            completed.append(target)

            # Save state after each target
            self.scan_state.save(
                self.results['scan_id'],
                all_targets,
                completed,
                self.report_builder.findings,
                self.scan_config
            )

        self.stats['end_time'] = time.time()
        duration = self.stats['end_time'] - self.stats['start_time']

        print("\n[+] Resumed scan complete!")
        print(f"    Targets scanned: {self.stats['targets_scanned']}")
        print(f"    Checks run: {self.stats['checks_run']}")
        print(f"    Findings: {self.stats['findings_count']}")
        print(f"    Duration: {duration:.2f} seconds")

        self.scan_state.clear()
        self.scan_in_progress = False
        return self.results

    def _check_rate_limit(self, target, tor_session):
        """Detect if the target is rate-limiting or blocking us"""
        url = target if target.startswith('http') else 'http://' + target
        timeout = self.scan_config.get('timeout', 15)

        resp = tor_session.get(url, timeout=timeout)
        if not resp:
            return 'unreachable'

        # Common rate limit / block indicators
        if resp.status_code == 429:
            retry_after = resp.headers.get('Retry-After', 'unknown')
            print(f"    \033[93m[!] RATE LIMITED (429) — Retry-After: {retry_after}\033[0m")
            return 'rate_limited'

        if resp.status_code == 403:
            block_sigs = ['blocked', 'forbidden', 'access denied', 'ban',
                           'captcha', 'challenge', 'cloudflare', 'ddos-guard']
            if resp.text and any(sig in resp.text.lower() for sig in block_sigs):
                print("    \033[91m[!] BLOCKED (403 with block signature)\033[0m")
                return 'blocked'

        if resp.status_code == 503:
            if resp.text and ('captcha' in resp.text.lower() or 'challenge' in resp.text.lower()):
                print("    \033[93m[!] CAPTCHA/CHALLENGE detected (503)\033[0m")
                return 'captcha'

        return 'ok'

    def scan_target(self, target: str) -> Dict[str, Any]:
        """Scan a single target with all registered checks"""
        findings = []

        print(f"\n[*] Scanning: {target}")

        # Pre-scan rate limit check
        status = self._check_rate_limit(target, self.tor_session)
        if status == 'unreachable':
            print("    \033[91m[!] Target unreachable — skipping\033[0m")
            findings.append({
                'check': 'Rate Limit Detection',
                'severity': 'error',
                'finding': 'Target unreachable',
                'detail': 'Could not connect to target before scan started',
                'url': target
            })
            self.report_builder.add_findings(target, findings)
            self.stats['targets_scanned'] += 1
            return {'target': target, 'timestamp': time.time(), 'findings': findings}

        if status == 'rate_limited':
            print("    \033[93m[!] Rate limited — rotating circuit and waiting 15s...\033[0m")
            self.tor_session.rotate_circuit()
            time.sleep(15)
            findings.append({
                'check': 'Rate Limit Detection',
                'severity': 'high',
                'finding': 'Target rate-limiting detected (429)',
                'detail': 'Rotated Tor circuit and paused before continuing',
                'url': target
            })

        if status == 'blocked':
            print("    \033[91m[!] Blocked — rotating circuit...\033[0m")
            self.tor_session.rotate_circuit()
            time.sleep(10)
            findings.append({
                'check': 'Rate Limit Detection',
                'severity': 'critical',
                'finding': 'Target actively blocking scanner (403 + block signature)',
                'detail': 'Rotated Tor circuit — subsequent checks may fail',
                'url': target
            })

        if status == 'captcha':
            findings.append({
                'check': 'Rate Limit Detection',
                'severity': 'high',
                'finding': 'CAPTCHA/challenge page detected (503)',
                'detail': 'Target requires human verification — automated scanning limited',
                'url': target
            })

        consecutive_failures = 0

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
                    consecutive_failures = 0
                else:
                    consecutive_failures = 0

                self.stats['checks_run'] += 1
                logger.info(f"{check.name} completed on {target}")

            except Exception as e:
                logger.error(f"Check {check.name} failed on {target}: {e}")
                findings.append({
                    'check': check.name,
                    'severity': 'error',
                    'finding': f"Check failed: {str(e)}"
                })
                consecutive_failures += 1

                # If 3+ checks fail in a row, we're probably being blocked
                if consecutive_failures >= 3:
                    print("    \033[91m[!] 3+ consecutive failures — target may be blocking. Rotating circuit.\033[0m")
                    self.tor_session.rotate_circuit()
                    time.sleep(10)
                    consecutive_failures = 0
                    findings.append({
                        'check': 'Rate Limit Detection',
                        'severity': 'high',
                        'finding': 'Multiple consecutive check failures — possible blocking',
                        'detail': 'Rotated Tor circuit after 3 consecutive failures',
                        'url': target
                    })

        # Add findings to report builder.
        # FIX: Use lock to prevent concurrent threads from corrupting shared state.
        # stats dict and report_builder.findings are accessed from multiple threads
        # in scan_all_parallel() without synchronization.
        with self._lock:
            self.report_builder.add_findings(target, findings)
            self.stats['targets_scanned'] += 1
            self.stats['findings_count'] += len(findings)

        return {
            'target': target,
            'timestamp': time.time(),
            'findings': findings
        }

    def scan_all(self):
        """Scan all targets with state persistence"""
        self.scan_in_progress = True
        self.stats['start_time'] = time.time()

        targets = self.target_manager.get_targets()
        if not targets:
            print("[!] No targets to scan")
            self.scan_in_progress = False
            return {}

        print(f"\n[*] Starting scan of {len(targets)} targets")
        print(f"[*] Configuration: {self.scan_config}")

        scan_id = int(time.time())
        self.results = {
            'scan_id': scan_id,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'targets_scanned': len(targets),
            'results': {}
        }

        completed_targets = []

        for target in targets:
            if not self.scan_in_progress:
                print("[!] Scan stopped by user")
                break
            result = self.scan_target(target)
            self.results['results'][target] = result
            completed_targets.append(target)

            # Save state after each target for crash recovery
            self.scan_state.save(
                scan_id,
                targets,
                completed_targets,
                self.report_builder.findings,
                self.scan_config
            )

        self.stats['end_time'] = time.time()
        duration = self.stats['end_time'] - self.stats['start_time']

        print("\n[+] Scan complete!")
        print(f"    Targets scanned: {self.stats['targets_scanned']}")
        print(f"    Checks run: {self.stats['checks_run']}")
        print(f"    Findings: {self.stats['findings_count']}")
        print(f"    Duration: {duration:.2f} seconds")

        # Clear state on successful completion
        self.scan_state.clear()
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

        print("\n[+] Parallel scan complete!")
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
