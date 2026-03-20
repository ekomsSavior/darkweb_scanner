import json
import os
import time
import csv
from datetime import datetime

SEVERITY_ICONS = {
    'critical': '🔴',
    'high': '🟠',
    'medium': '🟡',
    'low': '🔵',
    'info': '⚪',
    'error': '❌'
}

class ReportBuilder:
    """Builds and exports scan reports in multiple formats"""

    def __init__(self, report_dir="reports"):
        self.report_dir = report_dir
        self.findings = {}  # Dict: {target: [findings]}
        self.metadata = {
            'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'start_time': None,
            'end_time': None,
            'target_count': 0,
            'total_findings': 0
        }
        self.ensure_report_dir()

    def ensure_report_dir(self):
        os.makedirs(self.report_dir, exist_ok=True)

    def start_scan(self):
        self.metadata['start_time'] = time.time()
        print("[*] Scan started")

    def end_scan(self):
        self.metadata['end_time'] = time.time()
        self.metadata['duration'] = self.metadata['end_time'] - self.metadata['start_time']
        print(f"[+] Scan completed in {self.metadata['duration']:.2f} seconds")

    def add_findings(self, target, findings):
        if findings:
            self.findings[target] = findings
            self.metadata['total_findings'] += len(findings)
            self.metadata['target_count'] = len(self.findings)

    def get_summary(self):
        summary = {
            'targets_with_findings': len(self.findings),
            'total_findings': self.metadata['total_findings'],
            'severity_counts': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        for target_findings in self.findings.values():
            for finding in target_findings:
                severity = finding.get('severity', 'info').lower()
                if severity in summary['severity_counts']:
                    summary['severity_counts'][severity] += 1

        return summary

    def _get_cross_site_identifiers(self):
        """Extract cross-site identifier matches from findings"""
        id_map = {}  # identifier -> [targets]
        for target, findings in self.findings.items():
            for f in findings:
                data = f.get('data', {})
                if not isinstance(data, dict):
                    continue
                # Check for session_ids, emails, wallets, etc.
                for key in ['session_ids', 'email', 'btc_wallet', 'xmr_wallet', 'eth_wallet',
                            'telegram', 'discord_invite', 'wickr', 'session_id']:
                    values = data.get(key, [])
                    if isinstance(values, list):
                        for v in values:
                            vid = f"{key}:{v}"
                            if vid not in id_map:
                                id_map[vid] = set()
                            id_map[vid].add(target)
        return {k: list(v) for k, v in id_map.items() if len(v) > 1}

    # === JSON ===
    def export_json(self, filename=None):
        if not filename:
            filename = f"scan_{self.metadata['scan_id']}.json"
        filepath = os.path.join(self.report_dir, filename)

        output = {
            'metadata': self.metadata,
            'summary': self.get_summary(),
            'cross_site_identifiers': self._get_cross_site_identifiers(),
            'findings': self.findings
        }
        try:
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2, default=str)
            print(f"[+] JSON report saved to {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Error saving JSON: {e}")
            return None

    # === Text ===
    def export_text(self, filename=None):
        if not filename:
            filename = f"scan_{self.metadata['scan_id']}.txt"
        filepath = os.path.join(self.report_dir, filename)

        try:
            with open(filepath, 'w') as f:
                f.write("=" * 70 + "\n")
                f.write("DARKWEB VULNERABILITY SCAN REPORT\n")
                f.write(f"Scan ID: {self.metadata['scan_id']}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")

                summary = self.get_summary()
                f.write("SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Targets with findings: {summary['targets_with_findings']}\n")
                f.write(f"Total findings: {summary['total_findings']}\n")
                f.write("Severity breakdown:\n")
                for sev, count in summary['severity_counts'].items():
                    f.write(f"  {sev.capitalize()}: {count}\n")
                f.write("\n")

                # Cross-site identifiers
                xsite = self._get_cross_site_identifiers()
                if xsite:
                    f.write("CROSS-SITE IDENTIFIER MATCHES\n")
                    f.write("-" * 40 + "\n")
                    for identifier, targets in xsite.items():
                        f.write(f"  {identifier}\n")
                        for t in targets:
                            f.write(f"    -> {t}\n")
                    f.write("\n")

                f.write("DETAILED FINDINGS\n")
                f.write("=" * 70 + "\n\n")

                for target, findings in self.findings.items():
                    f.write(f"TARGET: {target}\n")
                    f.write("-" * 40 + "\n")
                    if not findings:
                        f.write("  No findings\n")
                    else:
                        for finding in findings:
                            severity = finding.get('severity', 'info').upper()
                            f.write(f"[{severity}] {finding.get('finding', 'No details')}\n")
                            if 'detail' in finding:
                                f.write(f"      Detail: {finding['detail']}\n")
                            if 'url' in finding:
                                f.write(f"      URL: {finding['url']}\n")
                        f.write("\n")

                if self.metadata.get('duration'):
                    f.write(f"\nScan duration: {self.metadata['duration']:.2f} seconds\n")

            print(f"[+] Text report saved to {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Error saving text report: {e}")
            return None

    # === CSV ===
    def export_csv(self, filename=None):
        if not filename:
            filename = f"scan_{self.metadata['scan_id']}.csv"
        filepath = os.path.join(self.report_dir, filename)

        try:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Target', 'Check', 'Severity', 'Finding', 'Detail', 'URL'])
                for target, findings in self.findings.items():
                    for finding in findings:
                        writer.writerow([
                            target,
                            finding.get('check', 'Unknown'),
                            finding.get('severity', 'info'),
                            finding.get('finding', ''),
                            finding.get('detail', ''),
                            finding.get('url', '')
                        ])
            print(f"[+] CSV report saved to {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Error saving CSV: {e}")
            return None

    # === Markdown ===
    def export_markdown(self, filename=None):
        if not filename:
            filename = f"scan_{self.metadata['scan_id']}.md"
        filepath = os.path.join(self.report_dir, filename)

        try:
            with open(filepath, 'w') as f:
                f.write(f"# DarkWeb Scan Report\n\n")
                f.write(f"**Scan ID:** `{self.metadata['scan_id']}`\n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if self.metadata.get('duration'):
                    f.write(f"**Duration:** {self.metadata['duration']:.2f} seconds\n")
                f.write("\n---\n\n")

                # Summary
                summary = self.get_summary()
                f.write("## Summary\n\n")
                f.write(f"| Metric | Count |\n|--------|-------|\n")
                f.write(f"| Targets scanned | {summary['targets_with_findings']} |\n")
                f.write(f"| Total findings | {summary['total_findings']} |\n")
                for sev, count in summary['severity_counts'].items():
                    icon = SEVERITY_ICONS.get(sev, '')
                    f.write(f"| {icon} {sev.capitalize()} | {count} |\n")
                f.write("\n")

                # Cross-site identifiers
                xsite = self._get_cross_site_identifiers()
                if xsite:
                    f.write("## Cross-Site Identifier Matches\n\n")
                    f.write("These identifiers were found on **multiple targets** — potential operator correlation:\n\n")
                    for identifier, targets in xsite.items():
                        id_type, id_value = identifier.split(':', 1)
                        f.write(f"### `{id_value[:50]}`\n")
                        f.write(f"- **Type:** {id_type.replace('_', ' ').title()}\n")
                        f.write(f"- **Found on:**\n")
                        for t in targets:
                            f.write(f"  - `{t}`\n")
                        f.write("\n")

                # Per-target findings
                f.write("## Findings by Target\n\n")

                for target, findings in self.findings.items():
                    f.write(f"### `{target}`\n\n")

                    if not findings:
                        f.write("No findings.\n\n")
                        continue

                    # Group by check name
                    by_check = {}
                    for finding in findings:
                        check = finding.get('check', 'Unknown')
                        if check not in by_check:
                            by_check[check] = []
                        by_check[check].append(finding)

                    for check_name, check_findings in by_check.items():
                        f.write(f"#### {check_name}\n\n")
                        for finding in check_findings:
                            severity = finding.get('severity', 'info')
                            icon = SEVERITY_ICONS.get(severity, '')
                            f.write(f"- {icon} **[{severity.upper()}]** {finding.get('finding', '')}\n")
                            if 'detail' in finding:
                                detail = finding['detail'].replace('\n', '\n  > ')
                                f.write(f"  > {detail}\n")
                            if 'url' in finding and finding['url'] != target:
                                f.write(f"  > URL: `{finding['url']}`\n")
                        f.write("\n")

                    f.write("---\n\n")

            print(f"[+] Markdown report saved to {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Error saving markdown report: {e}")
            return None

    def clear(self):
        self.findings = {}
        self.metadata = {
            'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'start_time': None,
            'end_time': None,
            'target_count': 0,
            'total_findings': 0
        }
