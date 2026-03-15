import json
import os
import time
from datetime import datetime

class ReportBuilder:
    """Builds and exports scan reports in various formats"""
    
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
        """Make sure reports directory exists"""
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)
    
    def start_scan(self):
        """Mark scan start"""
        self.metadata['start_time'] = time.time()
        print("[*] Scan started")
    
    def end_scan(self):
        """Mark scan end"""
        self.metadata['end_time'] = time.time()
        self.metadata['duration'] = self.metadata['end_time'] - self.metadata['start_time']
        print(f"[+] Scan completed in {self.metadata['duration']:.2f} seconds")
    
    def add_findings(self, target, findings):
        """Add findings for a target"""
        if findings:
            self.findings[target] = findings
            self.metadata['total_findings'] += len(findings)
            self.metadata['target_count'] = len(self.findings)
    
    def get_summary(self):
        """Return a summary of findings"""
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
    
    def export_json(self, filename=None):
        """Export findings as JSON"""
        if not filename:
            filename = f"scan_{self.metadata['scan_id']}.json"
        
        filepath = os.path.join(self.report_dir, filename)
        
        output = {
            'metadata': self.metadata,
            'summary': self.get_summary(),
            'findings': self.findings
        }
        
        try:
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2)
            print(f"[+] JSON report saved to {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Error saving JSON: {e}")
            return None
    
    def export_text(self, filename=None):
        """Export findings as human-readable text"""
        if not filename:
            filename = f"scan_{self.metadata['scan_id']}.txt"
        
        filepath = os.path.join(self.report_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                f.write("=" * 60 + "\n")
                f.write("DARKWEB VULNERABILITY SCAN REPORT\n")
                f.write(f"Scan ID: {self.metadata['scan_id']}\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                summary = self.get_summary()
                f.write("SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Targets with findings: {summary['targets_with_findings']}\n")
                f.write(f"Total findings: {summary['total_findings']}\n")
                f.write("Severity breakdown:\n")
                for sev, count in summary['severity_counts'].items():
                    f.write(f"  {sev.capitalize()}: {count}\n")
                f.write("\n")
                
                f.write("DETAILED FINDINGS\n")
                f.write("=" * 60 + "\n\n")
                
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
    
    def export_csv(self, filename=None):
        """Export findings as CSV for spreadsheet analysis"""
        if not filename:
            filename = f"scan_{self.metadata['scan_id']}.csv"
        
        filepath = os.path.join(self.report_dir, filename)
        
        try:
            import csv
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
    
    def clear(self):
        """Clear all findings"""
        self.findings = {}
        self.metadata = {
            'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'start_time': None,
            'end_time': None,
            'target_count': 0,
            'total_findings': 0
        }
