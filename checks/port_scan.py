from .base_check import BaseCheck
import subprocess
import re

class PortScanCheck(BaseCheck):
    """Port scanning via nmap through proxychains"""
    
    def __init__(self):
        super().__init__()
        self.name = "Port Scan"
        self.description = "Scans common ports using nmap through Tor"
        self.enabled = False  # Disabled by default as it's slow
        
        self.common_ports = "22,80,443,8080,8443,6669,6697,9001,9050,9051"
    
    def run(self, target, tor_session, config=None):
        findings = []
        
        # Extract hostname
        host = target.replace('http://', '').replace('https://', '').split('/')[0]

        # FIX: Validate hostname before passing to subprocess.
        # Without validation, a crafted hostname like "-oN /tmp/evil" would be
        # interpreted as an nmap flag instead of a target (argument injection).
        # We reject any hostname starting with "-" and validate the format.
        if not host or host.startswith('-') or not re.match(r'^[a-zA-Z0-9._-]+$', host):
            return [{
                'check': self.name,
                'severity': 'error',
                'finding': f"Invalid hostname, skipping port scan: {host[:50]}",
            }]

        print(f"    └─ Port scan in progress (this may take a while)...")

        try:
            # Use proxychains with nmap
            cmd = [
                'proxychains4', '-q',
                'nmap', '-sT', '-Pn', '-p', self.common_ports,
                '--max-retries', '1',
                '--max-rtt-timeout', '5000ms',
                '--min-rate', '10',
                '--host-timeout', '120s',
                '--', host  # "--" prevents host from being parsed as nmap flags
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            
            # Parse output for open ports
            lines = result.stdout.split('\n')
            for line in lines:
                if '/tcp' in line and 'open' in line:
                    port = line.split('/')[0]
                    service = line.split()[-1] if len(line.split()) > 2 else 'unknown'
                    
                    findings.append({
                        'check': self.name,
                        'severity': 'info' if port not in ['22', '80', '443'] else 'low',
                        'finding': f"Open port: {port} ({service})",
                        'detail': line.strip(),
                        'host': host
                    })
            
            if not findings:
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': "No common ports open",
                    'host': host
                })
                
        except subprocess.TimeoutExpired:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': "Port scan timed out (host may be slow or filtering)",
                'host': host
            })
        except FileNotFoundError:
            findings.append({
                'check': self.name,
                'severity': 'error',
                'finding': "nmap or proxychains not installed",
                'detail': "Install with: sudo apt install nmap proxychains4"
            })
        except Exception as e:
            findings.append({
                'check': self.name,
                'severity': 'error',
                'finding': f"Port scan failed: {str(e)[:50]}",
                'host': host
            })
        
        return findings
