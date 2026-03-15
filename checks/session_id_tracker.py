from .base_check import BaseCheck
import re

class SessionIDTracker(BaseCheck):
    """Track Session messenger IDs across sites"""
    
    def __init__(self):
        super().__init__()
        self.name = "Session ID Tracker"
        self.description = "Detects Session messenger IDs (popular in Com/764 networks)"
        
        # Session IDs are 64-66 character hex strings starting with 05
        self.session_pattern = r'05[a-f0-9]{62,64}'
        
        # Store found IDs for cross-reference
        self.found_ids = set()
    
    def run(self, target, tor_session, config=None):
        findings = []
        
        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)
        
        if not resp or not resp.text:
            return findings
        
        # Find all Session IDs in the page
        session_ids = re.findall(self.session_pattern, resp.text)
        
        if session_ids:
            # Remove duplicates
            unique_ids = list(set(session_ids))
            
            # Check if any were seen before
            new_ids = [sid for sid in unique_ids if sid not in self.found_ids]
            self.found_ids.update(new_ids)
            
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"Found {len(unique_ids)} Session messenger IDs",
                'detail': f"IDs: {', '.join(unique_ids[:3])}" + ("..." if len(unique_ids) > 3 else ""),
                'url': url,
                'session_ids': unique_ids
            })
            
            # Check for cross-site matches (if we have previous scans)
            if hasattr(self, 'previous_ids') and self.previous_ids:
                matches = set(unique_ids) & set(self.previous_ids)
                if matches:
                    findings.append({
                        'check': self.name,
                        'severity': 'critical',
                        'finding': f"Cross-site Session IDs detected",
                        'detail': f"Same IDs found on multiple sites: {', '.join(matches)}",
                        'url': url
                    })
        
        return findings
