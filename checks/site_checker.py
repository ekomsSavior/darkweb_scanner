from .base_check import BaseCheck

class SiteChecker(BaseCheck):
    """Check if a .onion site is actually reachable"""
    
    def __init__(self):
        super().__init__()
        self.name = "Site Availability Check"
        self.description = "Verifies if .onion site is reachable before other checks"
    
    def run(self, target, tor_session, config=None):
        findings = []
        
        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url, timeout=10)
        
        if not resp:
            findings.append({
                'check': self.name,
                'severity': 'error',
                'finding': "Site unreachable",
                'detail': "No response from .onion site - may be offline",
                'url': url
            })
            return findings
        
        # Check for Tor error pages
        if resp.text:
            error_signatures = [
                "unable to connect to the tor hidden service",
                "404 not found", 
                "onion site not available",
                "no such onion site",
                "this onion site is not available"
            ]
            text_lower = resp.text.lower()
            for sig in error_signatures:
                if sig in text_lower:
                    findings.append({
                        'check': self.name,
                        'severity': 'error',
                        'finding': "Site returns Tor error page",
                        'detail': f"Error signature detected: {sig}",
                        'url': url
                    })
                    return findings
        
        # Site is reachable
        findings.append({
            'check': self.name,
            'severity': 'info',
            'finding': "Site is reachable",
            'url': url
        })
        
        return findings
