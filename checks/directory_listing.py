from .base_check import BaseCheck

class DirectoryListingCheck(BaseCheck):
    """Check if directory listing is enabled"""
    
    def __init__(self):
        super().__init__()
        self.name = "Directory Listing"
        self.description = "Checks if directory listing is enabled on common paths"
        
        self.common_dirs = [
            '/', '/images/', '/css/', '/js/', '/uploads/', 
            '/files/', '/assets/', '/static/', '/backups/',
            '/admin/', '/includes/', '/tmp/', '/logs/'
        ]
    
    def run(self, target, tor_session, config=None):
        findings = []
        
        base = target if target.startswith('http') else 'http://' + target
        base = base.rstrip('/')
        
        for directory in self.common_dirs:
            url = base + directory
            resp = tor_session.get(url)
            
            if resp:
                # Check for directory listing indicators
                text = resp.text.lower()
                
                if 'index of /' in text or 'directory listing' in text:
                    findings.append({
                        'check': self.name,
                        'severity': 'medium',
                        'finding': f"Directory listing enabled: {directory}",
                        'detail': 'Directory listing exposes file structure',
                        'url': url
                    })
                elif resp.status_code == 403:
                    findings.append({
                        'check': self.name,
                        'severity': 'info',
                        'finding': f"Directory access forbidden: {directory}",
                        'url': url
                    })
        
        return findings
