from .base_check import BaseCheck
import re

class FingerprintCheck(BaseCheck):
    """Identify technology stack from HTTP responses"""
    
    def __init__(self):
        super().__init__()
        self.name = "Technology Fingerprint"
        self.description = "Identifies server software and frameworks"
        
        # Common CMS signatures
        self.cms_signatures = {
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'drupal': ['drupal', 'Drupal', 'sites/default'],
            'joomla': ['joomla', 'Joomla', 'com_content'],
            'vbulletin': ['vbulletin', 'vbscript'],
            'phpbb': ['phpBB', 'style.php'],
            'discuz': ['discuz', 'forum.php']
        }
        
        # Common server headers that reveal versions
        self.revealing_headers = ['Server', 'X-Powered-By', 'X-Generator', 'Via']
    
    def run(self, target, tor_session, config=None):
        findings = []
        
        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)
        
        if not resp:
            return findings
        
        # Check revealing headers
        for header in self.revealing_headers:
            if header in resp.headers:
                value = resp.headers[header]
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': f"{header}: {value}",
                    'detail': 'Server reveals technology information',
                    'url': url
                })
        
        # Check for CMS signatures in HTML
        if resp.text:
            html_lower = resp.text.lower()
            
            for cms, signatures in self.cms_signatures.items():
                for sig in signatures:
                    if sig.lower() in html_lower:
                        findings.append({
                            'check': self.name,
                            'severity': 'info',
                            'finding': f"Detected: {cms.title()}",
                            'detail': f'CMS signature found: {sig}',
                            'url': url
                        })
                        break
        
        # Check for generator meta tag
        # FIX: resp.text can be None if the response has no body.
        # re.search() would throw TypeError on None input.
        gen_match = re.search(r'<meta name="generator" content="([^"]+)"', resp.text) if resp.text else None
        if gen_match:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Generator: {gen_match.group(1)}",
                'url': url
            })
        
        return findings
