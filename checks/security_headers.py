from .base_check import BaseCheck

class SecurityHeadersCheck(BaseCheck):
    """Check for missing security headers in HTTP responses"""
    
    def __init__(self):
        super().__init__()
        self.name = "HTTP Security Headers"
        self.description = "Checks for missing security headers (HSTS, CSP, XFO, etc.)"
        
        self.security_headers = {
            'Strict-Transport-Security': {
                'msg': 'HSTS missing - no HTTPS enforcement',
                'severity': 'medium',
                'description': 'HTTP Strict Transport Security forces HTTPS connections'
            },
            'Content-Security-Policy': {
                'msg': 'CSP missing - no XSS protection policy',
                'severity': 'medium',
                'description': 'Content Security Policy helps prevent XSS attacks'
            },
            'X-Frame-Options': {
                'msg': 'X-Frame-Options missing - clickjacking risk',
                'severity': 'medium',
                'description': 'Prevents your site from being framed (clickjacking protection)'
            },
            'X-Content-Type-Options': {
                'msg': 'X-Content-Type-Options missing - MIME sniffing risk',
                'severity': 'low',
                'description': 'Prevents browser from MIME-sniffing responses'
            },
            'Referrer-Policy': {
                'msg': 'Referrer-Policy missing - information disclosure risk',
                'severity': 'low',
                'description': 'Controls how much referrer information is sent'
            },
            'Permissions-Policy': {
                'msg': 'Permissions-Policy missing - feature control',
                'severity': 'info',
                'description': 'Controls browser features (camera, microphone, etc.)'
            }
        }
    
    def run(self, target, tor_session, config=None):
        """Check security headers"""
        findings = []
        
        # Ensure URL has scheme
        url = target if target.startswith('http') else 'http://' + target
        
        # Try HTTPS first if configured
        if config and config.get('check_https', True):
            https_url = url.replace('http://', 'https://')
            resp = tor_session.get(https_url)
            if resp:
                findings.extend(self._check_headers(resp.headers, https_url))
        
        # Also check HTTP
        resp = tor_session.get(url)
        if resp:
            findings.extend(self._check_headers(resp.headers, url))
        
        return findings
    
    def _check_headers(self, headers, url):
        """Check a specific response's headers"""
        findings = []
        
        # Check for server header (info only)
        server = headers.get('Server', '')
        if server:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Server fingerprint: {server}",
                'detail': f'Server header reveals: {server}',
                'url': url
            })
        
        # Check each security header
        for header, info in self.security_headers.items():
            if header not in headers:
                findings.append({
                    'check': self.name,
                    'severity': info['severity'],
                    'finding': info['msg'],
                    'detail': info['description'],
                    'url': url
                })
        
        return findings
