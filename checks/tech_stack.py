from .base_check import BaseCheck

class TechStackCheck(BaseCheck):
    """Comprehensive technology stack detection"""
    
    def __init__(self):
        super().__init__()
        self.name = "Technology Stack Analysis"
        self.description = "Identifies programming languages, frameworks, and libraries"
        
        # Technology signatures
        self.signatures = {
            'php': ['.php', 'phpinfo', 'X-PHP'],
            'python': ['django', 'flask', 'wsgi', 'python'],
            'ruby': ['rails', 'ruby', '.erb'],
            'nodejs': ['express', 'node.js', 'koa'],
            'asp.net': ['asp.net', 'aspx', '__viewstate'],
            'java': ['jsp', 'java', 'servlet', 'tomcat'],
            'nginx': ['nginx', 'server: nginx'],
            'apache': ['apache', 'server: apache'],
            'iis': ['iis', 'server: microsoft-iis'],
            'cloudflare': ['cloudflare', '__cfduid'],
            'jquery': ['jquery', 'jQuery'],
            'bootstrap': ['bootstrap', 'bootstrap.min.css'],
            'vue': ['vue.js', 'vuejs'],
            'react': ['react.js', 'reactjs']
        }
    
    def run(self, target, tor_session, config=None):
        findings = []
        
        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)
        
        if not resp:
            return findings
        
        detected = []
        
        # Check headers
        headers_str = str(resp.headers).lower()
        for tech, patterns in self.signatures.items():
            for pattern in patterns:
                if pattern.lower() in headers_str:
                    detected.append(tech)
                    break
        
        # Check HTML
        if resp.text:
            html_lower = resp.text.lower()
            for tech, patterns in self.signatures.items():
                for pattern in patterns:
                    # FIX: Removed .replace('\\', '') - none of the patterns
                    # contain backslashes, it was dead code.
                    if pattern.lower() in html_lower:
                        if tech not in detected:
                            detected.append(tech)
                        break
        
        if detected:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Detected technologies: {', '.join(set(detected))}",
                'url': url
            })
        
        return findings
