from .base_check import BaseCheck
import re

class SecurityHeadersCheck(BaseCheck):
    """Comprehensive HTTP security header analysis"""

    def __init__(self):
        super().__init__()
        self.name = "HTTP Security Headers"
        self.description = "Checks for missing/weak security headers (HSTS, CSP, XFO, CORS, Cache-Control)"

        self.security_headers = {
            'Strict-Transport-Security': {
                'msg': 'HSTS missing — no HTTPS enforcement',
                'severity': 'medium',
                'description': 'HTTP Strict Transport Security forces HTTPS connections'
            },
            'Content-Security-Policy': {
                'msg': 'CSP missing — no XSS protection policy',
                'severity': 'medium',
                'description': 'Content Security Policy helps prevent XSS attacks'
            },
            'X-Frame-Options': {
                'msg': 'X-Frame-Options missing — clickjacking risk',
                'severity': 'medium',
                'description': 'Prevents your site from being framed (clickjacking protection)'
            },
            'X-Content-Type-Options': {
                'msg': 'X-Content-Type-Options missing — MIME sniffing risk',
                'severity': 'low',
                'description': 'Prevents browser from MIME-sniffing responses'
            },
            'Referrer-Policy': {
                'msg': 'Referrer-Policy missing — information disclosure risk',
                'severity': 'low',
                'description': 'Controls how much referrer information is sent'
            },
            'Permissions-Policy': {
                'msg': 'Permissions-Policy missing — feature control',
                'severity': 'info',
                'description': 'Controls browser features (camera, microphone, geolocation)'
            },
            'X-Permitted-Cross-Domain-Policies': {
                'msg': 'X-Permitted-Cross-Domain-Policies missing',
                'severity': 'info',
                'description': 'Controls Flash/PDF cross-domain data loading'
            },
        }

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target

        resp = tor_session.get(url)
        if resp:
            findings.extend(self._check_headers(resp.headers, url))
            findings.extend(self._analyze_csp(resp.headers, url))
            findings.extend(self._check_cache_control(resp.headers, url))
            findings.extend(self._check_info_leakage(resp.headers, url))

        return findings

    def _check_headers(self, headers, url):
        """Check for missing security headers"""
        findings = []

        # Server fingerprint
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

        # X-XSS-Protection (legacy but still reveals info)
        xss_prot = headers.get('X-XSS-Protection', '')
        if xss_prot:
            if xss_prot.strip() == '0':
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': 'X-XSS-Protection explicitly disabled (0)',
                    'detail': 'Modern approach — relies on CSP instead',
                    'url': url
                })
            elif '1' in xss_prot and 'mode=block' not in xss_prot:
                findings.append({
                    'check': self.name,
                    'severity': 'low',
                    'finding': 'X-XSS-Protection enabled without mode=block',
                    'detail': 'Should be "1; mode=block" to prevent page rendering on XSS detection',
                    'url': url
                })

        return findings

    def _analyze_csp(self, headers, url):
        """Analyze Content-Security-Policy strength when present"""
        findings = []

        csp = headers.get('Content-Security-Policy', '')
        if not csp:
            return findings

        findings.append({
            'check': self.name,
            'severity': 'info',
            'finding': f"CSP policy present ({len(csp)} chars)",
            'detail': csp[:200] + ('...' if len(csp) > 200 else ''),
            'url': url
        })

        # Check for weak directives
        weaknesses = []

        if "'unsafe-inline'" in csp:
            weaknesses.append("unsafe-inline allowed (XSS risk)")
        if "'unsafe-eval'" in csp:
            weaknesses.append("unsafe-eval allowed (code injection risk)")
        if "data:" in csp:
            weaknesses.append("data: URIs allowed (potential bypass)")
        if "blob:" in csp:
            weaknesses.append("blob: URIs allowed (potential bypass)")

        # Check default-src
        if 'default-src' not in csp:
            weaknesses.append("No default-src — missing fallback policy")
        elif "default-src *" in csp or "default-src 'unsafe-inline' 'unsafe-eval'" in csp:
            weaknesses.append("default-src is effectively permissive")

        # Check script-src
        script_match = re.search(r"script-src\s+([^;]+)", csp)
        if script_match:
            script_src = script_match.group(1)
            if '*' in script_src:
                weaknesses.append("script-src allows wildcard origins")
            if 'http:' in script_src:
                weaknesses.append("script-src allows HTTP (mixed content risk)")

        # Check for report-uri / report-to
        if 'report-uri' in csp or 'report-to' in csp:
            report_match = re.search(r'report-(?:uri|to)\s+(\S+)', csp)
            if report_match:
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': f"CSP report endpoint: {report_match.group(1)[:60]}",
                    'url': url
                })

        if weaknesses:
            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': f"CSP weaknesses: {len(weaknesses)} found",
                'detail': '\n'.join([f"  - {w}" for w in weaknesses]),
                'url': url
            })

        return findings

    def _check_cache_control(self, headers, url):
        """Check if sensitive responses are being cached"""
        findings = []

        cache_control = headers.get('Cache-Control', '')
        pragma = headers.get('Pragma', '')
        expires = headers.get('Expires', '')

        if not cache_control:
            findings.append({
                'check': self.name,
                'severity': 'low',
                'finding': 'Cache-Control header missing',
                'detail': 'Responses may be cached by proxies, browsers, or CDNs — sensitive data risk',
                'url': url
            })
        else:
            cc_lower = cache_control.lower()
            if 'public' in cc_lower and 'no-store' not in cc_lower:
                findings.append({
                    'check': self.name,
                    'severity': 'medium',
                    'finding': f"Cache-Control: public (responses cached publicly)",
                    'detail': f'Value: {cache_control}',
                    'url': url
                })
            if 'no-store' not in cc_lower and 'private' not in cc_lower:
                findings.append({
                    'check': self.name,
                    'severity': 'low',
                    'finding': 'Cache-Control missing no-store/private — data may persist in caches',
                    'detail': f'Value: {cache_control}',
                    'url': url
                })

        return findings

    def _check_info_leakage(self, headers, url):
        """Check for headers that leak server/app information"""
        findings = []

        leak_headers = {
            'X-Powered-By': 'high',
            'X-AspNet-Version': 'high',
            'X-AspNetMvc-Version': 'high',
            'X-Runtime': 'medium',
            'X-Version': 'medium',
            'X-Generator': 'medium',
            'X-Drupal-Cache': 'medium',
            'X-Drupal-Dynamic-Cache': 'medium',
            'X-Varnish': 'low',
            'X-Request-Id': 'info',
            'X-Correlation-Id': 'info',
            'X-Trace-Id': 'info',
            'X-Debug-Token': 'high',
            'X-Debug-Token-Link': 'high',
        }

        for header, severity in leak_headers.items():
            value = headers.get(header, '')
            if value:
                findings.append({
                    'check': self.name,
                    'severity': severity,
                    'finding': f"Info leak: {header}: {value}",
                    'detail': f'Header reveals internal technology/version information',
                    'url': url
                })

        return findings
