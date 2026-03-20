from .base_check import BaseCheck

class CookieAnalyzerCheck(BaseCheck):
    """Analyze cookies for security flags, session tokens, and tracking indicators"""

    def __init__(self):
        super().__init__()
        self.name = "Cookie Analyzer"
        self.description = "Checks cookie security flags, session tokens, and tracking cookies"

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)

        if not resp:
            return findings

        cookies = resp.cookies
        set_cookie_headers = resp.headers.get('Set-Cookie', '')

        if not cookies and not set_cookie_headers:
            return findings

        insecure_cookies = []
        session_cookies = []
        tracking_cookies = []

        # Session-related cookie names
        session_names = ['session', 'sess', 'sid', 'token', 'auth', 'jwt',
                          'phpsessid', 'jsessionid', 'asp.net_sessionid',
                          'csrftoken', 'csrf', '_csrf', 'xsrf']

        # Tracking cookie names
        tracking_names = ['_ga', '_gid', '_gat', '__utma', '__utmb', '__utmc', '__utmz',
                           '_fbp', '_fbc', 'fr', '__cfduid', '_pk_id', '_pk_ses',
                           'hubspot', '_hjid', '_hjSession', 'intercom']

        for cookie in cookies:
            name_lower = cookie.name.lower()
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value[:30] + '...' if len(cookie.value) > 30 else cookie.value,
                'domain': cookie.domain or '',
                'path': cookie.path or '/',
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'),
            }

            # Check for session cookies
            if any(s in name_lower for s in session_names):
                session_cookies.append(cookie_info)

            # Check for tracking cookies
            if any(t in name_lower for t in tracking_names):
                tracking_cookies.append(cookie_info)

            # Check security flags
            if not cookie.secure:
                insecure_cookies.append(cookie_info)

        # Parse Set-Cookie headers for SameSite and other flags
        raw_cookies = []
        if isinstance(set_cookie_headers, str):
            raw_cookies = [set_cookie_headers]
        elif hasattr(resp.headers, 'getlist'):
            raw_cookies = resp.headers.getlist('Set-Cookie')

        missing_samesite = []
        missing_httponly = []
        for raw in raw_cookies:
            parts = raw.split(';')
            cookie_name = parts[0].split('=')[0].strip() if parts else 'unknown'
            flags = [p.strip().lower() for p in parts[1:]]

            if not any('samesite' in f for f in flags):
                missing_samesite.append(cookie_name)
            if not any('httponly' in f for f in flags):
                if any(s in cookie_name.lower() for s in session_names):
                    missing_httponly.append(cookie_name)

        # Build findings
        total = len(list(cookies))
        findings.append({
            'check': self.name,
            'severity': 'info',
            'finding': f"Cookies set: {total} total",
            'url': url
        })

        if session_cookies:
            details = []
            for c in session_cookies:
                flags = []
                if not c['secure']:
                    flags.append('NO Secure')
                if not c['httponly']:
                    flags.append('NO HttpOnly')
                flag_str = f" [{', '.join(flags)}]" if flags else " [OK]"
                details.append(f"  {c['name']}={c['value']}{flag_str}")

            sev = 'high' if any(not c['secure'] or not c['httponly'] for c in session_cookies) else 'info'
            findings.append({
                'check': self.name,
                'severity': sev,
                'finding': f"Session cookies: {len(session_cookies)} detected",
                'detail': '\n'.join(details),
                'url': url,
                'data': {'session_cookies': session_cookies}
            })

        if tracking_cookies:
            details = [f"  {c['name']} ({c['domain']})" for c in tracking_cookies]
            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': f"Tracking cookies: {len(tracking_cookies)} (OPSEC risk for .onion)",
                'detail': '\n'.join(details),
                'url': url,
                'data': {'tracking_cookies': tracking_cookies}
            })

        if insecure_cookies:
            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': f"Insecure cookies (no Secure flag): {len(insecure_cookies)}",
                'detail': '\n'.join([f"  {c['name']}" for c in insecure_cookies[:10]]),
                'url': url
            })

        if missing_httponly:
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"Session cookies without HttpOnly: {', '.join(missing_httponly)}",
                'detail': 'Session cookies accessible to JavaScript — XSS can steal sessions',
                'url': url
            })

        return findings
