from .base_check import BaseCheck
from urllib.parse import urlencode, urlparse, urljoin
from bs4 import BeautifulSoup

class OpenRedirectCheck(BaseCheck):
    """Detect open redirect vulnerabilities"""

    def __init__(self):
        super().__init__()
        self.name = "Open Redirect Detection"
        self.description = "Tests common redirect parameters for open redirect vulnerabilities"

        # Common redirect parameters
        self.redirect_params = [
            'url', 'redirect', 'redirect_url', 'redirect_uri',
            'next', 'return', 'returnTo', 'return_to', 'returnUrl',
            'goto', 'go', 'target', 'dest', 'destination',
            'rurl', 'redir', 'out', 'link', 'forward',
            'continue', 'ref', 'callback', 'path',
        ]

        # Common redirect endpoints
        self.redirect_paths = [
            '/redirect', '/out', '/go', '/link', '/click',
            '/logout', '/login', '/signin', '/auth',
            '/external', '/away', '/jump', '/visit',
        ]

        self.canary = 'https://evil.example.com/pwned'

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        base = url.rstrip('/')
        timeout = config.get('timeout', 10) if config else 10

        # Phase 1: Test redirect parameters on the base URL
        for param in self.redirect_params:
            test_url = f"{base}?{param}={self.canary}"

            try:
                resp = tor_session.session.get(
                    test_url, timeout=timeout,
                    proxies=tor_session.proxies,
                    allow_redirects=False  # Don't follow — check Location header
                )
                if resp:
                    location = resp.headers.get('Location', '')

                    if resp.status_code in [301, 302, 303, 307, 308]:
                        if 'evil.example.com' in location:
                            findings.append({
                                'check': self.name,
                                'severity': 'high',
                                'finding': f"Open redirect via ?{param}= parameter",
                                'detail': f'Redirects to: {location}',
                                'url': test_url,
                                'data': {'param': param, 'redirect_to': location}
                            })

                    # Check for meta refresh redirect in body
                    if resp.status_code == 200 and resp.text:
                        if 'evil.example.com' in resp.text.lower():
                            findings.append({
                                'check': self.name,
                                'severity': 'medium',
                                'finding': f"Possible meta/JS redirect via ?{param}= parameter",
                                'detail': 'Canary URL appears in response body (meta refresh or JS redirect)',
                                'url': test_url
                            })
            except Exception:
                pass

        # Phase 2: Test common redirect paths
        for path in self.redirect_paths:
            for param in ['url', 'redirect', 'next', 'goto']:
                test_url = f"{base}{path}?{param}={self.canary}"

                try:
                    resp = tor_session.session.get(
                        test_url, timeout=timeout,
                        proxies=tor_session.proxies,
                        allow_redirects=False
                    )
                    if resp and resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if 'evil.example.com' in location:
                            findings.append({
                                'check': self.name,
                                'severity': 'high',
                                'finding': f"Open redirect at {path}?{param}=",
                                'detail': f'Redirects to: {location}',
                                'url': test_url,
                                'data': {'path': path, 'param': param, 'redirect_to': location}
                            })
                            break  # Found one on this path, skip other params
                except Exception:
                    pass

        # Phase 3: Find redirect links in the page itself
        resp = tor_session.get(url, timeout=timeout)
        if resp and resp.text:
            try:
                soup = BeautifulSoup(resp.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    parsed = urlparse(href)
                    # Look for links that have redirect-like parameters
                    if parsed.query:
                        for param in self.redirect_params:
                            if param + '=' in parsed.query:
                                findings.append({
                                    'check': self.name,
                                    'severity': 'info',
                                    'finding': f"Redirect parameter in page link: {param}",
                                    'detail': f'URL: {href[:100]}',
                                    'url': url
                                })
                                break
            except Exception:
                pass

        if not findings:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': 'No open redirects detected in common parameters',
                'url': url
            })

        return findings
