from .base_check import BaseCheck

class CORSCheck(BaseCheck):
    """Check for CORS misconfigurations that allow data exfiltration"""

    def __init__(self):
        super().__init__()
        self.name = "CORS Misconfiguration"
        self.description = "Checks for overly permissive CORS policies (wildcard, credential reflection)"

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        timeout = config.get('timeout', 10) if config else 10

        # Test 1: Normal request — check for wildcard CORS
        resp = tor_session.get(url, timeout=timeout)
        if not resp:
            return findings

        acao = resp.headers.get('Access-Control-Allow-Origin', '')
        acac = resp.headers.get('Access-Control-Allow-Credentials', '')
        acam = resp.headers.get('Access-Control-Allow-Methods', '')
        acah = resp.headers.get('Access-Control-Allow-Headers', '')

        if acao == '*':
            sev = 'high' if acac.lower() == 'true' else 'medium'
            findings.append({
                'check': self.name,
                'severity': sev,
                'finding': 'CORS wildcard: Access-Control-Allow-Origin: *',
                'detail': 'Any origin can read responses from this site'
                          + (' WITH credentials' if acac.lower() == 'true' else ''),
                'url': url
            })

        # Test 2: Send request with evil origin — check if reflected
        evil_origins = [
            'https://evil.com',
            'https://attacker.onion',
            'null',
        ]

        for evil_origin in evil_origins:
            try:
                headers = {'Origin': evil_origin}
                resp2 = tor_session.session.get(
                    url, timeout=timeout,
                    proxies=tor_session.proxies,
                    headers={**tor_session.session.headers, **headers},
                    allow_redirects=True
                )
                if resp2:
                    reflected_origin = resp2.headers.get('Access-Control-Allow-Origin', '')
                    creds_allowed = resp2.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true'

                    if reflected_origin == evil_origin:
                        sev = 'critical' if creds_allowed else 'high'
                        findings.append({
                            'check': self.name,
                            'severity': sev,
                            'finding': f"CORS origin reflection: {evil_origin} reflected back",
                            'detail': 'Server echoes arbitrary Origin header as ACAO'
                                      + (' with credentials allowed — full account takeover risk' if creds_allowed else ''),
                            'url': url,
                            'data': {
                                'reflected_origin': evil_origin,
                                'credentials': creds_allowed
                            }
                        })
                        break  # One confirmed reflection is enough

                    # Check for null origin acceptance
                    if evil_origin == 'null' and reflected_origin == 'null':
                        findings.append({
                            'check': self.name,
                            'severity': 'high',
                            'finding': 'CORS accepts null origin',
                            'detail': 'null origin accepted — sandboxed iframes and data: URIs can read responses',
                            'url': url
                        })

            except Exception:
                pass

        # Check for overly permissive methods/headers
        if acam:
            dangerous = [m.strip() for m in acam.split(',')
                         if m.strip().upper() in ('PUT', 'DELETE', 'PATCH')]
            if dangerous:
                findings.append({
                    'check': self.name,
                    'severity': 'medium',
                    'finding': f"CORS allows dangerous methods: {', '.join(dangerous)}",
                    'url': url
                })

        if acah:
            sensitive_headers = [h.strip() for h in acah.split(',')
                                  if h.strip().lower() in ('authorization', 'x-api-key', 'cookie')]
            if sensitive_headers:
                findings.append({
                    'check': self.name,
                    'severity': 'medium',
                    'finding': f"CORS allows sensitive headers: {', '.join(sensitive_headers)}",
                    'url': url
                })

        if not findings:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': 'No CORS headers present or CORS properly configured',
                'url': url
            })

        return findings
