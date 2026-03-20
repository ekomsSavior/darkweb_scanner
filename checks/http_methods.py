from .base_check import BaseCheck

class HTTPMethodCheck(BaseCheck):
    """Test for dangerous HTTP methods enabled on the server"""

    def __init__(self):
        super().__init__()
        self.name = "HTTP Method Enumeration"
        self.description = "Checks for dangerous HTTP methods (PUT, DELETE, TRACE, OPTIONS)"

        self.dangerous_methods = {
            'PUT': {
                'severity': 'critical',
                'detail': 'PUT enabled — attackers can upload/overwrite files on the server'
            },
            'DELETE': {
                'severity': 'critical',
                'detail': 'DELETE enabled — attackers can delete resources on the server'
            },
            'TRACE': {
                'severity': 'high',
                'detail': 'TRACE enabled — Cross-Site Tracing (XST) attacks can steal credentials'
            },
            'PATCH': {
                'severity': 'medium',
                'detail': 'PATCH enabled — partial resource modification allowed'
            },
        }

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        url = url.rstrip('/')
        timeout = config.get('timeout', 10) if config else 10

        # Send OPTIONS request to discover allowed methods
        try:
            resp = tor_session.session.options(url, timeout=timeout,
                                                proxies=tor_session.proxies,
                                                allow_redirects=True)
            if resp:
                allow_header = resp.headers.get('Allow', '')
                access_control = resp.headers.get('Access-Control-Allow-Methods', '')

                allowed = set()
                if allow_header:
                    allowed.update(m.strip().upper() for m in allow_header.split(','))
                if access_control:
                    allowed.update(m.strip().upper() for m in access_control.split(','))

                if allowed:
                    findings.append({
                        'check': self.name,
                        'severity': 'info',
                        'finding': f"Allowed methods: {', '.join(sorted(allowed))}",
                        'detail': f'Allow: {allow_header}' if allow_header else f'CORS methods: {access_control}',
                        'url': url
                    })

                    # Flag dangerous methods
                    for method, info in self.dangerous_methods.items():
                        if method in allowed:
                            findings.append({
                                'check': self.name,
                                'severity': info['severity'],
                                'finding': f"Dangerous method enabled: {method}",
                                'detail': info['detail'],
                                'url': url
                            })

                # If OPTIONS itself returns 405 or no Allow header, probe directly
                if not allowed or resp.status_code in [405, 501]:
                    findings.extend(self._probe_methods(url, tor_session, timeout))

        except Exception:
            # OPTIONS not supported, probe directly
            findings.extend(self._probe_methods(url, tor_session, timeout))

        return findings

    def _probe_methods(self, url, tor_session, timeout):
        """Directly test dangerous methods when OPTIONS doesn't reveal them"""
        findings = []
        test_url = url + '/vulnscan_method_test_' + str(hash(url))[-8:]

        for method in ['TRACE', 'PUT', 'DELETE']:
            try:
                resp = tor_session.session.request(
                    method, test_url if method != 'TRACE' else url,
                    timeout=timeout,
                    proxies=tor_session.proxies,
                    allow_redirects=False
                )
                if resp and resp.status_code not in [405, 501, 400, 403, 404]:
                    info = self.dangerous_methods.get(method, {})
                    findings.append({
                        'check': self.name,
                        'severity': info.get('severity', 'high'),
                        'finding': f"{method} method accepted (HTTP {resp.status_code})",
                        'detail': info.get('detail', f'{method} not rejected by server'),
                        'url': url
                    })
            except Exception:
                pass

        return findings
