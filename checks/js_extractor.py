from .base_check import BaseCheck
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re

class JSExtractorCheck(BaseCheck):
    """Extract API endpoints, keys, secrets, and hardcoded credentials from JavaScript"""

    def __init__(self):
        super().__init__()
        self.name = "JavaScript Analyzer"
        self.description = "Extracts API endpoints, keys, secrets, and credentials from JS files"

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        timeout = config.get('timeout', 15) if config else 15

        resp = tor_session.get(url, timeout=timeout)
        if not resp or not resp.text:
            return findings

        # Collect all JS: inline scripts + external JS files
        js_sources = []

        try:
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Inline scripts
            for script in soup.find_all('script'):
                if script.string:
                    js_sources.append(('inline', script.string))

            # External JS files (fetch up to 10)
            js_urls = []
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                js_urls.append(js_url)

            for js_url in js_urls[:10]:
                js_resp = tor_session.get(js_url, timeout=timeout)
                if js_resp and js_resp.text:
                    js_sources.append((js_url, js_resp.text))
        except Exception:
            # Fall back to regex if BS4 fails
            js_sources.append(('page', resp.text))

        if not js_sources:
            return findings

        all_endpoints = set()
        all_keys = []
        all_creds = []
        all_domains = set()

        for source_name, js_code in js_sources:
            # === API Endpoints ===
            # Fetch/XHR URLs
            api_patterns = [
                r'["\'](/api/[a-zA-Z0-9/_\-\.]+)["\']',
                r'["\'](/v[0-9]+/[a-zA-Z0-9/_\-\.]+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']',
                r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'endpoint:\s*["\']([^"\']+)["\']',
                r'baseURL:\s*["\']([^"\']+)["\']',
            ]
            for pattern in api_patterns:
                matches = re.findall(pattern, js_code)
                for m in matches:
                    if len(m) > 3 and not m.endswith(('.js', '.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf')):
                        all_endpoints.add(m)

            # === API Keys & Tokens ===
            key_patterns = [
                (r'["\']?(api[_-]?key|apikey|api[_-]?token)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\']', 'API Key'),
                (r'["\']?(secret[_-]?key|api[_-]?secret)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\']', 'Secret Key'),
                (r'["\']?(access[_-]?token|auth[_-]?token|bearer)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_.]{20,})["\']', 'Auth Token'),
                (r'["\']?(aws[_-]?access[_-]?key)["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']', 'AWS Key'),
                (r'["\']?(private[_-]?key)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{16,})["\']', 'Private Key'),
                (r'AIza[a-zA-Z0-9\-_]{35}', 'Google API Key'),
                (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI/Stripe Key'),
                (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Token'),
            ]
            for pattern, key_type in key_patterns:
                matches = re.findall(pattern, js_code, re.IGNORECASE)
                for m in matches:
                    value = m[-1] if isinstance(m, tuple) else m
                    if len(value) >= 16:
                        all_keys.append({'type': key_type, 'value': value[:40] + '...', 'source': source_name})

            # === Hardcoded Credentials ===
            cred_patterns = [
                (r'["\']?(password|passwd|pwd)["\']?\s*[:=]\s*["\']([^"\']{4,})["\']', 'Password'),
                (r'["\']?(username|user|login)["\']?\s*[:=]\s*["\']([^"\']{3,})["\']', 'Username'),
                (r'["\']?(db[_-]?pass|database[_-]?password|mysql[_-]?password)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'DB Password'),
                (r'["\']?(smtp[_-]?password|mail[_-]?password)["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Mail Password'),
            ]
            for pattern, cred_type in cred_patterns:
                matches = re.findall(pattern, js_code, re.IGNORECASE)
                for m in matches:
                    key, value = m
                    # Skip obvious non-credentials
                    if value.lower() in ('', 'null', 'undefined', 'none', 'password', 'your_password', 'changeme',
                                          'placeholder', 'example', 'test', 'xxx', '***'):
                        continue
                    all_creds.append({'type': cred_type, 'key': key, 'value': value[:30], 'source': source_name})

            # === Interesting Domains ===
            domains = re.findall(r'https?://([a-zA-Z0-9][\w\-\.]+\.[a-zA-Z]{2,})', js_code)
            for d in domains:
                if not d.endswith(('.googleapis.com', '.gstatic.com', '.google.com', '.cloudflare.com',
                                    '.jsdelivr.net', '.cdnjs.com', '.unpkg.com', '.w3.org')):
                    all_domains.add(d)

            # === WebSocket endpoints ===
            ws_matches = re.findall(r'wss?://[^\s"\'<>]+', js_code)
            for ws in ws_matches:
                all_endpoints.add(ws)

        # Build findings
        if all_endpoints:
            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': f"API endpoints: {len(all_endpoints)} discovered",
                'detail': '\n'.join(sorted(list(all_endpoints))[:20]),
                'url': url,
                'data': {'endpoints': sorted(list(all_endpoints))}
            })

        if all_keys:
            findings.append({
                'check': self.name,
                'severity': 'critical',
                'finding': f"Exposed API keys/tokens: {len(all_keys)}",
                'detail': '\n'.join([f"{k['type']}: {k['value']} (in {k['source']})" for k in all_keys[:10]]),
                'url': url,
                'data': {'keys': all_keys}
            })

        if all_creds:
            findings.append({
                'check': self.name,
                'severity': 'critical',
                'finding': f"Hardcoded credentials: {len(all_creds)}",
                'detail': '\n'.join([f"{c['type']}: {c['key']}={c['value']} (in {c['source']})" for c in all_creds[:10]]),
                'url': url,
                'data': {'credentials': all_creds}
            })

        if all_domains:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Referenced domains: {len(all_domains)}",
                'detail': '\n'.join(sorted(list(all_domains))[:15]),
                'url': url,
                'data': {'domains': sorted(list(all_domains))}
            })

        return findings
