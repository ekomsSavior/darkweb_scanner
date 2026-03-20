from .base_check import BaseCheck
import hashlib

class CloneDetectorCheck(BaseCheck):
    """Detect if multiple targets serve identical content (same operator, different front doors)"""

    def __init__(self):
        super().__init__()
        self.name = "Clone/Mirror Detector"
        self.description = "Detects duplicate sites across targets by comparing content hashes"

        # Store fingerprints: hash -> {url, title, server, size}
        self.fingerprints = {}

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)

        if not resp or not resp.text:
            return findings

        # Build fingerprint
        content = resp.text.strip()
        content_hash = hashlib.sha256(content.encode('utf-8', errors='ignore')).hexdigest()

        # Structural hash — strip variable content (timestamps, tokens, nonces)
        # and hash the DOM structure only
        import re
        # Remove numbers that look like timestamps/IDs
        structural = re.sub(r'\d{10,}', 'NUM', content)
        # Remove hex tokens
        structural = re.sub(r'[a-f0-9]{32,}', 'HEX', structural)
        # Remove dynamic attributes
        structural = re.sub(r'(csrf|token|nonce|session|sid)=["\'][^"\']*["\']', r'\1="DYNAMIC"', structural, flags=re.IGNORECASE)
        structural_hash = hashlib.sha256(structural.encode('utf-8', errors='ignore')).hexdigest()

        # Extract title for display
        title_match = re.search(r'<title[^>]*>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip()[:60] if title_match else 'untitled'

        server = resp.headers.get('Server', 'unknown')
        size = len(content)

        fingerprint = {
            'url': url,
            'title': title,
            'server': server,
            'size': size,
            'content_hash': content_hash,
            'structural_hash': structural_hash,
        }

        # Check for exact content match
        if content_hash in self.fingerprints:
            match = self.fingerprints[content_hash]
            findings.append({
                'check': self.name,
                'severity': 'critical',
                'finding': f"EXACT CLONE of {match['url']}",
                'detail': f"Identical content (SHA256: {content_hash[:16]}...)\n"
                          f"  This: {url} ({title})\n"
                          f"  Match: {match['url']} ({match['title']})",
                'url': url,
                'data': {
                    'clone_type': 'exact',
                    'match_url': match['url'],
                    'hash': content_hash
                }
            })

        # Check for structural match (same site with different dynamic values)
        elif structural_hash in {fp.get('structural_hash') for fp in self.fingerprints.values()}:
            match = next(fp for fp in self.fingerprints.values()
                         if fp.get('structural_hash') == structural_hash)
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"STRUCTURAL CLONE of {match['url']}",
                'detail': f"Same page structure with different dynamic values\n"
                          f"  This: {url} ({title}, {size} bytes)\n"
                          f"  Match: {match['url']} ({match['title']}, {match['size']} bytes)",
                'url': url,
                'data': {
                    'clone_type': 'structural',
                    'match_url': match['url'],
                    'structural_hash': structural_hash
                }
            })

        # Check for similar size + same server (weak signal but worth noting)
        else:
            for fp_hash, fp in self.fingerprints.items():
                size_diff = abs(size - fp['size'])
                if (size_diff < 100 and size > 500 and
                        server == fp['server'] and server != 'unknown'):
                    findings.append({
                        'check': self.name,
                        'severity': 'medium',
                        'finding': f"Similar to {fp['url']} (same server, ~same size)",
                        'detail': f"  This: {size} bytes, server: {server}\n"
                                  f"  Match: {fp['size']} bytes, server: {fp['server']}",
                        'url': url,
                        'data': {
                            'clone_type': 'similar',
                            'match_url': fp['url'],
                            'size_diff': size_diff
                        }
                    })

        # Store this fingerprint (use content_hash as key, also store structural)
        self.fingerprints[content_hash] = fingerprint

        return findings

    def get_clone_report(self):
        """Return all detected clone groups"""
        # Group by structural hash
        groups = {}
        for fp in self.fingerprints.values():
            sh = fp.get('structural_hash', '')
            if sh not in groups:
                groups[sh] = []
            groups[sh].append(fp['url'])

        return {k: v for k, v in groups.items() if len(v) > 1}
