from .base_check import BaseCheck
import re

class PGPExtractorCheck(BaseCheck):
    """Extract PGP public key blocks and analyze for operator intel"""

    def __init__(self):
        super().__init__()
        self.name = "PGP Key Extractor"
        self.description = "Extracts PGP public key blocks, UIDs, key IDs, and creation metadata"

        # Track keys across targets
        self.found_keys = {}  # key_id -> {urls, uid, fingerprint}

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)

        if not resp or not resp.text:
            return findings

        page_text = resp.text

        # === Full PGP Public Key Blocks ===
        pgp_blocks = re.findall(
            r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----',
            page_text, re.DOTALL
        )

        if pgp_blocks:
            for i, block in enumerate(pgp_blocks):
                # Extract any embedded comments/headers
                version_match = re.search(r'Version:\s*(.+)', block)
                comment_match = re.search(r'Comment:\s*(.+)', block)

                details = [f"Key block #{i+1} ({len(block)} bytes)"]
                if version_match:
                    details.append(f"  Version: {version_match.group(1)}")
                if comment_match:
                    details.append(f"  Comment: {comment_match.group(1)}")

                findings.append({
                    'check': self.name,
                    'severity': 'high',
                    'finding': f"PGP public key block found",
                    'detail': '\n'.join(details),
                    'url': url,
                    'data': {'pgp_block': block[:500] + '...' if len(block) > 500 else block}
                })

        # === PGP Fingerprints (40 hex chars, often formatted with spaces) ===
        # Spaced format: XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX
        spaced_fps = re.findall(
            r'[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}\s+[A-F0-9]{4}',
            page_text
        )

        # Continuous format: 40 hex chars
        continuous_fps = re.findall(r'\b[A-F0-9]{40}\b', page_text)

        all_fps = set()
        for fp in spaced_fps:
            clean = fp.replace(' ', '')
            all_fps.add(clean)
        for fp in continuous_fps:
            all_fps.add(fp)

        if all_fps:
            for fp in all_fps:
                # Track across targets
                if fp not in self.found_keys:
                    self.found_keys[fp] = {'urls': [], 'fingerprint': fp}
                if url not in self.found_keys[fp]['urls']:
                    self.found_keys[fp]['urls'].append(url)

            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"PGP fingerprints: {len(all_fps)} found",
                'detail': '\n'.join([f"  {fp}" for fp in sorted(all_fps)]),
                'url': url,
                'data': {'fingerprints': sorted(list(all_fps))}
            })

            # Cross-site matches
            for fp in all_fps:
                other_urls = [u for u in self.found_keys[fp]['urls'] if u != url]
                if other_urls:
                    findings.append({
                        'check': self.name,
                        'severity': 'critical',
                        'finding': f"Cross-site PGP key: {fp[:16]}...",
                        'detail': f"Same key on: {', '.join(other_urls)}",
                        'url': url,
                        'data': {'fingerprint': fp, 'also_on': other_urls}
                    })

        # === Short Key IDs (8 or 16 hex chars, often prefixed with 0x) ===
        key_ids = re.findall(r'0x([A-Fa-f0-9]{8,16})\b', page_text)
        if key_ids:
            unique_ids = list(set(key_ids))
            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': f"PGP key IDs: {len(unique_ids)} found",
                'detail': '\n'.join([f"  0x{kid}" for kid in unique_ids[:10]]),
                'url': url,
                'data': {'key_ids': unique_ids}
            })

        # === PGP-related UIDs (Name <email>) near PGP context ===
        # Look for email patterns near PGP-related text
        pgp_context_regions = []
        for match in re.finditer(r'(?:pgp|gpg|public\s*key|fingerprint|key\s*id)', page_text, re.IGNORECASE):
            start = max(0, match.start() - 500)
            end = min(len(page_text), match.end() + 500)
            pgp_context_regions.append(page_text[start:end])

        uid_emails = set()
        for region in pgp_context_regions:
            emails = re.findall(r'[\w\.\+\-]+@[\w\.\-]+\.\w{2,}', region)
            uid_emails.update(emails)

            # Name <email> format
            uid_matches = re.findall(r'([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s*<([\w\.\+\-]+@[\w\.\-]+\.\w{2,})>', region)
            for name, email in uid_matches:
                findings.append({
                    'check': self.name,
                    'severity': 'high',
                    'finding': f"PGP UID: {name} <{email}>",
                    'detail': 'Real name and email from PGP key context',
                    'url': url,
                    'data': {'name': name, 'email': email}
                })

        # === Keyserver URLs ===
        keyserver_urls = re.findall(
            r'(?:keys\.openpgp\.org|keyserver\.ubuntu\.com|pgp\.mit\.edu|keys\.gnupg\.net)[/\w\?\=\&]*',
            page_text, re.IGNORECASE
        )
        if keyserver_urls:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Keyserver references: {len(keyserver_urls)}",
                'detail': '\n'.join(set(keyserver_urls)),
                'url': url
            })

        return findings

    def get_cross_site_keys(self):
        """Return PGP keys seen on multiple sites"""
        return {k: v for k, v in self.found_keys.items() if len(v['urls']) > 1}
