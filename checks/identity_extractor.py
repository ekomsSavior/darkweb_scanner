from .base_check import BaseCheck
import re

class IdentityExtractorCheck(BaseCheck):
    """Extract operator identifiers from page content for cross-site correlation"""

    def __init__(self):
        super().__init__()
        self.name = "Identity Extractor"
        self.description = "Extracts emails, crypto wallets, Telegram/Discord/Wickr handles, and PGP fingerprints"

        # All identifiers found across all targets: type -> {value: [urls]}
        self.global_identifiers = {}

        self.patterns = {
            'email': {
                'regex': r'[\w\.\+\-]+@[\w\.\-]+\.\w{2,}',
                'severity': 'high',
                'exclude': ['example.com', 'example.org', 'test.com', 'localhost']
            },
            'btc_wallet': {
                'regex': r'\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b',
                'severity': 'high',
                'exclude': []
            },
            'xmr_wallet': {
                'regex': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
                'severity': 'high',
                'exclude': []
            },
            'eth_wallet': {
                'regex': r'\b0x[a-fA-F0-9]{40}\b',
                'severity': 'high',
                'exclude': []
            },
            'telegram': {
                'regex': r'(?:t\.me/|telegram\.me/)([\w_]{5,32})',
                'severity': 'medium',
                'exclude': []
            },
            'telegram_handle': {
                'regex': r'@([a-zA-Z][\w]{4,31})(?:\s|$|[,.\)])',
                'severity': 'info',
                'exclude': ['gmail', 'yahoo', 'hotmail', 'outlook', 'proton', 'media', 'keyframes', 'import', 'charset', 'font-face']
            },
            'discord_invite': {
                'regex': r'(?:discord\.gg|discord\.com/invite)/([a-zA-Z0-9\-]+)',
                'severity': 'medium',
                'exclude': []
            },
            'session_id': {
                'regex': r'\b05[a-f0-9]{62,64}\b',
                'severity': 'high',
                'exclude': []
            },
            'wickr': {
                'regex': r'(?:wickr|wickr\.me)[:\s]+([a-zA-Z0-9_\-]+)',
                'severity': 'medium',
                'exclude': []
            },
            'pgp_fingerprint': {
                'regex': r'\b[A-F0-9]{4}(?:\s?[A-F0-9]{4}){9}\b',
                'severity': 'info',
                'exclude': []
            },
            'onion_link': {
                'regex': r'[a-z2-7]{56}\.onion',
                'severity': 'info',
                'exclude': []
            },
        }

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)

        if not resp or not resp.text:
            return findings

        page_text = resp.text
        extracted = {}

        for id_type, spec in self.patterns.items():
            matches = re.findall(spec['regex'], page_text)
            if not matches:
                continue

            # Deduplicate
            unique = list(set(matches))

            # Filter exclusions
            if spec['exclude']:
                unique = [m for m in unique if not any(exc in m.lower() for exc in spec['exclude'])]

            if not unique:
                continue

            extracted[id_type] = unique

            # Track globally for cross-site correlation
            for value in unique:
                key = f"{id_type}:{value}"
                if key not in self.global_identifiers:
                    self.global_identifiers[key] = []
                if url not in self.global_identifiers[key]:
                    self.global_identifiers[key].append(url)

        if not extracted:
            return findings

        # Build findings per type
        for id_type, values in extracted.items():
            severity = self.patterns[id_type]['severity']
            display_name = id_type.replace('_', ' ').title()
            preview = ', '.join(values[:3])
            suffix = f" (+{len(values) - 3} more)" if len(values) > 3 else ""

            findings.append({
                'check': self.name,
                'severity': severity,
                'finding': f"{display_name}: {len(values)} found",
                'detail': f"{preview}{suffix}",
                'url': url,
                'data': {id_type: values}
            })

        # Check for cross-site matches
        cross_site = []
        for id_type, values in extracted.items():
            for value in values:
                key = f"{id_type}:{value}"
                seen_on = self.global_identifiers.get(key, [])
                other_sites = [s for s in seen_on if s != url]
                if other_sites:
                    cross_site.append({
                        'type': id_type,
                        'value': value,
                        'also_on': other_sites
                    })

        if cross_site:
            for match in cross_site[:5]:
                findings.append({
                    'check': self.name,
                    'severity': 'critical',
                    'finding': f"Cross-site {match['type'].replace('_', ' ')}: {match['value'][:40]}",
                    'detail': f"Also found on: {', '.join(match['also_on'])}",
                    'url': url,
                    'data': match
                })

        return findings

    def get_cross_site_report(self):
        """Return all identifiers seen on multiple sites"""
        return {k: v for k, v in self.global_identifiers.items() if len(v) > 1}

    def get_all_identifiers(self):
        """Return all extracted identifiers grouped by type"""
        result = {}
        for key, urls in self.global_identifiers.items():
            id_type, value = key.split(':', 1)
            if id_type not in result:
                result[id_type] = {}
            result[id_type][value] = urls
        return result
