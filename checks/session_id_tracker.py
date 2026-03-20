from .base_check import BaseCheck
import re

class SessionIDTracker(BaseCheck):
    """Track Session messenger IDs across sites"""

    def __init__(self):
        super().__init__()
        self.name = "Session ID Tracker"
        self.description = "Detects Session messenger IDs (popular in Com/764 networks)"

        # Session IDs are 64-66 character hex strings starting with 05
        self.session_pattern = r'05[a-f0-9]{62,64}'

        # Store found IDs for cross-reference across targets
        # Maps session_id -> list of URLs where it was found
        self.seen_ids = {}

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)

        if not resp or not resp.text:
            return findings

        # Find all Session IDs in the page
        session_ids = re.findall(self.session_pattern, resp.text)

        if session_ids:
            unique_ids = list(set(session_ids))

            # Check for cross-site matches before updating
            cross_site_ids = []
            for sid in unique_ids:
                if sid in self.seen_ids and url not in self.seen_ids[sid]:
                    cross_site_ids.append(sid)

            # Record all IDs with their source URLs
            for sid in unique_ids:
                if sid not in self.seen_ids:
                    self.seen_ids[sid] = []
                if url not in self.seen_ids[sid]:
                    self.seen_ids[sid].append(url)

            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"Found {len(unique_ids)} Session messenger IDs",
                'detail': f"IDs: {', '.join(unique_ids[:3])}" + ("..." if len(unique_ids) > 3 else ""),
                'url': url,
                'session_ids': unique_ids
            })

            # Flag cross-site matches
            if cross_site_ids:
                for sid in cross_site_ids:
                    prev_sites = [s for s in self.seen_ids[sid] if s != url]
                    findings.append({
                        'check': self.name,
                        'severity': 'critical',
                        'finding': f"Cross-site Session ID: {sid[:16]}...",
                        'detail': f"Same ID found on: {', '.join(prev_sites)}",
                        'url': url,
                        'data': {'session_id': sid, 'also_seen_on': prev_sites}
                    })

        return findings

    def get_cross_site_report(self):
        """Return all IDs seen on multiple sites"""
        return {sid: urls for sid, urls in self.seen_ids.items() if len(urls) > 1}
