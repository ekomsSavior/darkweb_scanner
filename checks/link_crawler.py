from .base_check import BaseCheck
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import time

class LinkCrawlerCheck(BaseCheck):
    """Crawl target pages to discover links, subpages, and hidden content"""

    def __init__(self):
        super().__init__()
        self.name = "Link Crawler"
        self.description = "Discovers internal/external links, onion references, and hidden paths"
        self.discovered_onions = set()
        self.discovered_internal = {}  # target -> set of internal links
        self.discovered_external = {}  # target -> set of external links

    def run(self, target, tor_session, config=None):
        findings = []
        max_depth = config.get('max_depth', 1) if config else 1
        delay = config.get('delay', 1) if config else 1

        url = target if target.startswith('http') else 'http://' + target
        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc

        visited = set()
        queue = [(url, 0)]
        internal_links = set()
        external_links = set()
        onion_links = set()
        interesting_paths = set()

        while queue:
            current_url, depth = queue.pop(0)

            if current_url in visited:
                continue
            if depth > max_depth:
                continue

            visited.add(current_url)

            if depth > 0:
                time.sleep(delay)

            resp = tor_session.get(current_url)
            if not resp or not resp.text:
                continue

            try:
                soup = BeautifulSoup(resp.text, 'html.parser')
            except Exception:
                continue

            # Extract all links
            for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe']):
                href = tag.get('href') or tag.get('src') or tag.get('action')
                if not href:
                    continue

                # Skip anchors, javascript, mailto
                if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue

                # Resolve relative URLs
                full_url = urljoin(current_url, href)
                parsed = urlparse(full_url)

                # Classify the link
                if parsed.netloc == base_domain:
                    internal_links.add(full_url)
                    # Queue for crawling if within depth
                    if depth + 1 <= max_depth and full_url not in visited:
                        queue.append((full_url, depth + 1))
                elif '.onion' in parsed.netloc:
                    onion_links.add(full_url)
                    self.discovered_onions.add(parsed.netloc)
                else:
                    external_links.add(full_url)

                # Flag interesting paths
                path_lower = parsed.path.lower()
                interesting_extensions = ['.sql', '.bak', '.old', '.log', '.conf', '.ini', '.xml', '.json', '.csv', '.xlsx']
                interesting_dirs = ['/api/', '/admin/', '/debug/', '/test/', '/dev/', '/staging/', '/internal/', '/private/']

                for ext in interesting_extensions:
                    if path_lower.endswith(ext):
                        interesting_paths.add(full_url)
                for d in interesting_dirs:
                    if d in path_lower:
                        interesting_paths.add(full_url)

            # Extract onion addresses from raw text (not just links)
            raw_onions = re.findall(r'[a-z2-7]{56}\.onion', resp.text.lower())
            for onion in raw_onions:
                onion_links.add(f"http://{onion}")
                self.discovered_onions.add(onion)

        # Store for cross-reference
        self.discovered_internal[url] = internal_links
        self.discovered_external[url] = external_links

        # Build findings
        if internal_links:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Internal links: {len(internal_links)} discovered",
                'detail': '\n'.join(sorted(list(internal_links))[:20]),
                'url': url,
                'data': {'internal_links': sorted(list(internal_links))}
            })

        if external_links:
            # External clearnet links from an onion site are interesting
            severity = 'medium' if '.onion' in base_domain else 'info'
            findings.append({
                'check': self.name,
                'severity': severity,
                'finding': f"External links: {len(external_links)} found",
                'detail': '\n'.join(sorted(list(external_links))[:10]),
                'url': url,
                'data': {'external_links': sorted(list(external_links))}
            })

        if onion_links:
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"Onion links: {len(onion_links)} discovered",
                'detail': '\n'.join(sorted(list(onion_links))[:15]),
                'url': url,
                'data': {'onion_links': sorted(list(onion_links))}
            })

        if interesting_paths:
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"Interesting paths: {len(interesting_paths)} found",
                'detail': '\n'.join(sorted(list(interesting_paths))),
                'url': url,
                'data': {'interesting_paths': sorted(list(interesting_paths))}
            })

        findings.append({
            'check': self.name,
            'severity': 'info',
            'finding': f"Crawl stats: {len(visited)} pages visited (depth {max_depth})",
            'url': url
        })

        return findings

    def get_all_onions(self):
        """Return all discovered onion domains across all targets"""
        return self.discovered_onions
