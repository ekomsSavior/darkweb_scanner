from .base_check import BaseCheck
import re

class RobotsSitemapCheck(BaseCheck):
    """Parse robots.txt and sitemap.xml for intelligence gathering"""

    def __init__(self):
        super().__init__()
        self.name = "Robots & Sitemap Intel"
        self.description = "Extracts hidden paths from robots.txt and sitemap.xml"

    def run(self, target, tor_session, config=None):
        findings = []

        base = target if target.startswith('http') else 'http://' + target
        base = base.rstrip('/')
        timeout = config.get('timeout', 10) if config else 10

        # === robots.txt ===
        robots_url = base + '/robots.txt'
        resp = tor_session.get(robots_url, timeout=timeout)

        if resp and resp.status_code == 200 and 'user-agent' in resp.text.lower():
            disallowed = []
            allowed = []
            sitemaps = []
            crawl_delay = None

            for line in resp.text.splitlines():
                line = line.strip()
                lower = line.lower()

                if lower.startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        disallowed.append(path)
                elif lower.startswith('allow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        allowed.append(path)
                elif lower.startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    # Handle 'sitemap: http://...' vs 'sitemap:http://...'
                    if not sitemap_url.startswith('http'):
                        sitemap_url = 'http:' + sitemap_url
                    sitemaps.append(sitemap_url)
                elif lower.startswith('crawl-delay:'):
                    try:
                        crawl_delay = int(line.split(':', 1)[1].strip())
                    except ValueError:
                        pass

            if disallowed:
                # Disallowed paths are gold — they're what the admin wants hidden
                findings.append({
                    'check': self.name,
                    'severity': 'medium',
                    'finding': f"robots.txt: {len(disallowed)} disallowed paths",
                    'detail': '\n'.join(disallowed[:25]),
                    'url': robots_url,
                    'data': {'disallowed_paths': disallowed}
                })

                # Flag particularly interesting disallowed paths
                sensitive_patterns = ['admin', 'backup', 'config', 'database', 'db', 'dump',
                                       'private', 'secret', 'internal', 'api', 'debug', 'test',
                                       '.git', '.env', 'upload', 'panel', 'cgi-bin', 'phpmyadmin']
                hot_paths = [p for p in disallowed
                             if any(s in p.lower() for s in sensitive_patterns)]
                if hot_paths:
                    findings.append({
                        'check': self.name,
                        'severity': 'high',
                        'finding': f"Sensitive disallowed paths: {len(hot_paths)}",
                        'detail': '\n'.join(hot_paths),
                        'url': robots_url,
                        'data': {'sensitive_disallowed': hot_paths}
                    })

            if sitemaps:
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': f"Sitemaps referenced: {len(sitemaps)}",
                    'detail': '\n'.join(sitemaps),
                    'url': robots_url
                })

            if crawl_delay:
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': f"Crawl-Delay: {crawl_delay} seconds",
                    'url': robots_url
                })

        # === sitemap.xml ===
        sitemap_url = base + '/sitemap.xml'
        resp = tor_session.get(sitemap_url, timeout=timeout)

        if resp and resp.status_code == 200 and '<url' in resp.text.lower():
            urls = re.findall(r'<loc>(.*?)</loc>', resp.text, re.IGNORECASE)
            if urls:
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': f"sitemap.xml: {len(urls)} URLs listed",
                    'detail': '\n'.join(urls[:20]) + (f'\n... and {len(urls) - 20} more' if len(urls) > 20 else ''),
                    'url': sitemap_url,
                    'data': {'sitemap_urls': urls}
                })

                # Look for interesting patterns in sitemap
                api_urls = [u for u in urls if '/api/' in u.lower()]
                admin_urls = [u for u in urls if 'admin' in u.lower()]
                if api_urls:
                    findings.append({
                        'check': self.name,
                        'severity': 'medium',
                        'finding': f"API endpoints in sitemap: {len(api_urls)}",
                        'detail': '\n'.join(api_urls[:10]),
                        'url': sitemap_url
                    })
                if admin_urls:
                    findings.append({
                        'check': self.name,
                        'severity': 'high',
                        'finding': f"Admin paths in sitemap: {len(admin_urls)}",
                        'detail': '\n'.join(admin_urls[:10]),
                        'url': sitemap_url
                    })

        return findings
