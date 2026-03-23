from .base_check import BaseCheck
from bs4 import BeautifulSoup
import re

class PageMetadataCheck(BaseCheck):
    """Extract page metadata, language hints, timezone indicators, and operator fingerprints"""

    def __init__(self):
        super().__init__()
        self.name = "Page Metadata"
        self.description = "Extracts titles, meta tags, language, timezone hints, and operator fingerprints"

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)

        if not resp or not resp.text:
            return findings

        try:
            soup = BeautifulSoup(resp.text, 'html.parser')
        except Exception:
            return findings

        # === Page Title ===
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Page title: {title_tag.string.strip()[:100]}",
                'url': url
            })

        # === Meta Tags ===
        meta_info = {}
        for meta in soup.find_all('meta'):
            name = meta.get('name', meta.get('property', '')).lower()
            content = meta.get('content', '')
            if name and content:
                meta_info[name] = content

        interesting_meta = ['description', 'keywords', 'author', 'generator',
                             'og:title', 'og:description', 'og:site_name',
                             'twitter:creator', 'twitter:site',
                             'robots', 'copyright']

        found_meta = {k: v for k, v in meta_info.items() if k in interesting_meta}
        if found_meta:
            details = [f"  {k}: {v[:80]}" for k, v in found_meta.items()]
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Meta tags: {len(found_meta)} interesting",
                'detail': '\n'.join(details),
                'url': url,
                'data': {'meta_tags': found_meta}
            })

        # Author / generator = operator fingerprint
        if 'author' in found_meta:
            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': f"Author disclosed: {found_meta['author'][:60]}",
                'detail': 'Meta author tag reveals operator identity',
                'url': url
            })

        # === Language Detection ===
        lang_indicators = []

        # HTML lang attribute
        html_tag = soup.find('html')
        if html_tag and html_tag.get('lang'):
            lang_indicators.append(f"HTML lang: {html_tag['lang']}")

        # Content-Language header
        content_lang = resp.headers.get('Content-Language')
        if content_lang:
            lang_indicators.append(f"Content-Language: {content_lang}")

        # Meta language tags
        for key in ['language', 'content-language', 'og:locale']:
            if key in meta_info:
                lang_indicators.append(f"meta {key}: {meta_info[key]}")

        # Charset
        charset_meta = soup.find('meta', charset=True)
        if charset_meta:
            lang_indicators.append(f"Charset: {charset_meta['charset']}")

        if lang_indicators:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Language indicators: {len(lang_indicators)}",
                'detail': '\n'.join([f"  {lang}" for lang in lang_indicators]),
                'url': url,
                'data': {'languages': lang_indicators}
            })

        # === Timezone Hints ===
        page_text = resp.text
        tz_patterns = [
            (r'(?:UTC|GMT)\s*[+-]\s*\d{1,2}(?::\d{2})?', 'UTC offset'),
            (r'(?:America|Europe|Asia|Africa|Pacific|Atlantic)/[A-Z][a-z]+(?:_[A-Z][a-z]+)*', 'IANA timezone'),
            (r'(?:EST|CST|MST|PST|EDT|CDT|MDT|PDT|CET|EET|IST|JST|KST|AEST)', 'Timezone abbreviation'),
        ]

        tz_hits = []
        for pattern, tz_type in tz_patterns:
            matches = re.findall(pattern, page_text)
            for m in matches:
                tz_hits.append(f"{tz_type}: {m}")

        if tz_hits:
            unique_tz = list(set(tz_hits))
            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': f"Timezone indicators: {len(unique_tz)}",
                'detail': '\n'.join([f"  {t}" for t in unique_tz[:10]]),
                'url': url,
                'data': {'timezones': unique_tz}
            })

        # === Comments in HTML ===
        # FIX: Removed dead code above. The old approach used a broken lambda
        # that checked `isinstance(...) is False` (identity check, not boolean)
        # and `hasattr(text, 'prefix') is False` (makes no sense for Comment detection).
        # The variable was assigned but never used. Using Comment type directly.
        from bs4 import Comment
        html_comments = soup.find_all(string=lambda text: isinstance(text, Comment))

        interesting_comments = []
        for comment in html_comments:
            text = comment.strip()
            if len(text) > 5:
                # Skip common framework comments
                if any(skip in text.lower() for skip in ['[if ', 'endif', 'google tag', 'analytics']):
                    continue
                interesting_comments.append(text[:100])

        if interesting_comments:
            findings.append({
                'check': self.name,
                'severity': 'low',
                'finding': f"HTML comments: {len(interesting_comments)} found",
                'detail': '\n'.join([f"  <!-- {c} -->" for c in interesting_comments[:10]]),
                'url': url,
                'data': {'comments': interesting_comments}
            })

        # === Favicon hash (useful for Shodan correlation) ===
        favicon_link = soup.find('link', rel=lambda r: r and 'icon' in ' '.join(r).lower() if isinstance(r, list) else r and 'icon' in r.lower())
        if favicon_link and favicon_link.get('href'):
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Favicon: {favicon_link['href'][:80]}",
                'url': url
            })

        # === Error page fingerprinting ===
        error_url = url.rstrip('/') + '/a9z8x7_404_test_page'
        error_resp = tor_session.get(error_url)
        if error_resp and error_resp.text:
            error_text = error_resp.text.lower()
            error_sigs = {
                'Apache': 'apache',
                'Nginx': 'nginx',
                'IIS': 'microsoft-iis',
                'LiteSpeed': 'litespeed',
                'Caddy': 'caddy',
                'Tomcat': 'tomcat',
                'Express': 'cannot get',
                'Django': 'django',
                'Flask': 'werkzeug',
                'Laravel': 'laravel',
                'Rails': 'routing error',
                'WordPress': 'wordpress',
            }
            for tech, sig in error_sigs.items():
                if sig in error_text:
                    findings.append({
                        'check': self.name,
                        'severity': 'low',
                        'finding': f"Error page reveals: {tech}",
                        'detail': f'404 page contains "{sig}" signature',
                        'url': error_url
                    })
                    break

        return findings
