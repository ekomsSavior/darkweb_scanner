from .base_check import BaseCheck
import re

class Com764Detector(BaseCheck):
    """Detect Com/764 network indicators on target sites with context-aware filtering"""

    def __init__(self, wordlist_path=None):
        super().__init__()
        self.name = "Com/764 Network Detector"
        self.description = "Detects indicators of Com/764 child exploitation networks"

        # Known Com/764 group names from CAHN report
        self.group_names = [
            '764', '1800', '7997', '2992', '6996',
            'cultist', 'com764', 'com 764', 'c0m764',
            'cord of 764', 'council of 764',
            'harm nation', 'kaskar', 'brad764',
        ]

        # Known Com/764 behavioral indicators
        self.behavioral_indicators = [
            'cut for', 'prove your', 'verification required',
            'content required', 'lorebook', 'grooming',
            'master/slave', 'slave training', 'bricking',
            'content trade', 'content swap', 'love bombing',
            'extortion guide', 'sextortion',
        ]

        # CSAM keywords - terms that ONLY appear in exploitation context
        # These are unambiguous and don't need context filtering
        self.unambiguous_keywords = [
            'child porn', 'kiddie porn', 'cheese pizza',
            'pthc', 'ptsc', 'ptsk',
            'lolicon', 'shotacon', 'shota',
            'pedophile', 'pedo bear', 'preteen',
            'young girl pics', 'young boy pics',
            'underage', 'jailbait', 'hebe',
            'ageplay', 'daddy daughter',
        ]

        # Ambiguous keywords - common words that need context to be suspicious
        # Only flagged when they appear near other indicators
        self.ambiguous_keywords = {
            'cp': ['forum', 'board', 'trade', 'link', 'mega', 'collection', 'share', 'download', 'video', 'content'],
            'capture': ['bait', 'victim', 'target', 'force', 'record', 'blackmail'],
            'lolita': ['board', 'forum', 'city', 'chan', 'image', 'content'],
            'looking for young': ['girl', 'boy', 'teen', 'child'],
            'trade pics': ['private', 'dm', 'wickr', 'session', 'telegram'],
        }

        # Negative context — terms that indicate the page is NOT exploitation content
        self.negative_context = [
            'zero tolerance', 'abuse policy', 'report abuse',
            'child protection', 'ncmec', 'icmec',
            'law enforcement', 'fbi', 'europol', 'interpol',
            'news article', 'news report', 'journalist',
            'research paper', 'academic', 'study finds',
            'arrested for', 'sentenced to', 'convicted of',
            'fighting against', 'combating', 'prevention',
            'copyright', 'company policy', 'terms of service',
            'copy paste', 'checkpoint', 'control panel',
            'competitive programming', 'c++ programming',
        ]

        # Load custom wordlist if provided
        if wordlist_path:
            self._load_wordlist(wordlist_path)

    def _load_wordlist(self, path):
        """Load custom keywords from file"""
        try:
            with open(path, 'r') as f:
                custom_keywords = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
                self.unambiguous_keywords.extend(custom_keywords)
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")

    def _has_negative_context(self, page_text):
        """Check if page has indicators that it's NOT exploitation content"""
        neg_count = 0
        for term in self.negative_context:
            if term in page_text:
                neg_count += 1
        # If 2+ negative indicators, likely a news/policy/research page
        return neg_count >= 2

    def _check_ambiguous_with_context(self, keyword, page_text, context_words):
        """Check if an ambiguous keyword appears near context words (within 200 chars)"""
        positions = [m.start() for m in re.finditer(re.escape(keyword), page_text)]
        for pos in positions:
            # Get surrounding context window (200 chars each side)
            window_start = max(0, pos - 200)
            window_end = min(len(page_text), pos + len(keyword) + 200)
            window = page_text[window_start:window_end]

            for ctx_word in context_words:
                if ctx_word in window:
                    return True
        return False

    def run(self, target, tor_session, config=None):
        """Scan target for Com/764 indicators with context-aware filtering"""
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)

        if not resp:
            return findings

        page_text = resp.text.lower()

        # Check for negative context first
        is_likely_benign = self._has_negative_context(page_text)

        detected_groups = []
        detected_behavior = []
        detected_keywords = []
        detected_ambiguous = []

        # Check for group names (always flag, even on benign pages)
        for group in self.group_names:
            if group.lower() in page_text:
                detected_groups.append(group)

        # Check for behavioral indicators
        for indicator in self.behavioral_indicators:
            if indicator.lower() in page_text:
                detected_behavior.append(indicator)

        # Check unambiguous CSAM keywords
        for keyword in self.unambiguous_keywords:
            if keyword.lower() in page_text:
                detected_keywords.append(keyword)

        # Check ambiguous keywords WITH context requirement
        for keyword, context_words in self.ambiguous_keywords.items():
            if keyword in page_text:
                if self._check_ambiguous_with_context(keyword, page_text, context_words):
                    detected_ambiguous.append(keyword)

        # If page has negative context, downgrade non-group findings
        severity_modifier = 'info' if is_likely_benign else None

        # Build findings
        if detected_groups:
            sev = severity_modifier or ('critical' if '764' in str(detected_groups) else 'high')
            findings.append({
                'check': self.name,
                'severity': sev,
                'finding': f"Com/764 group names detected: {', '.join(detected_groups)}",
                'detail': 'Matches known Com/764 network identifiers from CAHN report'
                          + (' [DOWNGRADED: negative context detected]' if is_likely_benign else ''),
                'url': url
            })

        if detected_behavior:
            sev = severity_modifier or 'high'
            findings.append({
                'check': self.name,
                'severity': sev,
                'finding': f"Behavioral indicators: {', '.join(detected_behavior[:5])}",
                'detail': 'Matches documented grooming/extortion patterns'
                          + (' [DOWNGRADED: negative context detected]' if is_likely_benign else ''),
                'url': url
            })

        if detected_keywords:
            sev = severity_modifier or 'critical'
            findings.append({
                'check': self.name,
                'severity': sev,
                'finding': f"CSAM keywords: {', '.join(detected_keywords[:5])}",
                'detail': 'Unambiguous exploitation language detected'
                          + (' [DOWNGRADED: negative context detected]' if is_likely_benign else ''),
                'url': url
            })

        if detected_ambiguous:
            sev = severity_modifier or 'high'
            findings.append({
                'check': self.name,
                'severity': sev,
                'finding': f"Context-confirmed keywords: {', '.join(detected_ambiguous[:5])}",
                'detail': 'Ambiguous terms confirmed by surrounding exploitation context'
                          + (' [DOWNGRADED: negative context detected]' if is_likely_benign else ''),
                'url': url
            })

        return findings
