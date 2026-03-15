from .base_check import BaseCheck
import re

class Com764Detector(BaseCheck):
    """Detect Com/764 network indicators on target sites"""
    
    def __init__(self, wordlist_path=None):
        super().__init__()
        self.name = "Com/764 Network Detector"
        self.description = "Detects indicators of Com/764 child exploitation networks"
        
        # Known Com/764 group names from the report
        self.group_names = [
            '764', '1800', '7997', '2992', 'cultist', 'com764', 'com 764',
            'c0m764', 'cord of 764', 'council of 764'
        ]
        
        # Known Com/764 behavioral indicators
        self.behavioral_indicators = [
            'cut for', 'prove your', 'verification', 'content required',
            'lorebook', 'grooming', 'master/slave', 'slave training'
        ]
        
        # CSAM-related keywords from the report
        self.csam_keywords = [
            'cp', 'child porn', 'kiddie porn', 'cheese pizza', 'lolicon', 'shota',
            'lolita', 'pedo', 'pedophile', 'preteen', 'young girl', 'young boy',
            'trade pics', 'mega link', 'thothub', 'capture', 'baiting'
        ]
        
        # Load custom wordlist if provided
        if wordlist_path:
            self._load_wordlist(wordlist_path)
    
    def _load_wordlist(self, path):
        """Load custom keywords from file"""
        try:
            with open(path, 'r') as f:
                custom_keywords = [line.strip() for line in f if line.strip()]
                self.csam_keywords.extend(custom_keywords)
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")
    
    def run(self, target, tor_session, config=None):
        """Scan target for Com/764 indicators"""
        findings = []
        
        url = target if target.startswith('http') else 'http://' + target
        resp = tor_session.get(url)
        
        if not resp:
            return findings
        
        # Get page text
        page_text = resp.text.lower()
        
        # Track detected indicators
        detected_groups = []
        detected_behavior = []
        detected_keywords = []
        
        # Check for group names
        for group in self.group_names:
            if group.lower() in page_text:
                detected_groups.append(group)
        
        # Check for behavioral indicators
        for indicator in self.behavioral_indicators:
            if indicator.lower() in page_text:
                detected_behavior.append(indicator)
        
        # Check for CSAM keywords
        for keyword in self.csam_keywords:
            if keyword.lower() in page_text:
                detected_keywords.append(keyword)
        
        # Add findings if any indicators found
        if detected_groups:
            findings.append({
                'check': self.name,
                'severity': 'critical' if '764' in str(detected_groups) else 'high',
                'finding': f"Com/764 group names detected: {', '.join(detected_groups)}",
                'detail': 'Matches known Com/764 network identifiers from CAHN report',
                'url': url
            })
        
        if detected_behavior:
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"Com/764 behavioral indicators: {', '.join(detected_behavior[:3])}",
                'detail': 'Matches documented grooming/extortion patterns',
                'url': url
            })
        
        if detected_keywords:
            findings.append({
                'check': self.name,
                'severity': 'critical',
                'finding': f"CSAM-related keywords: {', '.join(detected_keywords[:5])}",
                'detail': 'Site contains language associated with exploitation content',
                'url': url
            })
        
        return findings
