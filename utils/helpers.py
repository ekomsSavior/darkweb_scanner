import re
from urllib.parse import urlparse

def validate_onion_url(url):
    """Validate if a URL is a proper .onion address"""
    if not url:
        return False
    
    # Add scheme if missing
    if not url.startswith('http'):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        # Check if it ends with .onion
        if not parsed.netloc.endswith('.onion'):
            return False
        
        # Check length (typical .onion v2 is 16 chars, v3 is 56)
        hostname = parsed.netloc.replace('.onion', '')
        # FIX: Previously this did `pass` for invalid lengths, which meant
        # any length was accepted. Onion v2 addresses are 16 chars (base32),
        # v3 are 56 chars. Anything else is not a valid onion address.
        if len(hostname) not in [16, 56]:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-z2-7]+$', hostname):
            return False
        
        return True
    except:
        return False

def extract_domain(url):
    """Extract domain from URL"""
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return url

def strip_html_tags(html):
    """Strip HTML tags from text"""
    if not html:
        return ""
    
    # Simple regex-based stripping (consider BeautifulSoup for production)
    clean = re.sub('<.*?>', '', html)
    clean = re.sub(r'\s+', ' ', clean)
    return clean.strip()

def normalize_url(url):
    """Normalize URL to consistent format"""
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    
    # Remove trailing slash
    url = url.rstrip('/')
    
    return url

def calculate_risk_score(findings):
    """Calculate overall risk score from findings"""
    severity_weights = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 1,
        'info': 0
    }
    
    if not findings:
        return 0
    
    total = 0
    for finding in findings:
        severity = finding.get('severity', 'info').lower()
        total += severity_weights.get(severity, 0)
    
    # Normalize to 0-100 scale
    max_possible = len(findings) * 10
    if max_possible == 0:
        return 0
    
    return min(100, int((total / max_possible) * 100))

def merge_findings(existing_findings, new_findings):
    """Merge two finding lists, removing duplicates"""
    # Simple deduplication by finding description and URL
    seen = set()
    merged = []
    
    for findings in [existing_findings, new_findings]:
        for f in findings:
            key = (f.get('finding', ''), f.get('url', ''))
            if key not in seen:
                seen.add(key)
                merged.append(f)
    
    return merged
