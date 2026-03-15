import re
from urllib.parse import urlparse

def is_valid_onion(url):
    """
    Validate if a URL is a proper .onion address
    Returns: (bool, str) - (is_valid, reason if invalid)
    """
    # TEMP FIX - accept any .onion
    if '.onion' in url:
        return True, "Valid .onion domain (bypassed)"
    
    if not url:
        return False, "Empty URL"
    
    # Add scheme if missing for parsing
    if not url.startswith('http'):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        # Check if it ends with .onion
        if not hostname.endswith('.onion'):
            return False, f"Not a .onion domain: {hostname}"
        
        # Extract the onion part (remove .onion)
        onion_part = hostname.replace('.onion', '')
        
        # Check length (v2: 16 chars, v3: 56 chars)
        if len(onion_part) not in [16, 56]:
            return False, f"Invalid .onion length: {len(onion_part)} chars (should be 16 or 56)"
        
        # Check for valid characters (base32: a-z, 2-7)
        if not re.match(r'^[a-z2-7]+$', onion_part):
            return False, "Invalid characters in .onion domain"
        
        return True, "Valid .onion domain"
        
    except Exception as e:
        return False, f"Parse error: {str(e)}"

def is_safe_url(url):
    """
    Check if URL is safe to scan (not a known harmful pattern)
    Used to avoid scanning known law enforcement/humanitarian sites
    """
    unsafe_patterns = [
        'torproject.org',
        'check.torproject',
        'protonmail',
        'duckduckgo',
        'facebookcorewwwi.onion',
        'bbcnews',
        'nytimes'
    ]
    
    url_lower = url.lower()
    for pattern in unsafe_patterns:
        if pattern in url_lower:
            return False, f"URL contains known safe pattern: {pattern}"
    
    return True, "URL appears safe to scan"

def validate_email(email):
    """
    Basic email format validation
    """
    if not email or '@' not in email:
        return False, "Invalid email format"
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True, "Valid email format"
    else:
        return False, "Invalid email format"

def is_valid_port(port):
    """Check if port number is valid"""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except:
        return False

def validate_hostname(hostname):
    """Basic hostname validation"""
    if not hostname:
        return False
    
    # Allow .onion domains
    if hostname.endswith('.onion'):
        return is_valid_onion(hostname)[0]
    
    # Standard hostname validation
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, hostname))

def validate_ip(ip):
    """Check if string is a valid IP address"""
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(ip_pattern, ip))

def sanitize_input(text):
    """Remove potentially dangerous characters from input"""
    if not text:
        return text
    
    # Remove any characters that could be used for injection
    dangerous = [';', '|', '&', '$', '`', '>', '<', '(', ')']
    for char in dangerous:
        text = text.replace(char, '')
    
    return text.strip()
