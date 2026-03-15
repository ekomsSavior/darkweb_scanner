# Scanner configuration settings

# Tor settings
TOR_PROXY_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_PASSWORD = None  # Set if using password authentication

# Default scan settings
DEFAULT_SCAN_CONFIG = {
    'delay': 1,  # Seconds between requests
    'threads': 1,  # Parallel threads (1 = sequential)
    'timeout': 15,  # Request timeout in seconds
    'rotate_circuit_every': 10,  # Rotate Tor circuit every N requests
    'max_depth': 1,  # Crawl depth (1 = homepage only)
    'follow_redirects': True,
    'check_https': True,  # Check both HTTP and HTTPS
    'verify_ssl': False,  # Don't verify SSL certs for .onion
}

# Paths
DATA_DIR = 'data'
REPORT_DIR = 'reports'
WORDLIST_DIR = 'wordlists'

# Risk thresholds
RISK_THRESHOLDS = {
    'critical': 80,
    'high': 60,
    'medium': 40,
    'low': 20
}

# User agent strings to rotate (optional)
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
]
