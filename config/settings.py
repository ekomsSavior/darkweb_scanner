# Scanner configuration settings
import os

# Tor settings
# FIX: Use environment variables for sensitive config instead of hardcoding.
# Set TOR_PASSWORD via: export TOR_PASSWORD=yourpassword
# Hardcoding passwords in source means anyone with repo access sees them.
TOR_PROXY_PORT = int(os.environ.get('TOR_PROXY_PORT', 9050))
TOR_CONTROL_PORT = int(os.environ.get('TOR_CONTROL_PORT', 9051))
TOR_PASSWORD = os.environ.get('TOR_PASSWORD')

# Default scan settings
DEFAULT_SCAN_CONFIG = {
    'delay': 1,           # Seconds between requests
    'threads': 1,         # Parallel threads (1 = sequential)
    'timeout': 15,        # Request timeout in seconds
    'rotate_circuit_every': 10,  # Rotate Tor circuit every N requests
    'max_depth': 1,       # Crawl depth (1 = homepage only)
    'follow_redirects': True,
    'check_https': True,  # Check both HTTP and HTTPS
    'verify_ssl': False,  # Don't verify SSL certs for .onion
}

# Paths
# FIX: Relative paths break when the scanner is run from a different working directory.
# All dirs are now relative to the project root (where this file lives), not cwd.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(_PROJECT_ROOT, 'data')
REPORT_DIR = os.path.join(_PROJECT_ROOT, 'reports')
WORDLIST_DIR = os.path.join(_PROJECT_ROOT, 'wordlists')
STATE_DIR = os.path.join(_PROJECT_ROOT, 'state')

# Risk thresholds
RISK_THRESHOLDS = {
    'critical': 80,
    'high': 60,
    'medium': 40,
    'low': 20
}

# User agent strings to rotate
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/109.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0',
]
