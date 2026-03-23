from .base_check import BaseCheck
import hashlib
import os

class SensitiveFilesCheck(BaseCheck):
    """Check for exposed sensitive files and directories"""

    def __init__(self, wordlist_path=None):
        super().__init__()
        self.name = "Sensitive Files"
        self.description = "Checks for exposed sensitive files and directories"

        # Default paths to check
        self.paths = [
            # Version control
            '/.git/HEAD', '/.git/config', '/.svn/entries', '/.hg/',

            # Backups and archives
            '/backup.zip', '/backup.tar.gz', '/backup.sql', '/backup/',
            '/backups/', '/dump.sql', '/db.sql', '/database.sql',
            '/www.zip', '/site.zip', '/website.zip', '/public_html.zip',

            # Configuration files
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/config.php', '/config.php.bak', '/wp-config.php', '/wp-config.php.bak',
            '/configuration.php', '/settings.php', '/app.config',

            # Sensitive info
            '/robots.txt', '/.htaccess', '/.htpasswd', '/.well-known/security.txt',
            '/phpinfo.php', '/info.php', '/test.php', '/.bash_history',

            # Admin interfaces
            '/admin/', '/administrator/', '/login/', '/wp-admin/',
            '/phpmyadmin/', '/pma/', '/myadmin/', '/adminer/',

            # Common directories to check for listing
            '/uploads/', '/files/', '/images/', '/assets/', '/static/',

            # Logs
            '/logs/', '/log/', '/error_log', '/access.log', '/debug.log'
        ]

        # Load custom wordlist if provided
        if wordlist_path and os.path.exists(wordlist_path):
            self._load_wordlist(wordlist_path)

    def _load_wordlist(self, path):
        """Load custom paths from file"""
        try:
            with open(path, 'r') as f:
                custom_paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                self.paths.extend(custom_paths)
                print(f"[+] Loaded {len(custom_paths)} custom paths from {path}")
        except Exception as e:
            print(f"[!] Error loading wordlist: {e}")

    def _get_baseline(self, base, tor_session, timeout):
        """Fetch a known-bogus path to fingerprint catch-all/SPA responses"""
        bogus_url = base + '/a9z8x7w6v5_nonexistent_path_baseline'
        resp = tor_session.get(bogus_url, timeout=timeout)
        if resp and resp.status_code == 200:
            return {
                'size': len(resp.content),
                'hash': hashlib.sha256(resp.content).hexdigest()
            }
        return None

    def _is_false_positive(self, response, baseline):
        """Check if response matches the catch-all baseline (SPA false positive)"""
        if not baseline:
            return False

        resp_size = len(response.content)
        resp_hash = hashlib.md5(response.content).hexdigest()

        # Exact content match = catch-all page
        if resp_hash == baseline['hash']:
            return True

        # Size within 50 bytes and same general range = likely catch-all
        if abs(resp_size - baseline['size']) < 50 and resp_size > 200:
            return True

        return False

    def run(self, target, tor_session, config=None):
        """Check for exposed sensitive files"""
        findings = []

        # Normalize base URL
        base = target if target.startswith('http') else 'http://' + target
        base = base.rstrip('/')

        timeout = config.get('timeout', 10) if config else 10

        # Get baseline for false positive detection
        baseline = self._get_baseline(base, tor_session, timeout)
        if baseline:
            print(f"    [*] SPA baseline detected (hash: {baseline['hash'][:8]}..., size: {baseline['size']})")

        for path in self.paths:
            url = base + path

            try:
                if '.onion' in url:
                    url = url.replace('https://', 'http://')

                resp = tor_session.get(url, timeout=timeout)

                if resp:
                    status = resp.status_code

                    if status == 200:
                        # Skip if it matches the catch-all baseline
                        if self._is_false_positive(resp, baseline):
                            continue

                        severity = self._determine_severity(path, resp)
                        findings.append({
                            'check': self.name,
                            'severity': severity,
                            'finding': f"Exposed file: {path}",
                            'detail': f'File accessible at {url} (HTTP {status}, {len(resp.content)} bytes)',
                            'url': url,
                            'status_code': status
                        })

                    elif status == 403:
                        findings.append({
                            'check': self.name,
                            'severity': 'info',
                            'finding': f"Access forbidden: {path}",
                            'detail': 'File may exist but access is forbidden (403)',
                            'url': url,
                            'status_code': status
                        })

                    elif status == 401:
                        findings.append({
                            'check': self.name,
                            'severity': 'low',
                            'finding': f"Authentication required: {path}",
                            'detail': 'Path requires authentication (401) - may contain sensitive data',
                            'url': url,
                            'status_code': status
                        })

            except Exception:
                pass

        return findings

    def _determine_severity(self, path, response):
        """Determine severity based on file type and content"""
        path_lower = path.lower()

        # Critical severity files
        if any(critical in path_lower for critical in ['.git', '.env', '.htpasswd', 'backup', 'dump.sql', 'wp-config.php']):
            return 'critical'

        # High severity
        elif any(high in path_lower for high in ['admin', 'phpinfo', 'config', '.svn', '.hg']):
            return 'high'

        # Medium severity
        elif path_lower in ['/robots.txt', '/.htaccess', '/logs/', '/uploads/']:
            return 'medium'

        # Check response content for additional clues
        if response and response.text:
            if 'password' in response.text.lower() or 'passwd' in response.text.lower():
                return 'critical'
            if 'database' in response.text.lower() or 'mysql' in response.text.lower():
                return 'high'

        return 'medium'
