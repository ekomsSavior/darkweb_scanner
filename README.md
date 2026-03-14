# DarkWeb Vulnerability Scanner

**Threat Intel tool for scanning .onion infrastructure**

Developed for legitimate threat intelligence operations, red team assessments, and forensic investigation of dark web infrastructure. This scanner conducts text-only analysis of Tor hidden services to identify security misconfigurations, exposed sensitive files, and indicators of criminal networks.

## Features

- Full Tor integration with SOCKS5 proxy support
- Modular vulnerability checking system
- Interactive CLI for real-time control
- No media download - text-only analysis
- Circuit rotation for operational security
- Multi-format reporting (JSON, text, CSV)

## Quick Installation

```bash
# Clone the repository
git clone https://github.com/ekomsSavior/darkweb_scanner.git
cd darkweb_scanner

# Install dependencies 
sudo apt update
sudo apt install tor torify python3-pip -y
pip3 install stem requests[socks] colorama beautifulsoup4 python-nmap PySocks dnspython --break-system-packages

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

Start the scanner:
```bash
python3 vulnscan.py
```

### Available Commands

| Command | Description |
|---------|-------------|
| `targets` | Show all loaded targets |
| `add <url>` | Add a target .onion URL |
| `load <file>` | Load targets from file (one per line) |
| `remove <n>` | Remove target by number |
| `checks` | List all available vulnerability checks |
| `enable <n>` | Enable a specific check |
| `disable <n>` | Disable a specific check |
| `config` | Show current scan configuration |
| `set <key> <val>` | Set configuration value (delay, threads, timeout) |
| `scan` | Start scanning all loaded targets |
| `report [fmt]` | Generate report (text, json, csv) |
| `clear` | Clear all targets |
| `rotate` | Manually rotate Tor circuit |
| `status` | Show scanner status |
| `exit` | Exit the scanner |

### Example Workflow

```
vulnscan> add http://target.onion
vulnscan> targets
vulnscan> checks
vulnscan> set delay 2
vulnscan> scan
vulnscan> report json
vulnscan> exit
```

## Directory Structure

```
darkweb_scanner/
├── vulnscan.py              # Main entry point
├── core/                    # Core modules
│   ├── tor_session.py      # Tor connection management
│   ├── target_manager.py    # Target handling
│   ├── scan_engine.py       # Scan orchestration
│   └── report_builder.py    # Report generation
├── checks/                  # Vulnerability checks
│   ├── base_check.py        # Abstract base class
│   ├── security_headers.py  # HTTP header analysis
│   ├── sensitive_files.py   # Exposed file detection
│   ├── com764_detector.py   # Criminal network indicators
│   └── ...                  # Additional checks
├── utils/                   # Helper functions
├── wordlists/               # Custom detection patterns
├── data/                    # Target files
└── reports/                 # Generated reports
```

## Legal Disclaimer

This tool is designed for legitimate security assessments, threat intelligence operations, and forensic investigations. Users must obtain explicit written authorization before scanning any systems or networks. Unauthorized scanning of .onion services or any other infrastructure may violate local, national, and international laws. The developer assumes no liability for misuse or illegal activities conducted with this software.

## Operational Security

- All traffic routes through Tor SOCKS5 proxy
- No media files are downloaded
- Circuit rotation prevents correlation
- Configurable delays prevent denial of service
- Text-only analysis only

