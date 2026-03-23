import re
import json

def parse_report_pdf(pdf_path):
    """
    Parse a PDF report to extract .onion URLs and identifiers
    This is a placeholder - you'll need to install PyPDF2 for actual PDF parsing
    """
    try:
        # Try to import PyPDF2 if available
        import PyPDF2
        urls = []
        
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)
            for page in reader.pages:
                text = page.extract_text()
                # Find .onion URLs
                found_urls = re.findall(r'[a-zA-Z0-9]{16,56}\.onion', text)
                urls.extend(found_urls)
        
        return list(set(urls))  # Remove duplicates
    except ImportError:
        print("[!] PyPDF2 not installed. Install with: pip3 install PyPDF2")
        return []
    except Exception as e:
        print(f"[!] Error parsing PDF: {e}")
        return []

def extract_identifiers(text):
    """Extract various identifiers from text"""
    identifiers = {
        'emails': [],
        'session_ids': [],
        'btc_wallets': [],
        'urls': [],
        'telegram': [],
        'discord': []
    }
    
    # Email pattern
    emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    identifiers['emails'] = list(set(emails))
    
    # Session IDs (05 followed by hex)
    session_ids = re.findall(r'05[a-f0-9]{62,64}', text)
    identifiers['session_ids'] = list(set(session_ids))
    
    # Bitcoin wallets
    btc_patterns = [
        r'bc1[a-zA-Z0-9]{25,39}',  # bech32
        r'1[a-zA-Z0-9]{25,33}',     # legacy
        r'3[a-zA-Z0-9]{25,33}'      # segwit
    ]
    for pattern in btc_patterns:
        found = re.findall(pattern, text)
        identifiers['btc_wallets'].extend(found)
    identifiers['btc_wallets'] = list(set(identifiers['btc_wallets']))
    
    # Telegram handles
    telegram = re.findall(r'@[\w_]+|t\.me/[\w_]+|telegram\.me/[\w_]+', text)
    identifiers['telegram'] = list(set(telegram))
    
    # Discord invites
    discord = re.findall(r'discord\.gg/[\w]+|discord\.com/invite/[\w]+', text)
    identifiers['discord'] = list(set(discord))
    
    # URLs
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    identifiers['urls'] = list(set(urls))
    
    return identifiers

def parse_keyword_file(filepath):
    """Parse a keyword file (one per line, # for comments)"""
    keywords = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    keywords.append(line.lower())
    except Exception as e:
        print(f"[!] Error parsing keyword file: {e}")
    
    return keywords

def parse_targets_file(filepath):
    """Parse a targets file (one URL per line)"""
    targets = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Add scheme if missing
                    if not line.startswith('http'):
                        line = 'http://' + line
                    targets.append(line)
    except Exception as e:
        print(f"[!] Error parsing targets file: {e}")
    
    return targets

def parse_json_report(json_path):
    """Parse your team's JSON report format"""
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        # Extract targets (adjust based on your actual JSON structure)
        targets = []
        if isinstance(data, list):
            for item in data:
                if 'url' in item:
                    targets.append(item['url'])
                elif 'domain' in item:
                    targets.append('http://' + item['domain'])
        elif isinstance(data, dict):
            if 'sites' in data:
                for site in data['sites']:
                    if 'url' in site:
                        targets.append(site['url'])
            elif 'targets' in data:
                targets = data['targets']
        
        return list(set(targets))
    except Exception as e:
        print(f"[!] Error parsing JSON: {e}")
        return []
