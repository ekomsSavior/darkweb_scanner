from .base_check import BaseCheck
import ssl
import socket
import re
from datetime import datetime

class SSLAnalyzerCheck(BaseCheck):
    """Analyze SSL/TLS certificates for intel — real domains, org names, emails"""

    def __init__(self):
        super().__init__()
        self.name = "SSL/TLS Certificate Analyzer"
        self.description = "Extracts intel from TLS certs: real domains, org names, SANs, issuer info"

    def run(self, target, tor_session, config=None):
        findings = []

        url = target if target.startswith('http') else 'http://' + target
        timeout = config.get('timeout', 10) if config else 10

        # Try HTTPS version
        https_url = url.replace('http://', 'https://')
        resp = tor_session.get(https_url, timeout=timeout)

        if not resp:
            return findings

        # Check if we got redirected to HTTPS or if HTTPS is available
        actual_url = resp.url if hasattr(resp, 'url') else https_url

        # Try to extract cert info via the response
        # requests doesn't expose raw certs easily, so we also check headers
        # for cert-related info and try direct SSL connection for non-.onion

        # For .onion sites, check if they serve HTTPS at all (unusual)
        if '.onion' in url:
            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': 'HTTPS available on .onion site',
                'detail': 'Onion sites using HTTPS may leak certificate info (real domains, org names)',
                'url': https_url
            })

        # Check response for certificate-related headers
        if resp.headers:
            # Public-Key-Pins header
            pkp = resp.headers.get('Public-Key-Pins') or resp.headers.get('Public-Key-Pins-Report-Only')
            if pkp:
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': f"Public Key Pinning: {pkp[:80]}",
                    'url': actual_url
                })

            # Expect-CT header
            expect_ct = resp.headers.get('Expect-CT')
            if expect_ct:
                findings.append({
                    'check': self.name,
                    'severity': 'info',
                    'finding': f"Expect-CT: {expect_ct[:80]}",
                    'url': actual_url
                })

        # For non-.onion targets, try direct SSL cert extraction
        hostname = url.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]

        if not hostname.endswith('.onion'):
            cert_info = self._get_cert_info(hostname, timeout)
            if cert_info:
                findings.extend(self._analyze_cert(cert_info, actual_url))

        # Check if site redirects from onion to clearnet (massive OPSEC failure)
        if '.onion' in url and resp.url and '.onion' not in resp.url:
            findings.append({
                'check': self.name,
                'severity': 'critical',
                'finding': f"OPSEC FAILURE: .onion redirects to clearnet: {resp.url}",
                'detail': 'Hidden service redirects to a clearnet domain, exposing real infrastructure',
                'url': url,
                'data': {'clearnet_redirect': resp.url}
            })

        return findings

    def _get_cert_info(self, hostname, timeout):
        """Extract SSL certificate from a host.

        IMPORTANT: We use CERT_REQUIRED here instead of CERT_NONE.
        With CERT_NONE, Python's ssl module returns an empty dict from
        getpeercert(binary_form=False), making cert extraction useless.
        With CERT_REQUIRED (or CERT_OPTIONAL), the full cert dict is returned.

        We also set check_hostname=False because we want the cert data even
        if the hostname doesn't match (common on darkweb infrastructure).

        NOTE: This method uses a direct socket connection, NOT the Tor proxy.
        It should ONLY be called for non-.onion targets (the caller already
        checks for this). For clearnet targets scanned through Tor, be aware
        this reveals the scanner's real IP to the target on port 443.
        If OPSEC matters, skip this check entirely or route through Tor's
        SOCKS proxy with a CONNECT tunnel.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            # FIX: CERT_NONE causes getpeercert() to return an empty dict.
            # CERT_REQUIRED actually retrieves the certificate data.
            context.verify_mode = ssl.CERT_REQUIRED

            with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        return cert
        except ssl.SSLCertVerificationError:
            # Cert verification failed (self-signed, expired, etc.)
            # Fall back to CERT_NONE and use binary form
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, 443), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # With CERT_NONE, binary_form=True is the only way to get cert data
                        der_cert = ssock.getpeercert(binary_form=True)
                        if der_cert:
                            # Parse basic info from DER using ssl module
                            parsed = ssl.DER_cert_to_PEM_cert(der_cert)
                            return {'raw_pem': parsed, 'der': der_cert}
            except Exception:
                pass
        except Exception:
            pass
        return None

    def _analyze_cert(self, cert, url):
        """Analyze certificate fields for intel"""
        findings = []

        # Subject (who the cert is for)
        subject = dict(x[0] for x in cert.get('subject', []) if x)
        if subject:
            cn = subject.get('commonName', '')
            org = subject.get('organizationName', '')
            country = subject.get('countryName', '')
            state = subject.get('stateOrProvinceName', '')
            locality = subject.get('localityName', '')

            subject_parts = []
            if cn:
                subject_parts.append(f"CN={cn}")
            if org:
                subject_parts.append(f"O={org}")
            if country:
                subject_parts.append(f"C={country}")
            if state:
                subject_parts.append(f"ST={state}")
            if locality:
                subject_parts.append(f"L={locality}")

            findings.append({
                'check': self.name,
                'severity': 'medium',
                'finding': f"Certificate subject: {', '.join(subject_parts)}",
                'detail': 'Certificate subject may reveal real identity/organization',
                'url': url,
                'data': {'subject': subject}
            })

            if org:
                findings.append({
                    'check': self.name,
                    'severity': 'high',
                    'finding': f"Organization disclosed in cert: {org}",
                    'detail': f'Location: {locality or "?"}, {state or "?"}, {country or "?"}',
                    'url': url
                })

        # Issuer
        issuer = dict(x[0] for x in cert.get('issuer', []) if x)
        if issuer:
            issuer_cn = issuer.get('commonName', '')
            issuer_org = issuer.get('organizationName', '')
            if issuer_cn:
                # Self-signed = operator generated it themselves
                subject_cn = subject.get('commonName', '') if subject else ''
                if issuer_cn == subject_cn:
                    findings.append({
                        'check': self.name,
                        'severity': 'info',
                        'finding': f"Self-signed certificate (issuer = subject)",
                        'url': url
                    })
                else:
                    findings.append({
                        'check': self.name,
                        'severity': 'info',
                        'finding': f"Issuer: {issuer_cn} ({issuer_org or 'unknown org'})",
                        'url': url
                    })

        # Subject Alternative Names (SANs) — can leak additional domains
        sans = cert.get('subjectAltName', [])
        if sans:
            san_list = [value for typ, value in sans]
            findings.append({
                'check': self.name,
                'severity': 'high',
                'finding': f"Subject Alt Names: {len(san_list)} domains",
                'detail': '\n'.join(san_list[:20]),
                'url': url,
                'data': {'sans': san_list}
            })

            # Check for clearnet domains in SANs of an onion site
            clearnet_sans = [s for s in san_list if not s.endswith('.onion')]
            if clearnet_sans:
                findings.append({
                    'check': self.name,
                    'severity': 'critical',
                    'finding': f"Clearnet domains in cert SANs: {', '.join(clearnet_sans[:5])}",
                    'detail': 'Certificate reveals real domain names behind the hidden service',
                    'url': url,
                    'data': {'clearnet_domains': clearnet_sans}
                })

        # Validity dates
        not_before = cert.get('notBefore', '')
        not_after = cert.get('notAfter', '')
        if not_after:
            try:
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                if expiry < datetime.utcnow():
                    findings.append({
                        'check': self.name,
                        'severity': 'medium',
                        'finding': f"Certificate expired: {not_after}",
                        'url': url
                    })
            except ValueError:
                pass

        # Serial number (can be used for cert tracking across sites)
        serial = cert.get('serialNumber', '')
        if serial:
            findings.append({
                'check': self.name,
                'severity': 'info',
                'finding': f"Certificate serial: {serial}",
                'detail': 'Serial number can be used to track cert reuse across sites',
                'url': url
            })

        return findings
