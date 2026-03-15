import os
import requests
import stem
import stem.connection
from stem.control import Controller
import time
import random
import logging

logger = logging.getLogger(__name__)

class TorSession:
    def __init__(self, proxy_port=9050, control_port=9051, password=None):
        self.proxy_port = proxy_port
        self.proxies = {
            'http': f'socks5h://127.0.0.1:{proxy_port}',
            'https': f'socks5h://127.0.0.1:{proxy_port}'
        }
        self.session = requests.Session()
        self.session.proxies = self.proxies
        self.session.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0'}
        
        # Connect to Tor controller for circuit management with robust error handling
        self.controller = None
        self.circuit_count = 0
        self.tor_available = False
        
        try:
            # Try different possible cookie paths
            cookie_paths = [
                '/run/tor/control.authcookie',
                '/var/run/tor/control.authcookie', 
                '/var/lib/tor/control.authcookie',
                '/run/tor/control.authcookie',  # Common on Kali
                '/tmp/tor/control.authcookie'
            ]
            
            # First try password authentication if provided
            if password:
                try:
                    self.controller = Controller.from_port(port=control_port)
                    self.controller.authenticate(password=password)
                    logger.info("Tor controller connected successfully with password")
                    self.circuit_count = 0
                    self.tor_available = True
                except Exception as e:
                    logger.warning(f"Password authentication failed: {e}")
                    self.controller = None
            
            # If no controller yet, try cookie authentication
            if not self.controller:
                for cookie_path in cookie_paths:
                    try:
                        if os.path.exists(cookie_path):
                            logger.debug(f"Trying cookie auth with: {cookie_path}")
                            self.controller = Controller.from_port(port=control_port)
                            
                            # Try to read the cookie file
                            with open(cookie_path, 'rb') as f:
                                auth_cookie = f.read()
                            
                            self.controller.authenticate(cookie=auth_cookie)
                            logger.info(f"Tor controller connected successfully using cookie: {cookie_path}")
                            self.circuit_count = 0
                            self.tor_available = True
                            break
                    except PermissionError:
                        logger.warning(f"Permission denied reading cookie: {cookie_path}")
                        continue
                    except Exception as e:
                        logger.debug(f"Failed to authenticate with {cookie_path}: {e}")
                        continue
            
            # If still no controller, try unauthenticated connection (if Tor allows)
            if not self.controller:
                try:
                    self.controller = Controller.from_port(port=control_port)
                    self.controller.authenticate()  # Try default auth
                    logger.info("Tor controller connected with default authentication")
                    self.circuit_count = 0
                    self.tor_available = True
                except Exception as e:
                    logger.warning(f"Default authentication failed: {e}")
                    self.controller = None
            
            if not self.controller:
                logger.warning("Could not connect to Tor controller - circuit rotation disabled")
                
        except Exception as e:
            logger.warning(f"Tor controller not available - circuit rotation disabled: {e}")
            self.controller = None
            self.tor_available = False
            self.circuit_count = 0

    def rotate_circuit(self):
        """Request a new Tor circuit (new IP)."""
        if self.controller and self.tor_available:
            try:
                self.controller.signal(stem.Signal.NEWNYM)
                time.sleep(5)  # Wait for circuit establishment
                self.circuit_count += 1
                logger.info(f"Circuit rotated. Total circuits: {self.circuit_count}")
                return True
            except Exception as e:
                logger.error(f"Circuit rotation failed: {e}")
                return False
        else:
            logger.debug("No controller available for circuit rotation")
            return False

    def get(self, url, timeout=15, rotate_every=10):
        # Force HTTP for .onion sites
        if '.onion' in url:
            url = url.replace('https://', 'http://')
        
        # Only attempt rotation if we have a controller
        if self.controller and self.tor_available:
            if self.circuit_count > 0 and self.circuit_count % rotate_every == 0:
                self.rotate_circuit()
        
        try:
            response = self.session.get(url, timeout=timeout, allow_redirects=True)
            if self.controller and self.tor_available:
                self.circuit_count += 1
            return response
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout: {url}")
        except requests.exceptions.ConnectionError as e:
            # Don't show connection errors for .onion HTTPS attempts
            if 'https' not in url.lower():
                logger.error(f"Connection error for {url}: {e}")
        except Exception as e:
            logger.error(f"Request failed for {url}: {e}")
        return None

    def head(self, url, timeout=10):
        """Make HEAD request through Tor"""
        try:
            return self.session.head(url, timeout=timeout)
        except Exception as e:
            logger.debug(f"HEAD request failed for {url}: {e}")
            return None

    def close(self):
        self.session.close()
        if self.controller:
            self.controller.close()
            logger.info("Tor controller closed")
