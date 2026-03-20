import os
import requests
import stem
import stem.connection
from stem.control import Controller
import time
import random
import logging

from config.settings import TOR_PROXY_PORT, TOR_CONTROL_PORT, TOR_PASSWORD, USER_AGENTS

logger = logging.getLogger(__name__)

class TorSession:
    def __init__(self, proxy_port=None, control_port=None, password=None):
        self.proxy_port = proxy_port or TOR_PROXY_PORT
        self.control_port = control_port or TOR_CONTROL_PORT
        self.proxies = {
            'http': f'socks5h://127.0.0.1:{self.proxy_port}',
            'https': f'socks5h://127.0.0.1:{self.proxy_port}'
        }
        self.session = requests.Session()
        self.session.proxies = self.proxies
        self.user_agents = USER_AGENTS
        self.session.headers = {'User-Agent': random.choice(self.user_agents)}

        # Connect to Tor controller for circuit management
        self.controller = None
        self.circuit_count = 0
        self.tor_available = False

        auth_password = password or TOR_PASSWORD

        try:
            cookie_paths = [
                '/run/tor/control.authcookie',
                '/var/run/tor/control.authcookie',
                '/var/lib/tor/control.authcookie',
                '/tmp/tor/control.authcookie'
            ]

            # Try password authentication if provided
            if auth_password:
                try:
                    self.controller = Controller.from_port(port=self.control_port)
                    self.controller.authenticate(password=auth_password)
                    logger.info("Tor controller connected successfully with password")
                    self.circuit_count = 0
                    self.tor_available = True
                except Exception as e:
                    logger.warning(f"Password authentication failed: {e}")
                    self.controller = None

            # Try cookie authentication
            if not self.controller:
                for cookie_path in cookie_paths:
                    try:
                        if os.path.exists(cookie_path):
                            logger.debug(f"Trying cookie auth with: {cookie_path}")
                            self.controller = Controller.from_port(port=self.control_port)
                            with open(cookie_path, 'rb') as f:
                                auth_cookie = f.read()
                            self.controller.authenticate(cookie=auth_cookie)
                            logger.info(f"Tor controller connected using cookie: {cookie_path}")
                            self.circuit_count = 0
                            self.tor_available = True
                            break
                    except PermissionError:
                        logger.warning(f"Permission denied reading cookie: {cookie_path}")
                        continue
                    except Exception as e:
                        logger.debug(f"Failed to authenticate with {cookie_path}: {e}")
                        continue

            # Try unauthenticated connection
            if not self.controller:
                try:
                    self.controller = Controller.from_port(port=self.control_port)
                    self.controller.authenticate()
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

    def _rotate_user_agent(self):
        """Pick a random User-Agent for the next request"""
        self.session.headers['User-Agent'] = random.choice(self.user_agents)

    def rotate_circuit(self):
        """Request a new Tor circuit (new IP)."""
        if self.controller and self.tor_available:
            try:
                self.controller.signal(stem.Signal.NEWNYM)
                time.sleep(5)
                self.circuit_count += 1
                self._rotate_user_agent()
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

        # Rotate circuit periodically
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
