"""
Configuration module for APIVulnMiner
Handles all scanner settings and validation
"""

import json
import re
from typing import Optional, Dict, Any
from urllib.parse import urlparse
from pathlib import Path

from utils.logger import get_logger

logger = get_logger(__name__)

class Config:
    """Configuration class for APIVulnMiner scanner."""
    
    def __init__(
        self,
        target_url: str,
        wordlist_path: Optional[str] = None,
        threads: int = 20,
        delay: float = 0.05,
        timeout: int = 10,
        headers: Optional[str] = None,
        auth_token: Optional[str] = None,
        proxy: Optional[str] = None,
        verbose: bool = False
    ):
        self.target_url = target_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.threads = max(1, min(threads, 100))  # Limit between 1-100
        self.delay = max(0.0, delay)  # Minimum 0 delay
        self.timeout = max(1, timeout)  # Minimum 1 second timeout
        self.headers = headers
        self.auth_token = auth_token
        self.proxy = proxy
        self.verbose = verbose
        
        # Derived properties
        self.parsed_url = urlparse(self.target_url)
        self.base_domain = self.parsed_url.netloc
        
    def validate(self) -> bool:
        """Validate configuration settings."""
        try:
            # Validate URL
            if not self._validate_url():
                return False
            
            # Validate wordlist path if provided
            if self.wordlist_path and not self._validate_wordlist_path():
                return False
            
            # Validate headers if provided
            if self.headers and not self._validate_headers():
                return False
            
            # Validate proxy if provided
            if self.proxy and not self._validate_proxy():
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation error: {str(e)}")
            return False
    
    def _validate_url(self) -> bool:
        """Validate target URL."""
        if not self.target_url:
            logger.error("Target URL is required")
            return False
        
        if not self.parsed_url.scheme:
            logger.error("URL must include scheme (http:// or https://)")
            return False
        
        if self.parsed_url.scheme not in ['http', 'https']:
            logger.error("URL scheme must be http or https")
            return False
        
        if not self.parsed_url.netloc:
            logger.error("URL must include a valid hostname")
            return False
        
        # Check for valid hostname format
        hostname_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        
        hostname = self.parsed_url.hostname
        if hostname and not hostname_pattern.match(hostname):
            # Allow IP addresses
            ip_pattern = re.compile(
                r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            )
            if not ip_pattern.match(hostname):
                logger.error("Invalid hostname or IP address")
                return False
        
        return True
    
    def _validate_wordlist_path(self) -> bool:
        """Validate wordlist file path."""
        if not Path(self.wordlist_path).exists():
            logger.error(f"Wordlist file not found: {self.wordlist_path}")
            return False
        
        if not Path(self.wordlist_path).is_file():
            logger.error(f"Wordlist path is not a file: {self.wordlist_path}")
            return False
        
        return True
    
    def _validate_headers(self) -> bool:
        """Validate custom headers JSON."""
        try:
            headers_dict = json.loads(self.headers)
            if not isinstance(headers_dict, dict):
                logger.error("Headers must be a JSON object")
                return False
            return True
        except json.JSONDecodeError:
            logger.error("Invalid JSON format for headers")
            return False
    
    def _validate_proxy(self) -> bool:
        """Validate proxy URL."""
        try:
            proxy_parsed = urlparse(self.proxy)
            if not proxy_parsed.scheme or not proxy_parsed.netloc:
                logger.error("Invalid proxy URL format")
                return False
            
            if proxy_parsed.scheme not in ['http', 'https', 'socks4', 'socks5']:
                logger.error("Proxy scheme must be http, https, socks4, or socks5")
                return False
            
            return True
        except Exception:
            logger.error("Error parsing proxy URL")
            return False
    
    def get_headers_dict(self) -> Dict[str, str]:
        """Get headers as dictionary."""
        if not self.headers:
            return {}
        
        try:
            return json.loads(self.headers)
        except json.JSONDecodeError:
            logger.warning("Failed to parse headers, returning empty dict")
            return {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'target_url': self.target_url,
            'wordlist_path': self.wordlist_path,
            'threads': self.threads,
            'delay': self.delay,
            'timeout': self.timeout,
            'headers': self.headers,
            'auth_token': '***' if self.auth_token else None,  # Mask token
            'proxy': self.proxy,
            'verbose': self.verbose,
            'base_domain': self.base_domain
        }
    
    def __str__(self) -> str:
        """String representation of configuration."""
        config_dict = self.to_dict()
        return json.dumps(config_dict, indent=2)
    
    @classmethod
    def from_file(cls, config_file: str) -> 'Config':
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            return cls(**config_data)
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_file}")
            raise
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in configuration file: {config_file}")
            raise
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            raise 