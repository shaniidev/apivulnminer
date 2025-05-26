"""
Vulnerability Testing Module
Implements OWASP API Top 10 vulnerability detection
"""

import asyncio
import json
import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs
import base64
import hashlib

import httpx
from utils.logger import get_logger

logger = get_logger(__name__)

class VulnerabilityTester:
    """Advanced vulnerability testing for API endpoints."""
    
    def __init__(self):
        self.payloads = self._load_payloads()
        self.patterns = self._load_detection_patterns()
        
    def _load_payloads(self) -> Dict[str, List[str]]:
        """Load vulnerability testing payloads."""
        return {
            'sql_injection': [
                "' OR '1'='1",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR 1=1#",
                "admin'--",
                "' OR 'x'='x",
                "1' AND 1=1--",
                "' WAITFOR DELAY '00:00:05'--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "<img src=x onerror=alert('XSS')>",
                "';alert('XSS');//",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')></iframe>"
            ],
            'command_injection': [
                "; ls -la",
                "| whoami",
                "; cat /etc/passwd",
                "&& id",
                "; ping -c 4 127.0.0.1",
                "| curl http://evil.com",
                "; sleep 5"
            ],
            'ldap_injection': [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "admin)(&(password=*))",
                "*))%00"
            ],
            'nosql_injection': [
                "true, $where: '1 == 1'",
                ", $where: '1 == 1'",
                "$ne: 1",
                "'; return true; var dummy='",
                "[$ne]=1"
            ]
        }
    
    def _load_detection_patterns(self) -> Dict[str, List[str]]:
        """Load vulnerability detection patterns."""
        return {
            'sql_error': [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"Driver.*SQL.*Server",
                r"OLE DB.*SQL Server",
                r"SQLServer JDBC Driver",
                r"SqlException",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*oci_.*",
                r"Warning.*ora_.*"
            ],
            'xss_reflection': [
                r"<script>alert\('XSS'\)</script>",
                r"javascript:alert\('XSS'\)",
                r"<img src=x onerror=alert\('XSS'\)>",
                r"<svg onload=alert\('XSS'\)>"
            ],
            'command_execution': [
                r"uid=\d+.*gid=\d+",
                r"root:.*:0:0:",
                r"bin:.*:1:1:",
                r"daemon:.*:2:2:",
                r"PING.*bytes of data",
                r"64 bytes from"
            ],
            'directory_traversal': [
                r"root:.*:0:0:",
                r"\[boot loader\]",
                r"\[operating systems\]",
                r"<title>Index of /",
                r"Directory Listing"
            ],
            'sensitive_data': [
                r"password\s*[:=]\s*['\"]?[\w@#$%^&*()]+",
                r"api[_-]?key\s*[:=]\s*['\"]?[\w-]+",
                r"secret\s*[:=]\s*['\"]?[\w-]+",
                r"token\s*[:=]\s*['\"]?[\w.-]+",
                r"-----BEGIN.*PRIVATE KEY-----",
                r"-----BEGIN.*CERTIFICATE-----"
            ]
        }
    
    async def test_endpoint(
        self, 
        client: httpx.AsyncClient, 
        url: str, 
        method: str, 
        response: httpx.Response
    ) -> List[Dict[str, Any]]:
        """Test an endpoint for vulnerabilities."""
        vulnerabilities = []
        
        # Test based on response content and headers
        vulnerabilities.extend(await self._test_information_disclosure(response))
        vulnerabilities.extend(await self._test_security_headers(response))
        vulnerabilities.extend(await self._test_authentication_bypass(client, url, method))
        
        # Only test injection vulnerabilities on endpoints that accept parameters
        if method in ['POST', 'PUT', 'PATCH'] or '?' in url:
            vulnerabilities.extend(await self._test_injection_vulnerabilities(client, url, method))
        
        # Test for excessive data exposure
        vulnerabilities.extend(await self._test_excessive_data_exposure(response))
        
        # Test for rate limiting
        vulnerabilities.extend(await self._test_rate_limiting(client, url, method))
        
        # Test for CORS misconfigurations
        vulnerabilities.extend(await self._test_cors_misconfiguration(client, url))
        
        return vulnerabilities
    
    async def _test_information_disclosure(self, response: httpx.Response) -> List[Dict[str, Any]]:
        """Test for information disclosure vulnerabilities."""
        vulnerabilities = []
        content = response.text.lower()
        
        # Check for sensitive information in response
        for pattern in self.patterns['sensitive_data']:
            if re.search(pattern, content, re.IGNORECASE):
                vulnerabilities.append({
                    'name': 'Information Disclosure',
                    'type': 'sensitive_data_exposure',
                    'severity': 'high',
                    'description': f'Sensitive data pattern detected in response content.',
                    'evidence': pattern,
                    'recommendation': 'Remove sensitive information from API responses'
                })
        
        # Check for debug information
        debug_indicators = [
            'debug', 'trace', 'stack trace', 'exception', 'error',
            'warning', 'mysql', 'postgresql', 'oracle', 'sql server'
        ]
        
        for indicator in debug_indicators:
            if indicator in content:
                vulnerabilities.append({
                    'name': 'Debug Information Disclosure',
                    'type': 'information_disclosure',
                    'severity': 'medium',
                    'description': f'Debug information detected in response: {indicator}',
                    'evidence': indicator,
                    'recommendation': 'Disable debug mode in production'
                })
                break
        
        return vulnerabilities
    
    async def _test_security_headers(self, response: httpx.Response) -> List[Dict[str, Any]]:
        """Test for missing security headers."""
        vulnerabilities = []
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        security_headers = {
            'x-content-type-options': {
                'name': 'Missing X-Content-Type-Options Header',
                'severity': 'low',
                'description': 'X-Content-Type-Options header is missing',
                'recommendation': 'Add X-Content-Type-Options: nosniff header'
            },
            'x-frame-options': {
                'name': 'Missing X-Frame-Options Header',
                'severity': 'medium',
                'description': 'X-Frame-Options header is missing',
                'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN header'
            },
            'x-xss-protection': {
                'name': 'Missing X-XSS-Protection Header',
                'severity': 'low',
                'description': 'X-XSS-Protection header is missing',
                'recommendation': 'Add X-XSS-Protection: 1; mode=block header'
            },
            'strict-transport-security': {
                'name': 'Missing HSTS Header',
                'severity': 'medium',
                'description': 'Strict-Transport-Security header is missing',
                'recommendation': 'Add HSTS header for HTTPS endpoints'
            },
            'content-security-policy': {
                'name': 'Missing CSP Header',
                'severity': 'medium',
                'description': 'Content-Security-Policy header is missing',
                'recommendation': 'Implement Content Security Policy'
            }
        }
        
        for header, info in security_headers.items():
            if header not in headers:
                current_severity = info['severity'] # Start with the default severity

                if response.status_code == 404:
                    # For 404s, cap severity at 'low' for all missing headers
                    if current_severity in ['medium', 'high', 'critical']:
                        current_severity = 'low'
                elif response.status_code == 405:
                    # For 405s, specifically cap XFO, XSS-P, XCTO at 'low'
                    # Other headers (like CSP, HSTS) retain their original severity (e.g., 'medium')
                    if header in ['x-frame-options', 'x-xss-protection', 'x-content-type-options']:
                        if current_severity in ['medium', 'high', 'critical']: # Ensure we only downgrade
                             current_severity = 'low'
                
                vulnerabilities.append({
                    'name': info['name'],
                    'type': 'missing_security_header',
                    'severity': current_severity,
                    'description': info['description'],
                    'recommendation': info['recommendation']
                })
        
        return vulnerabilities
    
    async def _test_authentication_bypass(
        self, 
        client: httpx.AsyncClient, 
        url: str, 
        method: str
    ) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities."""
        vulnerabilities = []
        
        # Test without authentication headers
        try:
            # Remove authorization header
            headers = dict(client.headers)
            if 'authorization' in headers:
                del headers['authorization']
            
            test_client = httpx.AsyncClient(headers=headers, timeout=5)
            response = await test_client.request(method, url)
            
            # If we get a successful response without auth, it's a vulnerability
            if response.status_code < 400:
                severity = "low" if method.upper() == "OPTIONS" else "high"
                vulnerabilities.append({
                    'name': 'Authentication Bypass',
                    'type': 'broken_authentication',
                    'severity': severity,
                    'description': 'Endpoint accessible without authentication',
                    'evidence': f'Status code: {response.status_code}, Method: {method}',
                    'recommendation': 'Implement proper authentication checks for sensitive methods/endpoints'
                })
            
            await test_client.aclose()
            
        except Exception as e:
            logger.debug(f"Auth bypass test failed for {url}: {str(e)}")
        
        return vulnerabilities
    
    async def _test_injection_vulnerabilities(
        self, 
        client: httpx.AsyncClient, 
        url: str, 
        method: str
    ) -> List[Dict[str, Any]]:
        """Test for injection vulnerabilities."""
        vulnerabilities = []
        
        # Test SQL injection
        for payload in self.payloads['sql_injection'][:3]:  # Limit to 3 payloads
            try:
                vuln = await self._test_sql_injection(client, url, method, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    break  # Found one, no need to test more
            except Exception as e:
                logger.debug(f"SQL injection test failed: {str(e)}")
        
        # Test XSS
        for payload in self.payloads['xss'][:2]:  # Limit to 2 payloads
            try:
                vuln = await self._test_xss(client, url, method, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    break
            except Exception as e:
                logger.debug(f"XSS test failed: {str(e)}")
        
        # Test command injection
        for payload in self.payloads['command_injection'][:2]:
            try:
                vuln = await self._test_command_injection(client, url, method, payload)
                if vuln:
                    vulnerabilities.append(vuln)
                    break
            except Exception as e:
                logger.debug(f"Command injection test failed: {str(e)}")
        
        return vulnerabilities
    
    async def _test_sql_injection(
        self, 
        client: httpx.AsyncClient, 
        url: str, 
        method: str, 
        payload: str
    ) -> Optional[Dict[str, Any]]:
        """Test for SQL injection vulnerability."""
        try:
            if method == 'GET':
                test_url = f"{url}?id={payload}"
                response = await client.get(test_url, timeout=5)
            else:
                data = {'id': payload, 'test': payload}
                response = await client.request(method, url, json=data, timeout=5)
            
            # Check for SQL error patterns
            content = response.text
            for pattern in self.patterns['sql_error']:
                if re.search(pattern, content, re.IGNORECASE):
                    return {
                        'name': 'SQL Injection',
                        'type': 'injection',
                        'severity': 'high',
                        'description': 'SQL injection vulnerability detected',
                        'evidence': f'Payload: {payload}, Pattern: {pattern}',
                        'recommendation': 'Use parameterized queries and input validation'
                    }
        
        except Exception:
            pass
        
        return None
    
    async def _test_xss(
        self, 
        client: httpx.AsyncClient, 
        url: str, 
        method: str, 
        payload: str
    ) -> Optional[Dict[str, Any]]:
        """Test for XSS vulnerability."""
        try:
            if method == 'GET':
                test_url = f"{url}?q={payload}"
                response = await client.get(test_url, timeout=5)
            else:
                data = {'message': payload, 'content': payload}
                response = await client.request(method, url, json=data, timeout=5)
            
            # Check if payload is reflected
            if payload in response.text:
                return {
                    'name': 'Cross-Site Scripting (XSS)',
                    'type': 'injection',
                    'severity': 'medium',
                    'description': 'XSS vulnerability detected - user input reflected without sanitization',
                    'evidence': f'Payload: {payload}',
                    'recommendation': 'Sanitize and encode user input before output'
                }
        
        except Exception:
            pass
        
        return None
    
    async def _test_command_injection(
        self, 
        client: httpx.AsyncClient, 
        url: str, 
        method: str, 
        payload: str
    ) -> Optional[Dict[str, Any]]:
        """Test for command injection vulnerability."""
        try:
            if method == 'GET':
                test_url = f"{url}?cmd={payload}"
                response = await client.get(test_url, timeout=10)
            else:
                data = {'command': payload, 'exec': payload}
                response = await client.request(method, url, json=data, timeout=10)
            
            # Check for command execution patterns
            content = response.text
            for pattern in self.patterns['command_execution']:
                if re.search(pattern, content, re.IGNORECASE):
                    return {
                        'name': 'Command Injection',
                        'type': 'injection',
                        'severity': 'critical',
                        'description': 'Command injection vulnerability detected',
                        'evidence': f'Payload: {payload}, Pattern: {pattern}',
                        'recommendation': 'Avoid executing system commands with user input'
                    }
        
        except Exception:
            pass
        
        return None
    
    async def _test_excessive_data_exposure(self, response: httpx.Response) -> List[Dict[str, Any]]:
        """Test for excessive data exposure."""
        vulnerabilities = []
        
        try:
            # Check if response contains JSON with potentially sensitive fields
            if 'application/json' in response.headers.get('content-type', ''):
                data = response.json()
                
                sensitive_fields = [
                    'password', 'secret', 'token', 'key', 'private',
                    'ssn', 'social_security', 'credit_card', 'cvv',
                    'internal', 'debug', 'admin'
                ]
                
                def check_sensitive_data(obj, path=""):
                    found_sensitive = []
                    if isinstance(obj, dict):
                        for key, value in obj.items():
                            current_path = f"{path}.{key}" if path else key
                            if any(sensitive in key.lower() for sensitive in sensitive_fields):
                                found_sensitive.append(current_path)
                            if isinstance(value, (dict, list)):
                                found_sensitive.extend(check_sensitive_data(value, current_path))
                    elif isinstance(obj, list):
                        for i, item in enumerate(obj):
                            current_path = f"{path}[{i}]"
                            if isinstance(item, (dict, list)):
                                found_sensitive.extend(check_sensitive_data(item, current_path))
                    return found_sensitive
                
                sensitive_found = check_sensitive_data(data)
                if sensitive_found:
                    vulnerabilities.append({
                        'name': 'Excessive Data Exposure',
                        'type': 'excessive_data_exposure',
                        'severity': 'medium',
                        'description': 'API response contains potentially sensitive fields',
                        'evidence': f'Sensitive fields: {", ".join(sensitive_found[:5])}',
                        'recommendation': 'Filter sensitive data from API responses'
                    })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _test_rate_limiting(
        self, 
        client: httpx.AsyncClient, 
        url: str, 
        method: str
    ) -> List[Dict[str, Any]]:
        """Test for rate limiting implementation."""
        vulnerabilities = []
        
        try:
            # Send multiple rapid requests
            start_time = time.time()
            responses = []
            
            for _ in range(5):  # Send 5 rapid requests
                response = await client.request(method, url, timeout=3)
                responses.append(response.status_code)
                await asyncio.sleep(0.1)  # Small delay
            
            # Check if all requests succeeded (no rate limiting)
            if all(status < 400 for status in responses):
                vulnerabilities.append({
                    'name': 'Missing Rate Limiting',
                    'type': 'lack_of_rate_limiting',
                    'severity': 'medium',
                    'description': 'No rate limiting detected on endpoint',
                    'evidence': f'5 rapid requests all succeeded: {responses}',
                    'recommendation': 'Implement rate limiting to prevent abuse'
                })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    async def _test_cors_misconfiguration(
        self, 
        client: httpx.AsyncClient, 
        url: str
    ) -> List[Dict[str, Any]]:
        """Test for CORS misconfiguration."""
        vulnerabilities = []
        
        try:
            # Test with malicious origin
            headers = {'Origin': 'https://evil.com'}
            response = await client.options(url, headers=headers, timeout=5)
            
            cors_header = response.headers.get('access-control-allow-origin', '')
            
            if cors_header == '*':
                vulnerabilities.append({
                    'name': 'CORS Misconfiguration',
                    'type': 'security_misconfiguration',
                    'severity': 'medium',
                    'description': 'CORS allows all origins (*)',
                    'evidence': f'Access-Control-Allow-Origin: {cors_header}',
                    'recommendation': 'Restrict CORS to specific trusted origins'
                })
            elif 'evil.com' in cors_header:
                vulnerabilities.append({
                    'name': 'CORS Misconfiguration',
                    'type': 'security_misconfiguration',
                    'severity': 'high',
                    'description': 'CORS reflects arbitrary origins',
                    'evidence': f'Access-Control-Allow-Origin: {cors_header}',
                    'recommendation': 'Validate origins against whitelist'
                })
        
        except Exception:
            pass
        
        return vulnerabilities 