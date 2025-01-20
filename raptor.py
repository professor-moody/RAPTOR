#!/usr/bin/env python3

import requests
import json
import yaml
import logging
import sys
import asyncio
import concurrent.futures
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin, urlparse
import re
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
import colorama
from colorama import Fore, Style
from datetime import datetime
import argparse

# Local imports
from core.collector import EnhancedDataCollector
from graphql.analyzer import GraphQLAnalyzer
from output.formatter import OutputFormatter
from logic_mapping.patterns import PatternMatcher


# Initialize colorama for cross-platform color support
colorama.init()

def print_banner():
    """Print the RAPTOR tool banner with colors"""
    banner = f"""
{Fore.CYAN}╭──────────────────────────────────────────────────────────────╮
│{Style.RESET_ALL}                                                              {Fore.CYAN}│
│   {Fore.RED}██████╗   █████╗  ██████╗ ████████╗ █████╗ ██████╗       {Fore.CYAN}│
│   {Fore.RED}██╔══██╗ ██╔══██╗ ██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗      {Fore.CYAN}│
│   {Fore.RED}██████╔╝ ███████║ ██████╔╝   ██║   ██║  ██║██████╔╝      {Fore.CYAN}│
│   {Fore.RED}██╔══██╗ ██╔══██║ ██╔═══╝    ██║   ██║  ██║██╔══██╗      {Fore.CYAN}│
│   {Fore.RED}██║  ██║ ██║  ██║ ██║        ██║   ╚█████╔╝██║  ██║      {Fore.CYAN}│
│   {Fore.RED}╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝        ╚═╝    ╚════╝ ╚═╝  ╚═╝      {Fore.CYAN}│
│{Style.RESET_ALL}                                                              {Fore.CYAN}│
├──────────────────────────────────────────────────────────────┤
│{Fore.WHITE}      Rapid API Testing and Operation Reconnaissance v1.5     {Fore.CYAN}│
├──────────────────────────────────────────────────────────────┤
│{Fore.YELLOW}  [*] API Discovery  [*] Auth Detection  [*] Schema Analysis  {Fore.CYAN}│
╰──────────────────────────────────────────────────────────────╯{Style.RESET_ALL}
"""
    print(banner)

class RAPTOR:
    """RAPTOR - Rapid API Testing and Operation Reconnaissance"""
    
    def __init__(self, base_url: str, wordlist_path: Optional[str] = None, options: Dict = None):
        self.base_url = base_url.rstrip('/')
        self.session = self._setup_session()
        self.discovered_endpoints: Set[str] = set()
        self.api_docs: Dict = {}
        self.parameters: Dict[str, List[str]] = {}
        self.auth_methods: Set[str] = set()
        self.versions: Set[str] = set()
        self.formatter = OutputFormatter()
        self.workflows: Dict[str, List[Dict]] = {}
        self._discovered_auth_methods: Set[str] = set()
        self.options = options or {}
        self.graphql_results = {}
        
        # Load wordlist
        self.wordlist = self._load_wordlist(wordlist_path)
        
        # Common paths
        self.common_doc_paths = [
            '/swagger.json',
            '/swagger/v1/swagger.json',
            '/api-docs',
            '/api-docs.json',
            '/v1/api-docs',
            '/v2/api-docs',
            '/swagger-ui.html',
            '/graphql',
            '/playground'
        ]

    def _setup_session(self) -> requests.Session:
        """Set up requests session with proper configuration"""
        session = requests.Session()
        
        # Configure connection pooling and retries
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=3,
            pool_block=False
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        # Set default headers and timeouts
        session.headers.update({
            'User-Agent': 'RAPTOR/1.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        
        # Set longer timeouts
        session.timeout = (10, 30)  # (connect timeout, read timeout)
        
        return session

    def _load_wordlist(self, wordlist_path: Optional[str]) -> List[str]:
        """Load wordlist from file or use default paths"""
        if wordlist_path:
            try:
                with open(wordlist_path) as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(self.formatter.error(f"Error loading wordlist: {e}"))
                return []
        else:
            # Default common API endpoints
            return [
                'api', 'v1', 'v2', 'v3', 'docs', 'swagger', 'health',
                'status', 'metrics', 'admin', 'auth', 'login', 'users',
                'products', 'orders', 'items', 'search', 'query'
            ]

    def scan(self) -> Dict[str, Any]:
        """Execute full RAPTOR scan"""
        try:
            # Basic discovery
            self._discover_endpoints()
            
            if self.discovered_endpoints:
                print(self.formatter.info("\nStarting detailed analysis..."))
                
                # Run authentication detection
                if not self.options.get('no_auth'):
                    self.check_auth_methods()
                
                # Find and parse documentation
                self._find_documentation()
                
                # Analyze parameters and versions
                self._analyze_parameters()
                self._detect_versions()
                
                # GraphQL analysis
                if not self.options.get('skip_graphql'):
                    self._analyze_graphql()
                
                # Business logic mapping
                if not self.options.get('no_business_logic'):
                    self._map_business_logic()
            
            return self._generate_report()
            
        except Exception as e:
            print(self.formatter.error(f"Scan error: {str(e)}"))
            raise

    def _discover_endpoints(self):
        """Enhanced endpoint discovery"""
        print(self.formatter.info("Starting endpoint discovery..."))
        
        # First check documentation paths
        for path in self.common_doc_paths:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code != 404:
                    self.discovered_endpoints.add(url)
                    print(self.formatter.success(f"Found endpoint: {url} ({response.status_code})"))
            except requests.RequestException:
                continue

        # Then try wordlist-based discovery
        with ThreadPoolExecutor(max_workers=self.options.get('threads', 10)) as executor:
            futures = []
            for word in self.wordlist:
                url = urljoin(self.base_url, word)
                futures.append(executor.submit(self._check_endpoint, url))
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        self.discovered_endpoints.add(result['url'])
                        print(self.formatter.success(
                            f"Found endpoint: {result['url']} ({result['status']})"
                        ))
                except Exception as e:
                    print(self.formatter.error(f"Error during discovery: {str(e)}"))

    def _check_endpoint(self, url: str) -> Optional[Dict[str, Any]]:
        """Check if endpoint exists with enhanced detection"""
        try:
            response = self.session.get(url, timeout=10)
            
            # Consider various response scenarios
            if response.status_code != 404:
                return {
                    'url': url,
                    'status': response.status_code,
                    'content_type': response.headers.get('content-type', ''),
                    'auth_required': response.status_code in [401, 403]
                }
        except requests.RequestException:
            pass
        return None

    def _analyze_graphql(self):
        """Analyze GraphQL endpoints with enhanced detection"""
        print(self.formatter.info("\nAnalyzing GraphQL endpoints..."))
        
        graphql_analyzer = GraphQLAnalyzer(
            session=self.session,
            base_url=self.base_url,
            formatter=self.formatter
        )
        
        self.graphql_results = graphql_analyzer.analyze()
        
        # Add discovered GraphQL endpoints to main set
        if 'endpoints' in self.graphql_results:
            for url, info in self.graphql_results['endpoints'].items():
                if info.get('is_graphql'):
                    self.discovered_endpoints.add(url)
                    print(self.formatter.success(f"Confirmed GraphQL endpoint: {url}"))
        
        # Report vulnerabilities
        if 'vulnerabilities' in self.graphql_results:
            print(self.formatter.info("\nGraphQL Vulnerabilities:"))
            for vuln in self.graphql_results['vulnerabilities']:
                severity = vuln.get('severity', 'UNKNOWN')
                print(self.formatter.warning(
                    f"[{severity}] {vuln['type']} in {vuln.get('url', 'Unknown endpoint')}"
                ))

    def check_auth_methods(self):
        """Enhanced authentication method detection"""
        print(self.formatter.info("\nDetecting authentication methods..."))
        
        # Track checked endpoints
        checked_endpoints = set()

        # Extended auth headers with provider-specific headers
        auth_headers = {
            # Standard Auth Headers
            'Authorization': 'Bearer test',
            'X-API-Key': 'test',
            'API-Key': 'test',
            'X-Auth-Token': 'test',
            'X-Access-Token': 'test',
            
            # AWS
            'X-Amz-Security-Token': 'test',
            'X-Amz-Date': 'test',
            
            # Azure
            'X-MS-OAuth-Token': 'test',
            'X-ZUMO-AUTH': 'test',
            
            # Google Cloud
            'X-Goog-AuthUser': 'test',
            'X-GCP-Auth-Token': 'test',
            
            # Firebase
            'Firebase-Auth': 'test',
            
            # Common API Gateways
            'X-Kong-Auth': 'test',
            'X-Tyk-Authorization': 'test',
            'X-WSO2-Auth': 'test',
            
            # Identity Providers
            'X-Auth0-Token': 'test',
            'X-Okta-Token': 'test',
            'X-Ping-Identity': 'test',
            
            # Standard variations
            'Client-ID': 'test',
            'X-Client-ID': 'test',
            'X-Auth': 'test',
            'X-Auth-Key': 'test',
            'App-Key': 'test',
            'Token': 'test',
            'JWT': 'test',
        }

        # OAuth-related paths to check
        auth_provider_paths = {
            'oauth_paths': [
                '/oauth',
                '/oauth2',
                '/oauth/token',
                '/oauth/authorize',
                '/oauth2/token',
                '/oauth2/authorize',
                '/.well-known/openid-configuration',
                '/.well-known/oauth-authorization-server',
                '/connect/token',
                '/connect/authorize'
            ],
            'keycloak_paths': [
                '/auth/realms',
                '/auth/admin',
                '/auth/realms/master',
            ],
            'auth0_paths': [
                '/.well-known/jwks.json',
                '/userinfo',
                '/authorize',
            ],
            'okta_paths': [
                '/oauth2/default',
                '/oauth2/v1',
                '/.well-known/okta-openid-configuration',
            ],
            'azure_paths': [
                '/.well-known/openid-configuration',
                '/oauth2/v2.0/authorize',
                '/oauth2/v2.0/token',
            ],
            'aws_cognito_paths': [
                '/oauth2/token',
                '/oauth2/authorize',
                '/.well-known/cognito-idp-configuration',
            ]
        }

        try:
            # First, check discovered endpoints
            print(self.formatter.info("Checking discovered endpoints..."))
            for endpoint in self.discovered_endpoints:
                if endpoint in checked_endpoints:
                    continue
                    
                try:
                    # Basic request without auth
                    response = self.session.get(endpoint, timeout=10)
                    self._analyze_auth_response(endpoint, response)
                    self._analyze_provider_specific_response(endpoint, response)
                    checked_endpoints.add(endpoint)

                    # Test with different auth headers
                    for header, value in auth_headers.items():
                        try:
                            auth_response = self.session.get(
                                endpoint, 
                                headers={header: value},
                                timeout=10
                            )
                            self._analyze_auth_header_response(endpoint, header, auth_response)
                        except requests.RequestException:
                            continue

                except requests.RequestException as e:
                    print(self.formatter.warning(f"Error checking auth for {endpoint}: {str(e)}"))

            # Check provider-specific paths
            print(self.formatter.info("\nChecking provider-specific endpoints..."))
            for provider, paths in auth_provider_paths.items():
                for path in paths:
                    url = urljoin(self.base_url, path)
                    if url in checked_endpoints:
                        continue
                        
                    try:
                        response = self.session.get(url, timeout=10)
                        if response.status_code != 404:
                            self._analyze_oauth_response(url, response)
                            self._analyze_provider_specific_response(url, response)
                        checked_endpoints.add(url)
                    except requests.RequestException:
                        continue

        except Exception as e:
            print(self.formatter.warning(f"Error during auth detection: {str(e)}"))

        # Print final summary
        if self.auth_methods:
            print(self.formatter.info("\nAuthentication Methods Detected:"))
            for method in sorted(self.auth_methods):
                print(self.formatter.success(f"✓ {method}"))
        else:
            print(self.formatter.warning("\nNo authentication methods detected."))

    def _analyze_auth_response(self, endpoint: str, response: requests.Response):
        """Analyze basic response for auth indicators"""
        try:
            # Check status codes
            if response.status_code in [401, 403]:
                self._add_auth_method("Authentication Required", endpoint)

            # Check WWW-Authenticate header
            if 'www-authenticate' in response.headers:
                auth_header = response.headers['www-authenticate'].lower()
                if 'basic' in auth_header:
                    self._add_auth_method("Basic Authentication", endpoint)
                elif 'bearer' in auth_header:
                    self._add_auth_method("Bearer Token", endpoint)
                elif 'digest' in auth_header:
                    self._add_auth_method("Digest Authentication", endpoint)
                elif 'ntlm' in auth_header:
                    self._add_auth_method("NTLM Authentication", endpoint)
                elif 'negotiate' in auth_header:
                    self._add_auth_method("Kerberos/Negotiate", endpoint)

            # Check for JWT indicators
            if any(h.lower() in ['jwt', 'json-web-token'] for h in response.headers):
                self._add_auth_method("JWT Authentication", endpoint)
        except Exception as e:
            print(self.formatter.warning(f"Error analyzing auth response for {endpoint}: {str(e)}"))

    def _analyze_auth_header_response(self, endpoint: str, header: str, response: requests.Response):
        """Analyze response from auth header tests"""
        try:
            if response.status_code in [401, 403]:
                # Map headers to auth types
                auth_type_mapping = {
                    'X-API-Key': 'API Key',
                    'API-Key': 'API Key',
                    'Authorization': 'Bearer Token',
                    'X-Auth-Token': 'Auth Token',
                    'X-Access-Token': 'Access Token',
                    'Client-ID': 'Client ID',
                    'X-Client-ID': 'Client ID',
                    'JWT': 'JWT Authentication',
                    'X-Session-Token': 'Session Token',
                    'Identity': 'Identity Token'
                }
                
                auth_type = auth_type_mapping.get(header, f"{header} Authentication")
                self._add_auth_method(auth_type, endpoint)
        except Exception as e:
            print(self.formatter.warning(f"Error analyzing auth header response for {endpoint}: {str(e)}"))

    def _analyze_provider_specific_response(self, endpoint: str, response: requests.Response):
        """Analyze response for specific auth providers"""
        try:
            # AWS Cognito Detection
            if any(h.lower().startswith('x-amz-') for h in response.headers):
                if 'cognito' in str(response.headers).lower():
                    self._add_auth_method("AWS Cognito", endpoint)
                else:
                    self._add_auth_method("AWS Authentication", endpoint)

            # Azure AD Detection
            if any(h.lower().startswith('x-ms-') for h in response.headers):
                if 'microsoftonline' in str(response.headers).lower():
                    self._add_auth_method("Azure AD", endpoint)
                else:
                    self._add_auth_method("Microsoft Authentication", endpoint)

            # Google Cloud Detection
            if any(h.lower().startswith('x-goog-') for h in response.headers):
                self._add_auth_method("Google Cloud Authentication", endpoint)

            # Firebase Detection
            if 'firebase' in str(response.headers).lower():
                self._add_auth_method("Firebase Authentication", endpoint)

            # Try to parse response for more provider info
            if 'application/json' in response.headers.get('content-type', ''):
                data = response.json()
                
                # Provider Detection from Response Data
                provider_keywords = {
                    'auth0': "Auth0",
                    'okta': "Okta",
                    'wso2': "WSO2",
                    'ping': "Ping Identity",
                    'forgerock': "ForgeRock"
                }
                
                data_str = str(data).lower()
                for keyword, provider in provider_keywords.items():
                    if keyword in data_str:
                        self._add_auth_method(provider, endpoint)
                
        except Exception as e:
            print(self.formatter.warning(f"Error analyzing provider response for {endpoint}: {str(e)}"))

    def _analyze_oauth_response(self, endpoint: str, response: requests.Response):
        """Analyze potential OAuth endpoint responses with provider detection"""
        try:
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                if 'json' in content_type:
                    data = response.json()
                    
                    # Basic OAuth/OIDC detection
                    oauth_indicators = [
                        'token_endpoint',
                        'authorization_endpoint',
                        'grant_types_supported',
                        'response_types_supported',
                        'issuer',
                        'jwks_uri'
                    ]
                    
                    if any(key in data for key in oauth_indicators):
                        # Provider-specific detection
                        issuer = str(data.get('issuer', '')).lower()
                        
                        # Map issuers to providers
                        provider_mapping = {
                            'okta': "Okta OAuth",
                            'auth0': "Auth0 OAuth",
                            'azure': "Azure AD OAuth",
                            'microsoftonline': "Azure AD OAuth",
                            'accounts.google': "Google OAuth",
                            'cognito': "AWS Cognito OAuth",
                            'keycloak': "Keycloak OAuth"
                        }
                        
                        provider_detected = False
                        for keyword, provider in provider_mapping.items():
                            if keyword in issuer:
                                self._add_auth_method(provider, endpoint)
                                provider_detected = True
                                break
                        
                        if not provider_detected:
                            if 'openid-configuration' in endpoint:
                                self._add_auth_method("OpenID Connect", endpoint)
                            else:
                                self._add_auth_method("OAuth 2.0", endpoint)
                
                # Generic OAuth detection from response body
                body = response.text.lower()
                oauth_keywords = ['oauth', 'openid', 'authorize', 'token', 'client_id', 'client_secret']
                if any(keyword in body for keyword in oauth_keywords):
                    if not any(method.lower().startswith('oauth') for method in self.auth_methods):
                        self._add_auth_method("OAuth", endpoint)
                    
        except Exception as e:
            print(self.formatter.warning(f"Error analyzing OAuth response for {endpoint}: {str(e)}"))

    def _add_auth_method(self, method: str, endpoint: str):
        """Add authentication method with logging"""
        try:
            # Only add and log if it's a new discovery
            method_endpoint = f"{method}:{endpoint}"
            if method_endpoint not in self._discovered_auth_methods:
                self.auth_methods.add(method)
                print(self.formatter.success(f"Detected {method} on {endpoint}"))
                self._discovered_auth_methods.add(method_endpoint)
        except Exception as e:
            print(self.formatter.warning(f"Error adding auth method: {str(e)}"))

    def _find_documentation(self):
        """Find and parse API documentation"""
        print(self.formatter.info("\nSearching for API documentation..."))
        
        for path in self.common_doc_paths:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    print(self.formatter.success(f"Found documentation at: {url}"))
                    
                    try:
                        if 'json' in response.headers.get('content-type', ''):
                            self.api_docs[url] = response.json()
                            self._parse_swagger_docs(url)
                        elif 'yaml' in response.headers.get('content-type', ''):
                            self.api_docs[url] = yaml.safe_load(response.text)
                            self._parse_swagger_docs(url)
                    except Exception:
                        print(self.formatter.warning(f"Could not parse documentation at {url}"))
                        
            except requests.RequestException:
                continue

    def _parse_swagger_docs(self, url: str):
        """Parse Swagger/OpenAPI documentation"""
        doc = self.api_docs[url]
        if not isinstance(doc, dict):
            return
            
        if 'paths' in doc:
            for path, methods in doc['paths'].items():
                full_path = urljoin(self.base_url, path)
                self.discovered_endpoints.add(full_path)
                
                # Extract parameters
                if isinstance(methods, dict):
                    for method, details in methods.items():
                        if isinstance(details, dict) and 'parameters' in details:
                            params = [p.get('name', '') for p in details['parameters']]
                            if full_path not in self.parameters:
                                self.parameters[full_path] = []
                            self.parameters[full_path].extend(params)

    def _analyze_parameters(self):
        """Analyze API parameters"""
        print(self.formatter.info("\nAnalyzing parameters..."))
        
        common_params = ['id', 'page', 'limit', 'sort', 'filter', 'q', 'search']
        
        for endpoint in self.discovered_endpoints:
            found_params = set()
            
            # Try common parameters
            for param in common_params:
                try:
                    response = self.session.get(f"{endpoint}?{param}=test", timeout=10)
                    if response.status_code != 404:
                        found_params.add(param)
                except requests.RequestException:
                    continue
            
            if found_params:
                if endpoint not in self.parameters:
                    self.parameters[endpoint] = []
                self.parameters[endpoint].extend(found_params)
                print(self.formatter.success(
                    f"Found parameters for {endpoint}: {', '.join(found_params)}"
                ))

    def _detect_versions(self):
        """Detect API versions"""
        print(self.formatter.info("\nDetecting API versions..."))
        
        version_pattern = re.compile(r'v\d+|version[=/-]\d+')
        
        for endpoint in self.discovered_endpoints:
            matches = version_pattern.findall(endpoint.lower())
            if matches:
                self.versions.update(matches)
                print(self.formatter.success(
                    f"Detected version {matches[0]} in {endpoint}"
                ))

    def _map_business_logic(self):
        """Map business logic and workflows"""
        print(self.formatter.info("\nMapping business logic..."))
        
        # Common workflow patterns
        workflow_patterns = {
            'authentication': {
                'endpoints': ['/login', '/auth', '/token'],
                'sequence': ['login', 'token_generation', 'token_refresh']
            },
            'user_management': {
                'endpoints': ['/users', '/register', '/profile'],
                'sequence': ['registration', 'verification', 'profile_completion']
            },
            'e_commerce': {
                'endpoints': ['/products', '/cart', '/checkout', '/orders'],
                'sequence': ['browse', 'cart', 'checkout', 'order']
            }
        }
        
        # Analyze endpoints against patterns
        for pattern_name, pattern in workflow_patterns.items():
            matching_endpoints = []
            for endpoint in self.discovered_endpoints:
                if any(p in endpoint.lower() for p in pattern['endpoints']):
                    matching_endpoints.append(endpoint)
            
            if matching_endpoints:
                self.workflows[pattern_name] = {
                    'endpoints': matching_endpoints,
                    'expected_sequence': pattern['sequence'],
                    'discovered_at': datetime.now().isoformat()
                }
                print(self.formatter.success(
                    f"Discovered potential {pattern_name} workflow: {', '.join(matching_endpoints)}"
                ))
    def _generate_report(self) -> Dict[str, Any]:
        """Generate detailed scan report"""
        report = {
            'scan_info': {
                'base_url': self.base_url,
                'scan_time': datetime.now().isoformat(),
                'endpoints_discovered': len(self.discovered_endpoints)
            },
            'authentication': {
                'methods_detected': list(self.auth_methods),
                'protected_endpoints': [
                    e for e in self.discovered_endpoints 
                    if self._check_endpoint(e) and self._check_endpoint(e).get('auth_required')
                ] if self.discovered_endpoints else []
            },
            'endpoints': {
                'total': len(self.discovered_endpoints),
                'listing': sorted(list(self.discovered_endpoints))
            },
            'business_logic': {
                'workflows_detected': self.workflows,
                'parameters': self.parameters,
                'versions': list(self.versions)
            },
            'documentation': {
                'found_at': list(self.api_docs.keys())
            }
        }

        # Add GraphQL results if any were found
        if self.graphql_results:
            report['graphql'] = {
                'endpoints': list(self.graphql_results.get('endpoints', {}).keys()),
                'vulnerabilities': self.graphql_results.get('vulnerabilities', []),
                'schema_analysis': self.graphql_results.get('schema_analysis', {}),
                'test_results': self.graphql_results.get('test_results', {})
            }

        return report


def main():
    parser = argparse.ArgumentParser(
        description='RAPTOR - Rapid API Testing and Operation Reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('url', help='Base URL to scan')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of threads for bruteforcing')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Timeout for requests in seconds')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('--no-auth', action='store_true',
                        help='Skip authentication detection')
    parser.add_argument('--no-business-logic', action='store_true',
                        help='Skip business logic mapping')
    parser.add_argument('--skip-graphql', action='store_true',
                        help='Skip GraphQL analysis')
    parser.add_argument('--graphql-tests', action='store_true',
                        help='Run detailed GraphQL security tests')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Print banner
    print_banner()

    try:
        # Initialize RAPTOR with options
        options = {
            'threads': args.threads,
            'timeout': args.timeout,
            'no_auth': args.no_auth,
            'no_business_logic': args.no_business_logic,
            'skip_graphql': args.skip_graphql,
            'graphql_tests': args.graphql_tests,
            'verbose': args.verbose
        }
        
        raptor = RAPTOR(args.url, args.wordlist, options)
        
        # Start scan
        print(OutputFormatter.info(f"Starting scan of {args.url}"))
        results = raptor.scan()
        
        # Save or print results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(OutputFormatter.success(f"Results saved to {args.output}"))
            
            # Print summary to console
            print("\nScan Summary:")
            print(f"Endpoints discovered: {len(results['endpoints']['listing'])}")
            print(f"Auth methods found: {len(results['authentication']['methods_detected'])}")
            
            # Print GraphQL findings if present
            if 'graphql' in results:
                graphql_results = results['graphql']
                print(f"GraphQL endpoints found: {len(graphql_results['endpoints'])}")
                if 'vulnerabilities' in graphql_results:
                    print(f"GraphQL vulnerabilities: {len(graphql_results['vulnerabilities'])}")
                    
                    # Print high-severity GraphQL findings
                    high_sev_vulns = [v for v in graphql_results['vulnerabilities'] 
                                    if v.get('severity', '').upper() == 'HIGH']
                    if high_sev_vulns:
                        print("\nHigh Severity GraphQL Findings:")
                        for vuln in high_sev_vulns:
                            print(f"- {vuln['type']} in {vuln.get('url', 'Unknown endpoint')}")

            if 'business_logic' in results:
                print(f"Workflows detected: {len(results['business_logic']['workflows_detected'])}")
        else:
            print(json.dumps(results, indent=2))

    except KeyboardInterrupt:
        print(OutputFormatter.warning("\nOperation cancelled by user"))
        sys.exit(1)
    except Exception as e:
        print(OutputFormatter.error(f"\nAn error occurred: {str(e)}"))
        if args.verbose:
            logging.exception("Detailed error information:")
        sys.exit(1)

if __name__ == '__main__':
    main()