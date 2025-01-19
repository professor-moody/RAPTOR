import requests
import json
import yaml
import logging
from typing import Dict, List, Set, Optional
from urllib.parse import urljoin, urlparse
import re
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport
import colorama
from colorama import Fore, Style
from datetime import datetime

# Initialize colorama for cross-platform color support
colorama.init()

class OutputFormatter:
    @staticmethod
    def success(message: str) -> str:
        return f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}"
    
    @staticmethod
    def info(message: str) -> str:
        return f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}"
    
    @staticmethod
    def warning(message: str) -> str:
        return f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}"
    
    @staticmethod
    def error(message: str) -> str:
        return f"{Fore.RED}[-] {message}{Style.RESET_ALL}"

class ResultFormatter:
    """Format tool results for output"""
    
    @staticmethod
    def format_command_result(result: Dict) -> str:
        """Format a single command result"""
        output = []
        
        if result.get('success'):
            output.append(OutputFormatter.success("Command executed successfully"))
        else:
            output.append(OutputFormatter.error("Command failed"))
            
        output.append(OutputFormatter.info(f"Command: {result.get('command', 'N/A')}"))
        
        if 'stdout' in result and result['stdout']:
            output.append("\nOutput:")
            output.append(result['stdout'].strip())
            
        if 'stderr' in result and result['stderr']:
            output.append("\nErrors:")
            output.append(OutputFormatter.warning(result['stderr'].strip()))
            
        if 'error' in result:
            output.append(OutputFormatter.error(f"Error: {result['error']}"))
            
        return "\n".join(output)

class APIDiscoverer:
    def __init__(self, base_url: str, wordlist_path: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        # Add rate limiting adapter
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=3,
            pool_block=False
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        
        # Set reasonable default headers
        self.session.headers.update({
            'User-Agent': 'API-Discovery-Tool/1.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        
        self.discovered_endpoints: Set[str] = set()
        self.api_docs: Dict = {}
        self.parameters: Dict[str, List[str]] = {}
        self.auth_methods: Set[str] = set()
        self.versions: Set[str] = set()
        self.formatter = OutputFormatter()
        
        # Add rate limiting
        self.request_delay = 1.0  # seconds between requests
        
        # Load custom wordlist if provided, else use default
        self.wordlist = self._load_wordlist(wordlist_path)
        
        # Common API paths to check
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

    def _load_wordlist(self, wordlist_path: Optional[str]) -> List[str]:
        """Load wordlist from file or use default paths"""
        if wordlist_path:
            try:
                with open(wordlist_path, 'r') as f:
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

    def discover_documentation(self):
        """Attempt to find API documentation"""
        print(self.formatter.info("Searching for API documentation..."))
        
        for path in self.common_doc_paths:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url)
                if response.status_code == 200:
                    print(self.formatter.success(f"Found documentation at: {url}"))
                    
                    # Try to parse as JSON or YAML
                    try:
                        if 'json' in response.headers.get('content-type', ''):
                            self.api_docs[url] = response.json()
                        else:
                            self.api_docs[url] = yaml.safe_load(response.text)
                    except Exception:
                        # Might be HTML documentation
                        if '<html' in response.text.lower():
                            self.api_docs[url] = {'type': 'html', 'content': response.text}
                            
            except requests.RequestException:
                continue

    def parse_swagger_documentation(self):
        """Parse found Swagger/OpenAPI documentation"""
        print(self.formatter.info("Parsing API documentation..."))
        
        for url, doc in self.api_docs.items():
            if isinstance(doc, dict) and 'paths' in doc:
                # OpenAPI/Swagger format
                for path, methods in doc['paths'].items():
                    full_path = urljoin(self.base_url, path)
                    self.discovered_endpoints.add(full_path)
                    
                    # Extract parameters
                    for method, details in methods.items():
                        params = []
                        if 'parameters' in details:
                            params.extend(p['name'] for p in details['parameters'])
                        if 'requestBody' in details:
                            schema = details['requestBody'].get('content', {}).get(
                                'application/json', {}).get('schema', {})
                            if 'properties' in schema:
                                params.extend(schema['properties'].keys())
                        
                        if params:
                            self.parameters[full_path] = params

    def bruteforce_endpoints(self, threads: int = 10):
        """Bruteforce endpoints using wordlist"""
        print(self.formatter.info("Starting endpoint bruteforce..."))
        
        def check_endpoint(path: str):
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url)
                if response.status_code != 404:
                    print(self.formatter.success(
                        f"Found endpoint: {url} ({response.status_code})"
                    ))
                    self.discovered_endpoints.add(url)
                    return url, response
            except requests.RequestException:
                pass
            return None, None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(check_endpoint, self.wordlist)

    def detect_auth_methods(self):
        """Detect authentication methods"""
        print(self.formatter.info("Detecting authentication methods..."))
        
        # Common auth-related paths to check
        auth_paths = [
            '/oauth',
            '/oauth2',
            '/auth',
            '/login',
            '/token',
            '/authenticate',
            '/.well-known/oauth-authorization-server',
            '/.well-known/openid-configuration'
        ]

        # Add auth paths to discovered endpoints
        for path in auth_paths:
            url = urljoin(self.base_url, path)
            try:
                response = self.session.get(url, timeout=5)
                if response.status_code != 404:
                    self.discovered_endpoints.add(url)
            except requests.RequestException:
                continue

        for endpoint in self.discovered_endpoints:
            try:
                # Initial request without auth
                response = self.session.get(endpoint, timeout=5)
                
                # Analyze response headers and status
                headers = response.headers
                
                # Check for WWW-Authenticate header (Basic Auth, Bearer token, etc.)
                if 'www-authenticate' in headers:
                    auth_header = headers['www-authenticate'].lower()
                    if 'basic' in auth_header:
                        self.auth_methods.add("Basic Authentication")
                        print(self.formatter.success(f"Detected Basic Authentication on {endpoint}"))
                    if 'bearer' in auth_header:
                        self.auth_methods.add("Bearer Token")
                        print(self.formatter.success(f"Detected Bearer Token authentication on {endpoint}"))
                    if 'digest' in auth_header:
                        self.auth_methods.add("Digest Authentication")
                        print(self.formatter.success(f"Detected Digest Authentication on {endpoint}"))
                
                # Check response body for auth-related keywords
                try:
                    body = response.text.lower()
                    if any(word in body for word in ['oauth', 'openid', 'authorization_endpoint']):
                        self.auth_methods.add("OAuth/OpenID Connect")
                except (AttributeError, UnicodeDecodeError):
                    pass

                # Check status codes
                if response.status_code in [401, 403]:
                    # Check specific headers that might indicate auth method
                    if 'x-api-key' in headers or any(h.lower().endswith('-api-key') for h in headers):
                        self.auth_methods.add("API Key")
                    elif 'authorization' in headers:
                        self.auth_methods.add("Bearer Token")

                # Look for auth-related response headers
                for header in headers:
                    header_lower = header.lower()
                    if 'api-key' in header_lower:
                        self.auth_methods.add("API Key")
                    elif 'jwt' in header_lower:
                        self.auth_methods.add("JWT")
                    elif 'session' in header_lower:
                        self.auth_methods.add("Session-based Auth")

                # Check documentation if available
                if endpoint in self.api_docs:
                    doc = self.api_docs[endpoint]
                    if isinstance(doc, dict):
                        security_schemes = doc.get('components', {}).get('securitySchemes', {})
                        if security_schemes:
                            for scheme_name, scheme in security_schemes.items():
                                scheme_type = scheme.get('type', '').lower()
                                if scheme_type in ['oauth2', 'openidconnect']:
                                    self.auth_methods.add("OAuth/OpenID Connect")
                                elif scheme_type == 'apikey':
                                    self.auth_methods.add("API Key")
                                elif scheme_type == 'http':
                                    scheme_scheme = scheme.get('scheme', '').lower()
                                    if scheme_scheme == 'bearer':
                                        self.auth_methods.add("Bearer Token")
                                    elif scheme_scheme == 'basic':
                                        self.auth_methods.add("Basic Authentication")

            except requests.RequestException as e:
                print(self.formatter.warning(f"Error checking {endpoint}: {str(e)}"))

    def discover_parameters(self):
        """Discover API parameters through various methods"""
        print(self.formatter.info("Discovering API parameters..."))
        
        common_params = ['id', 'page', 'limit', 'sort', 'filter', 'q', 'search']
        
        for endpoint in self.discovered_endpoints:
            params_found = set()
            
            # Try common parameters
            for param in common_params:
                try:
                    response = self.session.get(f"{endpoint}?{param}=test")
                    if response.status_code != 404:
                        params_found.add(param)
                except requests.RequestException:
                    continue
            
            # Check response content for parameter hints
            try:
                response = self.session.get(endpoint)
                if 'json' in response.headers.get('content-type', ''):
                    data = response.json()
                    if isinstance(data, dict):
                        params_found.update(data.keys())
            except (requests.RequestException, json.JSONDecodeError):
                continue
                
            if params_found:
                self.parameters[endpoint] = list(params_found)

    def detect_versions(self):
        """Detect API versions"""
        print(self.formatter.info("Detecting API versions..."))
        
        version_pattern = re.compile(r'v\d+|version[=/-]\d+')
        
        # Check URLs for version indicators
        for endpoint in self.discovered_endpoints:
            matches = version_pattern.findall(endpoint.lower())
            self.versions.update(matches)
            
        # Check documentation for version info
        for doc in self.api_docs.values():
            if isinstance(doc, dict):
                version = doc.get('info', {}).get('version')
                if version:
                    self.versions.add(f"v{version}")

    def analyze_graphql(self):
        """Analyze GraphQL endpoint if present"""
        print(self.formatter.info("Checking for GraphQL..."))
        
        graphql_endpoints = [
            '/graphql',
            '/api/graphql',
            '/query',
            '/api/query'
        ]
        
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        # Simple introspection query to check if endpoint is GraphQL
        introspection_query = {
            'query': '''
                query {
                  __schema {
                    queryType {
                      name
                    }
                  }
                }
            '''
        }
        
        for endpoint in graphql_endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                # First, do a simple GET request to check if endpoint exists
                response = self.session.get(url, headers=headers, timeout=5)
                
                if response.status_code == 429:
                    print(self.formatter.warning(f"Rate limited at {url}, skipping..."))
                    continue
                    
                if response.status_code not in [200, 400, 405]:  # Many GraphQL endpoints return 400 for GET
                    continue

                # Try POST request with introspection query
                try:
                    response = self.session.post(
                        url, 
                        json=introspection_query,
                        headers=headers,
                        timeout=5
                    )
                    
                    if response.status_code == 429:
                        print(self.formatter.warning(f"Rate limited at {url}, skipping..."))
                        continue

                    # Check if response is valid JSON and contains GraphQL-specific data
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'data' in data or 'errors' in data:  # GraphQL always returns data or errors
                                print(self.formatter.success(f"Found GraphQL endpoint at {url}"))
                                self.discovered_endpoints.add(url)
                        except json.JSONDecodeError:
                            continue
                            
                except requests.RequestException:
                    continue

            except requests.RequestException as e:
                # Only print warning for potentially interesting errors
                if isinstance(e, requests.exceptions.RequestException):
                    if e.response is not None and e.response.status_code not in [404, 429]:
                        print(self.formatter.warning(f"Error checking {url}: {str(e)}"))

    def print_auth_summary(self):
        """Print a summary of detected authentication methods"""
        if not self.auth_methods:
            print(self.formatter.warning("\nNo authentication methods detected."))
            return

        print(self.formatter.info("\nAuthentication Summary:"))
        print("=" * 50)
        for auth_method in sorted(self.auth_methods):
            print(self.formatter.success(f"✓ {auth_method}"))
        print("=" * 50)

    def generate_report(self) -> Dict:
        """Generate a complete report of findings"""
        
        # Group endpoints by auth method
        auth_endpoints = {}
        for endpoint in self.discovered_endpoints:
            for auth_method in self.auth_methods:
                if f"Endpoint: {endpoint}" not in auth_endpoints:
                    auth_endpoints[endpoint] = []
                auth_endpoints[endpoint].append(auth_method)

        return {
            'base_url': self.base_url,
            'authentication': {
                'detected_methods': list(self.auth_methods),
                'protected_endpoints': auth_endpoints,
                'auth_related_endpoints': [
                    endpoint for endpoint in self.discovered_endpoints
                    if any(auth_path in endpoint.lower() 
                          for auth_path in ['/auth', '/oauth', '/login', '/token'])
                ]
            },
            'endpoints': {
                'total_discovered': len(self.discovered_endpoints),
                'listing': list(self.discovered_endpoints)
            },
            'parameters': self.parameters,
            'api_versions': list(self.versions),
            'documentation': {
                'locations': list(self.api_docs.keys()),
                'formats_found': [
                    'OpenAPI/Swagger' if 'paths' in doc else 'HTML' if isinstance(doc, dict) and doc.get('type') == 'html' else 'Unknown'
                    for doc in self.api_docs.values()
                ]
            }
        }

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
│{Fore.WHITE}      Rapid API Testing and Operation Reconnaissance v1.0     {Fore.CYAN}│
├──────────────────────────────────────────────────────────────┤
│{Fore.YELLOW}  [*] API Discovery  [*] Auth Detection  [*] Schema Analysis  {Fore.CYAN}│
╰──────────────────────────────────────────────────────────────╯{Style.RESET_ALL}
"""
    print(banner)

def main():
    import argparse
    
    # Print the banner first
    print_banner()
    
    parser = argparse.ArgumentParser(description='API Endpoint Discoverer')
    parser.add_argument('url', help='Base URL to scan')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of threads for bruteforcing')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Timeout for requests in seconds')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')

    args = parser.parse_args()

    # Configure logging based on verbosity
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level)

    try:
        discoverer = APIDiscoverer(args.url, args.wordlist)

        # Run all discovery methods
        discoverer.discover_documentation()
        discoverer.parse_swagger_documentation()
        discoverer.bruteforce_endpoints(args.threads)
        discoverer.detect_auth_methods()
        discoverer.print_auth_summary()
        discoverer.discover_parameters()
        discoverer.detect_versions()
        discoverer.analyze_graphql()

        # Generate and save report
        report = discoverer.generate_report()
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(OutputFormatter.success(f"Results saved to {args.output}"))
        else:
            print(json.dumps(report, indent=2))

    except KeyboardInterrupt:
        print(OutputFormatter.warning("\nOperation cancelled by user"))
        sys.exit(1)
    except Exception as e:
        print(OutputFormatter.error(f"\nAn error occurred: {str(e)}"))
        sys.exit(1)

if __name__ == '__main__':
    main()