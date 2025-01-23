import requests
import logging
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from output.formatter import OutputFormatter

logger = logging.getLogger(__name__)

class AuthDetector:
    """Handles authentication method detection and analysis with improved output"""

    def __init__(self, session: requests.Session, formatter: OutputFormatter):
        self.session = session
        self.formatter = formatter
        self.base_url = ""  # Will be set in detect_auth_methods
        self.auth_methods: Set[str] = set()
        self._discovered_auth_methods: Set[str] = set()
        self._reported_paths: Set[str] = set()

        # Extended auth headers with provider-specific headers
        self.auth_headers = {
            # Standard Auth Headers
            'Authorization': 'Bearer test',
            'X-API-Key': 'test',
            'API-Key': 'test',
            'X-Auth-Token': 'test',
            'X-Access-Token': 'test',
            
            # AWS Headers
            'X-Amz-Security-Token': 'test',
            'X-Amz-Date': 'test',
            
            # Azure Headers
            'X-MS-OAuth-Token': 'test',
            'X-ZUMO-AUTH': 'test',
            
            # Google Cloud Headers
            'X-Goog-AuthUser': 'test',
            'X-GCP-Auth-Token': 'test',
            
            # Firebase Headers
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
        self.auth_provider_paths = {
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

    def detect_auth_methods(self, base_url: str, endpoints: Set[str], threads: int = 10) -> Dict[str, Any]:
        """Detect authentication methods with improved output organization"""
        print(self.formatter.info("Starting authentication detection..."))
        self.base_url = base_url
        self._reported_paths = set()  # Track reported paths to avoid duplicates
        
        try:
            # First check the base URL to establish primary auth method
            base_response = self.session.get(base_url, timeout=10)
            self._analyze_provider_specific_response(base_url, base_response)
            
            # Group endpoints by their path structure
            endpoint_groups = self._group_endpoints(endpoints)
            
            # Process each group
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = []
                for group, group_endpoints in endpoint_groups.items():
                    # Only process one endpoint per group initially
                    representative = group_endpoints[0]
                    futures.append(executor.submit(self._check_endpoint_auth, representative))
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.warning(f"Error during auth detection: {str(e)}")

            # Check for OAuth and other specific auth endpoints
            self._check_auth_provider_paths(base_url)
            
            return self._generate_report()
            
        except Exception as e:
            logger.error(f"Error during auth detection: {str(e)}")
            raise

    def _check_endpoint_auth(self, endpoint: str) -> Optional[str]:
        """Check authentication methods for a single endpoint"""
        try:
            # Basic request without auth
            response = self.session.get(endpoint, timeout=10)
            self._analyze_auth_response(endpoint, response)
            self._analyze_provider_specific_response(endpoint, response)

            # Test with different auth headers
            for header, value in self.auth_headers.items():
                try:
                    auth_response = self.session.get(
                        endpoint, 
                        headers={header: value},
                        timeout=10
                    )
                    self._analyze_auth_header_response(endpoint, header, auth_response)
                except requests.RequestException:
                    continue

            return endpoint

        except requests.RequestException:
            return None

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
            logger.error(f"Error analyzing auth response for {endpoint}: {str(e)}")

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
                    'JWT': 'JWT Authentication'
                }
                
                auth_type = auth_type_mapping.get(header, f"{header} Authentication")
                self._add_auth_method(auth_type, endpoint)

        except Exception as e:
            logger.error(f"Error analyzing auth header response for {endpoint}: {str(e)}")

    def _analyze_provider_specific_response(self, endpoint: str, response: requests.Response):
        """Analyze response for specific auth providers"""
        try:
            # AWS Cognito Detection
            if any(h.lower().startswith('x-amz-') for h in response.headers):
                if 'cognito' in str(response.headers).lower():
                    self._add_auth_method("AWS Cognito", endpoint)
                else:
                    self._add_auth_method("AWS", endpoint)

            # Azure AD Detection
            if any(h.lower().startswith('x-ms-') for h in response.headers):
                if 'microsoftonline' in str(response.headers).lower():
                    self._add_auth_method("Azure AD", endpoint)
                else:
                    self._add_auth_method("Microsoft", endpoint)

            # Google Cloud Detection
            if any(h.lower().startswith('x-goog-') for h in response.headers):
                self._add_auth_method("Google Cloud", endpoint)

            # Firebase Detection
            if 'firebase' in str(response.headers).lower():
                self._add_auth_method("Firebase", endpoint)

            # Try to parse response for more provider info
            if 'application/json' in response.headers.get('content-type', ''):
                try:
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
                except ValueError:
                    pass

        except Exception as e:
            logger.error(f"Error analyzing provider response for {endpoint}: {str(e)}")

    def _check_auth_provider_paths(self, base_url: str):
        """Check for OAuth and other specific auth endpoints"""
        for provider, paths in self.auth_provider_paths.items():
            for path in paths:
                url = urljoin(base_url, path)
                try:
                    response = self.session.get(url, timeout=10)
                    if response.status_code != 404:
                        self._analyze_oauth_response(url, response)
                except requests.RequestException:
                    continue

    def _analyze_oauth_response(self, endpoint: str, response: requests.Response):
        """Analyze potential OAuth endpoint responses"""
        try:
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                if 'json' in content_type:
                    try:
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
                    except ValueError:
                        pass

        except Exception as e:
            logger.error(f"Error analyzing OAuth response for {endpoint}: {str(e)}")

    def _add_auth_method(self, method: str, endpoint: str):
        """Add authentication method with smarter logging"""
        try:
            # Only add and log if it's a new discovery
            method_endpoint = f"{method}:{endpoint}"
            if method_endpoint not in self._discovered_auth_methods:
                base_url = self.base_url.rstrip('/')
                
                # If this is the first finding for this method
                if method not in self.auth_methods:
                    self.auth_methods.add(method)
                    print(self.formatter.success(
                        f"\n[+] Detected {method} Authentication Provider"
                    ))
                    
                # Only show endpoint if it's not just a path variant
                endpoint_without_base = endpoint.replace(base_url, '').strip('/')
                if '/' in endpoint_without_base or '.' in endpoint_without_base:
                    if self._is_interesting_endpoint(endpoint_without_base):
                        print(self.formatter.info(
                            f"    ╰─> Found at: /{endpoint_without_base}"
                        ))
                
                self._discovered_auth_methods.add(method_endpoint)
                
        except Exception as e:
            logger.error(f"Error adding auth method: {str(e)}")

    def _is_interesting_endpoint(self, endpoint: str) -> bool:
        """Determine if an endpoint is interesting enough to report"""
        # Skip common extensions of already reported paths
        if any(endpoint.endswith(ext) for ext in ['.json', '.xml']):
            base_path = endpoint.rsplit('.', 1)[0]
            if f"{base_path}/" in self._reported_paths:
                return False
                
        # Skip if we've already reported a similar path
        path_parts = endpoint.split('/')
        if len(path_parts) > 1:
            parent_path = '/'.join(path_parts[:-1])
            if parent_path in self._reported_paths:
                last_part = path_parts[-1]
                # Skip if it's just a variant of the parent
                if any(variant in last_part for variant in ['v1', 'v2', 'v3', 'api']):
                    return False
                    
        # Keep track of reported paths
        self._reported_paths.add(endpoint)
        return True

    def _group_endpoints(self, endpoints: Set[str]) -> Dict[str, List[str]]:
        """Group endpoints by their path structure"""
        groups = {}
        for endpoint in endpoints:
            path = endpoint.replace(self.base_url, '').strip('/')
            # Create a group key by removing extensions and variable parts
            group_key = self._get_group_key(path)
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(endpoint)
        return groups
        
    def _get_group_key(self, path: str) -> str:
        """Generate a group key for an endpoint path"""
        if not path:
            return 'root'
            
        parts = path.split('/')
        # Remove extensions
        parts = [p.split('.')[0] for p in parts]
        # Remove version numbers and common variants
        parts = [p for p in parts if not (p.startswith('v') and p[1:].isdigit())]
        # Remove empty parts
        parts = [p for p in parts if p]
        
        if not parts:
            return 'root'
            
        return '/'.join(parts)

    def _generate_report(self) -> Dict[str, Any]:
        """Generate final report of auth detection findings"""
        report = {
            'auth_methods': sorted(list(self.auth_methods)),
            'endpoints_checked': len(self._reported_paths),
            'auth_findings': []
        }

        # Group findings by auth method
        method_findings = {}
        for method_endpoint in sorted(self._discovered_auth_methods):
            method, endpoint = method_endpoint.split(':', 1)
            if method not in method_findings:
                method_findings[method] = []
            
            # Clean endpoint path
            endpoint_path = endpoint.replace(self.base_url, '').strip('/')
            if endpoint_path:
                method_findings[method].append(endpoint_path)

        # Add organized findings to report
        for method, endpoints in method_findings.items():
            report['auth_findings'].append({
                'method': method,
                'endpoints': sorted(list(set(endpoints))),
                'total_endpoints': len(endpoints)
            })

        # Add summary information
        report['summary'] = {
            'total_auth_methods': len(self.auth_methods),
            'total_endpoints_with_auth': len(self._discovered_auth_methods),
            'primary_auth_provider': self._determine_primary_provider()
        }

        return report

    def _determine_primary_provider(self) -> Optional[str]:
        """Determine the primary authentication provider"""
        if not self.auth_methods:
            return None
            
        # Count occurrences of each auth method
        method_counts = {}
        for method_endpoint in self._discovered_auth_methods:
            method = method_endpoint.split(':', 1)[0]
            method_counts[method] = method_counts.get(method, 0) + 1

        # Return the most common auth method
        if method_counts:
            return max(method_counts.items(), key=lambda x: x[1])[0]
        return None