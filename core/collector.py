# raptor/core/collector.py

import requests
import json
import logging
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs
import networkx as nx
from datetime import datetime
import yaml
from bs4 import BeautifulSoup

class EnhancedDataCollector:
    """Enhanced data collection for endpoint discovery and analysis"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.endpoints: Dict[str, Dict[str, Any]] = {}
        self.api_docs: Dict[str, Any] = {}
        self.parameters: Dict[str, List[str]] = {}
        self.auth_methods: Set[str] = set()
        self.versions: Set[str] = set()
        self.logger = logging.getLogger('raptor.collector')
        
        # Set up session with default headers
        self.session.headers.update({
            'User-Agent': 'RAPTOR/1.0',
            'Accept': 'application/json, */*',
        })

    def collect_endpoint_data(self, endpoint: str) -> Dict[str, Any]:
        """Collect comprehensive data about an endpoint"""
        if endpoint not in self.endpoints:
            self.endpoints[endpoint] = {
                'methods': set(),
                'parameters': {
                    'path': [],
                    'query': [],
                    'body': [],
                    'header': []
                },
                'auth_required': False,
                'responses': [],
                'content_types': set(),
                'last_seen': datetime.now()
            }

        try:
            # Try different HTTP methods
            for method in ['GET', 'POST', 'PUT', 'DELETE']:
                response = self.session.request(
                    method=method,
                    url=endpoint,
                    allow_redirects=False,
                    timeout=10
                )
                
                # Store successful methods
                if response.status_code != 405:  # Method not allowed
                    self.endpoints[endpoint]['methods'].add(method)
                
                # Store response information
                self._process_response(endpoint, response)
                
                # Check for authentication requirements
                self._check_auth_requirements(endpoint, response)
                
                # Extract parameters
                self._extract_parameters(endpoint, response)
                
        except requests.RequestException as e:
            self.logger.debug(f"Error collecting data for {endpoint}: {str(e)}")

        return self.endpoints[endpoint]

    def _process_response(self, endpoint: str, response: requests.Response):
        """Process and store response information"""
        content_type = response.headers.get('content-type', '')
        self.endpoints[endpoint]['content_types'].add(content_type)
        
        response_data = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content_type': content_type
        }
        
        # Try to parse response body
        try:
            if 'application/json' in content_type:
                response_data['body'] = response.json()
            else:
                response_data['body'] = response.text[:1000]  # Store first 1000 chars
        except json.JSONDecodeError:
            response_data['body'] = None
            
        self.endpoints[endpoint]['responses'].append(response_data)

    def _check_auth_requirements(self, endpoint: str, response: requests.Response):
        """Check if endpoint requires authentication"""
        # Check status codes
        if response.status_code in [401, 403]:
            self.endpoints[endpoint]['auth_required'] = True
            
        # Check headers
        auth_headers = ['www-authenticate', 'authorization', 'x-api-key']
        if any(h in response.headers.keys() for h in auth_headers):
            self.endpoints[endpoint]['auth_required'] = True
            
        # Check response content
        auth_keywords = ['unauthorized', 'forbidden', 'authentication required']
        try:
            content = response.text.lower()
            if any(keyword in content for keyword in auth_keywords):
                self.endpoints[endpoint]['auth_required'] = True
        except (AttributeError, UnicodeDecodeError):
            pass

    def _extract_parameters(self, endpoint: str, response: requests.Response):
        """Extract parameters from endpoint and response"""
        # Parse URL parameters
        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)
        
        # Store query parameters
        self.endpoints[endpoint]['parameters']['query'].extend(query_params.keys())
        
        # Parse path parameters
        path_segments = [s for s in parsed.path.split('/') if s]
        for segment in path_segments:
            if '{' in segment or ':' in segment or segment.isdigit():
                self.endpoints[endpoint]['parameters']['path'].append(segment)
        
        # Check response for potential parameters
        try:
            if 'application/json' in response.headers.get('content-type', ''):
                data = response.json()
                if isinstance(data, dict):
                    self.endpoints[endpoint]['parameters']['body'].extend(data.keys())
        except (json.JSONDecodeError, AttributeError):
            pass

    def parse_swagger_documentation(self):
        """Parse Swagger/OpenAPI documentation"""
        for url, doc in self.api_docs.items():
            if not isinstance(doc, dict):
                continue
                
            # Handle OpenAPI/Swagger formats
            if 'paths' in doc:
                for path, methods in doc['paths'].items():
                    full_path = urljoin(self.base_url, path)
                    
                    if full_path not in self.endpoints:
                        self.endpoints[full_path] = {
                            'methods': set(),
                            'parameters': {
                                'path': [],
                                'query': [],
                                'body': [],
                                'header': []
                            },
                            'auth_required': False,
                            'responses': [],
                            'content_types': set(),
                            'documented': True
                        }
                    
                    # Extract method information
                    for method, details in methods.items():
                        self.endpoints[full_path]['methods'].add(method.upper())
                        
                        # Extract parameters
                        if 'parameters' in details:
                            for param in details['parameters']:
                                param_in = param.get('in', '')
                                if param_in in ['path', 'query', 'header']:
                                    self.endpoints[full_path]['parameters'][param_in].append(
                                        param['name']
                                    )

    def get_endpoint_summary(self) -> Dict[str, Any]:
        """Generate a summary of collected endpoint data"""
        return {
            'total_endpoints': len(self.endpoints),
            'authenticated_endpoints': sum(
                1 for data in self.endpoints.values()
                if data['auth_required']
            ),
            'endpoints': {
                endpoint: {
                    'methods': list(data['methods']),
                    'parameters': data['parameters'],
                    'auth_required': data['auth_required'],
                    'content_types': list(data['content_types'])
                }
                for endpoint, data in self.endpoints.items()
            }
        }