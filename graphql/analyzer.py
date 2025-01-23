# raptor/graphql/analyzer.py

import asyncio
import json
from typing import Dict, List, Any, Optional, Set
import requests
from urllib.parse import urljoin

from output.formatter import OutputFormatter
from .schema import SchemaAnalyzer
from .tests import GraphQLTester

class GraphQLAnalyzer:
    """Main GraphQL analysis module"""

    def __init__(self, session: requests.Session, base_url: str, formatter: OutputFormatter):
        self.session = session
        self.base_url = base_url
        self.formatter = formatter
        self.schema_analyzer = SchemaAnalyzer(formatter)
        self.tester = GraphQLTester(session, formatter)
        self.discovered_endpoints: Set[str] = set()
        
        self.common_paths = [
            '/graphql',
            '/api/graphql',
            '/query',
            '/api/query',
            '/graphiql',
            '/v1/graphql',
            '/v2/graphql',
            '/playground',
            '/gql',
            '/api/gql',
            '/graphql/console',
            '/graphql/v1',
            '/graphql/v2',
            '/api/v1/graphql',
            '/api/v2/graphql'
        ]
        
    async def _check_endpoint(self, url: str) -> Dict[str, Any]:
        """Check if endpoint is GraphQL"""
        result = {
            'is_graphql': False,
            'supports_introspection': False,
            'schema_available': False,
            'details': {}
        }

        try:
            # Test basic query
            test_query = '{ __typename }'
            headers = {'Content-Type': 'application/json'}
            response = self.session.post(
                url, 
                json={'query': test_query},
                headers=headers,
                timeout=10
            )

            is_json = 'application/json' in response.headers.get('content-type', '')
            
            if response.status_code == 200 and is_json:
                data = response.json()
                if 'data' in data or 'errors' in data:
                    result['is_graphql'] = True
                    result['details']['status_code'] = response.status_code
                    
                    # Check introspection
                    schema = await self._fetch_schema(url)
                    if schema:
                        result['supports_introspection'] = True
                        result['schema_available'] = True
                        result['details']['schema_size'] = len(str(schema))

        except Exception as e:
            result['details']['error'] = str(e)

        return result

    async def _fetch_schema(self, url: str) -> Optional[Dict]:
        """Fetch GraphQL schema via introspection"""
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                types { name kind description fields { name type { name kind } } }
                queryType { name }
                mutationType { name }
                subscriptionType { name }
            }
        }
        """

        try:
            response = self.session.post(
                url,
                json={'query': introspection_query},
                headers={'Content-Type': 'application/json'},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    return data['data']['__schema']
                    
        except Exception as e:
            print(self.formatter.warning(f"Error fetching schema: {str(e)}"))
            
        return None

    async def _discover_endpoints(self) -> Dict[str, Any]:
        """Discover GraphQL endpoints"""
        endpoints = {}

        print(self.formatter.info("\nDiscovering GraphQL endpoints..."))
        
        for path in self.common_paths:
            url = urljoin(self.base_url, path)
            result = await self._check_endpoint(url)
            
            if result['is_graphql']:
                endpoints[url] = result
                self.discovered_endpoints.add(url)
                
                status = []
                if result['supports_introspection']:
                    status.append("Introspection: ✓")
                if result['schema_available']:
                    status.append("Schema: ✓")
                    
                print(self.formatter.success(
                    f"Found GraphQL endpoint: {url} ({', '.join(status)})"
                ))

        return endpoints

    def analyze(self) -> Dict[str, Any]:
        """Analyze discovered GraphQL endpoints"""
        results = {
            'endpoints': {},
            'vulnerabilities': [],
            'schema_analysis': {},
            'test_results': {}
        }

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                results = loop.run_until_complete(self._analyze())
            finally:
                loop.close()

        except Exception as e:
            print(self.formatter.error(f"Error during GraphQL analysis: {str(e)}"))
            results['error'] = str(e)

        return results

    async def _analyze(self) -> Dict[str, Any]:
        """Run full GraphQL analysis"""
        results = {
            'endpoints': {},
            'vulnerabilities': [],
            'schema_analysis': {},
            'test_results': {}
        }

        # Discover endpoints
        endpoints = await self._discover_endpoints()
        results['endpoints'] = endpoints

        for url, info in endpoints.items():
            if info['is_graphql']:
                print(self.formatter.info(f"\nAnalyzing endpoint: {url}"))
                
                # Get schema
                if info['schema_available']:
                    schema = await self._fetch_schema(url)
                    if schema:
                        # Analyze schema
                        schema_analysis = await self.schema_analyzer.analyze(schema)
                        results['schema_analysis'][url] = schema_analysis
                        
                        # Extract vulnerabilities
                        for issue in schema_analysis.get('security_concerns', []):
                            results['vulnerabilities'].append({
                                'url': url,
                                'type': issue['type'],
                                'severity': issue['severity'],
                                'location': issue['location'],
                                'description': issue['description']
                            })
                
                # Run security tests
                print(self.formatter.info("Running security tests..."))
                test_results = await self.tester.run_tests(url)
                results['test_results'][url] = test_results
                
                # Add test vulnerabilities
                for test_name, test_result in test_results.items():
                    if isinstance(test_result, dict) and test_result.get('vulnerable'):
                        results['vulnerabilities'].append({
                            'url': url,
                            'type': f'graphql_{test_name}',
                            'severity': test_result['severity'],
                            'details': test_result.get('details', {})
                        })

        # Print summary
        total_vulns = len(results['vulnerabilities'])
        if total_vulns:
            print(self.formatter.info(f"\nFound {total_vulns} potential vulnerabilities:"))
            for vuln in results['vulnerabilities']:
                print(self.formatter.warning(
                    f"[{vuln['severity']}] {vuln['type']} in {vuln['url']}"
                ))

        return results