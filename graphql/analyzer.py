# raptor/graphql/analyzer.py


import asyncio
import json
from typing import Dict, List, Any, Optional, Set
import requests

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
        
        # Configuration matching RAPTOR's existing settings
        self.timeout = 10
        self.max_retries = 3
        self.rate_limit_delay = 1.0
        
    def analyze(self) -> Dict[str, Any]:
        """Main synchronous entry point for GraphQL analysis"""
        results = {
            'endpoints': {},
            'vulnerabilities': [],
            'schema_analysis': {},
            'test_results': {}
        }

        try:
            # Create event loop for async operations
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
        """Asynchronous analysis implementation"""
        results = {
            'endpoints': {},
            'vulnerabilities': [],
            'schema_analysis': {},
            'test_results': {}
        }

        # Discover GraphQL endpoints
        endpoints = await self._discover_endpoints()
        results['endpoints'] = endpoints

        for url, info in endpoints.items():
            if info['is_graphql']:
                print(self.formatter.success(f"Analyzing GraphQL endpoint: {url}"))
                
                # Analyze schema if available
                schema = await self._fetch_schema(url)
                if schema:
                    schema_analysis = await self.schema_analyzer.analyze(schema)
                    results['schema_analysis'][url] = schema_analysis
                    
                    for vuln in self._extract_vulnerabilities(url, schema_analysis):
                        results['vulnerabilities'].append(vuln)
                        print(self.formatter.warning(
                            f"Found vulnerability: {vuln['type']} in {url}"
                        ))

                # Run security tests
                test_results = await self.tester.run_tests(url)
                results['test_results'][url] = test_results

        return results

    async def _discover_endpoints(self) -> Dict[str, Any]:
        """Discover GraphQL endpoints"""
        endpoints = {}
        
        patterns = [
            '/graphql',
            '/api/graphql',
            '/query',
            '/api/query',
            '/graphiql',
            '/v1/graphql',
            '/v2/graphql',
            '/playground',
            '/gql',
            '/api/gql'
        ]

        for pattern in patterns:
            url = f"{self.base_url.rstrip('/')}{pattern}"
            result = await self._check_endpoint(url)
            if result['is_graphql']:
                endpoints[url] = result
                self.discovered_endpoints.add(url)
                print(self.formatter.success(f"Found GraphQL endpoint: {url}"))

        return endpoints