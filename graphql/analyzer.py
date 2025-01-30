# raptor/graphql/analyzer.py

import asyncio
import json
from typing import Dict, List, Any, Optional, Set
import requests
<<<<<<< HEAD
from urllib.parse import urljoin, urlparse
import time
=======
from urllib.parse import urljoin
>>>>>>> 7e3c8bf9a36facf0d0f80cf45b2e0b541100c092

from output.formatter import OutputFormatter
from .schema import SchemaAnalyzer
from .tests import GraphQLTester

class GraphQLAnalyzer:
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
<<<<<<< HEAD
            '/.well-known/graphql',
=======
>>>>>>> 7e3c8bf9a36facf0d0f80cf45b2e0b541100c092
            '/graphql/v1',
            '/graphql/v2',
            '/api/v1/graphql',
            '/api/v2/graphql'
        ]
<<<<<<< HEAD

    async def _discover_endpoints(self) -> Dict[str, Any]:
        """Discover GraphQL endpoints"""
        endpoints = {}
        
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

=======
        
>>>>>>> 7e3c8bf9a36facf0d0f80cf45b2e0b541100c092
    async def _check_endpoint(self, url: str) -> Dict[str, Any]:
        """Check if endpoint is GraphQL"""
        result = {
            'is_graphql': False,
            'supports_introspection': False,
            'schema_available': False,
            'details': {}
        }

<<<<<<< HEAD
        detection_methods = [
            self._check_simple_query,
            self._check_introspection,
            self._check_malformed_query,
            self._check_batching
        ]

        for method in detection_methods:
            try:
                method_result = await method(url)
                result['details'].update(method_result)
                if method_result.get('is_graphql'):
                    result['is_graphql'] = True
                if method_result.get('supports_introspection'):
                    result['supports_introspection'] = True
                if method_result.get('schema_available'):
                    result['schema_available'] = True
            except Exception:
                continue

        return result

    async def _check_simple_query(self, url: str) -> Dict[str, Any]:
        """Check endpoint with a simple query"""
        try:
            query = '{ __typename }'
            headers = {'Content-Type': 'application/json'}
            response = self.session.post(
                url, 
                json={'query': query},
=======
        try:
            # Test basic query
            test_query = '{ __typename }'
            headers = {'Content-Type': 'application/json'}
            response = self.session.post(
                url, 
                json={'query': test_query},
>>>>>>> 7e3c8bf9a36facf0d0f80cf45b2e0b541100c092
                headers=headers,
                timeout=10
            )

            is_json = 'application/json' in response.headers.get('content-type', '')
<<<<<<< HEAD
            if response.status_code == 200 and is_json:
                data = response.json()
                if 'data' in data and '__typename' in data['data']:
                    return {'is_graphql': True, 'simple_query': True}

        except Exception:
            pass
        return {'is_graphql': False}

    async def _check_introspection(self, url: str) -> Dict[str, Any]:
        """Check introspection support"""
        try:
            schema = await self._fetch_schema(url)
            if schema:
                return {
                    'is_graphql': True,
                    'supports_introspection': True,
                    'schema_available': True
                }
        except Exception:
            pass
        return {'supports_introspection': False}

    async def _check_malformed_query(self, url: str) -> Dict[str, Any]:
        """Check response to malformed queries"""
        try:
            query = '{ malformed { field'  # Intentionally malformed
            response = self.session.post(
                url,
                json={'query': query},
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code == 400:
                data = response.json()
                if 'errors' in data and any('syntax' in str(e).lower() for e in data['errors']):
                    return {'is_graphql': True, 'handles_errors': True}
        except Exception:
            pass
        return {}

    async def _check_batching(self, url: str) -> Dict[str, Any]:
        """Check batch query support"""
        try:
            batch_query = [
                {'query': '{ __typename }'},
                {'query': '{ __typename }'}
            ]
            response = self.session.post(
                url,
                json=batch_query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code == 200 and isinstance(response.json(), list):
                return {'supports_batching': True}
        except Exception:
            pass
        return {'supports_batching': False}

    async def _fetch_schema(self, url: str) -> Optional[Dict]:
        """Fetch complete GraphQL schema"""
        introspection_query = """
        query IntrospectionQuery {
          __schema {
            queryType { name fields { name type { name kind } description args { name type { name kind } } } }
            mutationType { name fields { name type { name kind } description args { name type { name kind } } } }
            subscriptionType { name fields { name type { name kind } description } }
            types {
              name
              kind
              description
              fields { 
                name
                type { name kind ofType { name kind } }
                args { name type { name kind } }
              }
              interfaces { name }
              enumValues { name description }
              possibleTypes { name }
            }
            directives {
              name
              description
              locations
              args { name type { name kind } }
            }
          }
=======
            
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
>>>>>>> 7e3c8bf9a36facf0d0f80cf45b2e0b541100c092
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
<<<<<<< HEAD
                if 'data' in data and '__schema' in data['data']:
=======
                if 'data' in data:
>>>>>>> 7e3c8bf9a36facf0d0f80cf45b2e0b541100c092
                    return data['data']['__schema']
                    
        except Exception as e:
            print(self.formatter.warning(f"Error fetching schema: {str(e)}"))
            
        return None

<<<<<<< HEAD
    def _extract_vulnerabilities(self, url: str, schema_analysis: Dict) -> List[Dict]:
        """Extract and format vulnerabilities from schema analysis"""
        vulnerabilities = []
        
        # Extract from security concerns
        for concern in schema_analysis.get('security_concerns', []):
            vulnerabilities.append({
                'url': url,
                'type': concern['type'],
                'severity': concern['severity'],
                'location': concern['location'],
                'details': {
                    'description': concern['description']
                }
            })

        # Check for dangerous types
        for type_info in schema_analysis.get('types', {}).get('sensitive_types', []):
            vulnerabilities.append({
                'url': url,
                'type': 'sensitive_type_exposure',
                'severity': 'HIGH',
                'location': f"Type: {type_info}",
                'details': {
                    'description': f"Sensitive information exposed in type: {type_info}"
                }
            })

        # Check for dangerous mutations
        mutations = schema_analysis.get('mutations', [])
        for mutation in mutations:
            if any(pattern in mutation['name'].lower() for pattern in [
                'delete', 'remove', 'update', 'create', 'execute'
            ]):
                vulnerabilities.append({
                    'url': url,
                    'type': 'dangerous_mutation',
                    'severity': 'MEDIUM',
                    'location': f"Mutation: {mutation['name']}",
                    'details': {
                        'description': f"Potentially dangerous mutation found: {mutation['name']}"
                    }
                })

        return vulnerabilities

    async def _analyze(self) -> Dict[str, Any]:
        """Main analysis implementation"""
        try:
            results = {
                'endpoints': {},
                'vulnerabilities': [],
                'schema_analysis': {},
                'test_results': {}
            }

            print(self.formatter.info("\nStarting GraphQL Analysis..."))
            
            # Discover endpoints
            endpoints = await self._discover_endpoints()
            results['endpoints'] = endpoints

            for url, info in endpoints.items():
                if info['is_graphql']:
                    print(self.formatter.info(f"\nAnalyzing GraphQL endpoint: {url}"))
                    
                    # Schema Analysis
                    if info['schema_available']:
                        schema = await self._fetch_schema(url)
                        if schema:
                            print(self.formatter.info("Analyzing schema..."))
                            schema_analysis = await self.schema_analyzer.analyze(schema)
                            results['schema_analysis'][url] = schema_analysis
                            
                            # Extract vulnerabilities
                            vulns = self._extract_vulnerabilities(url, schema_analysis)
                            results['vulnerabilities'].extend(vulns)
                            
                            for vuln in vulns:
                                print(self.formatter.warning(
                                    f"[{vuln['severity']}] {vuln['type']} in {vuln['location']}"
                                ))

                    # Security Testing
                    print(self.formatter.info("Running security tests..."))
                    test_results = await self.tester.run_tests(url)
                    results['test_results'][url] = test_results
                    
                    # Extract test vulnerabilities
                    for test_name, test_result in test_results.items():
                        if isinstance(test_result, dict) and test_result.get('vulnerable'):
                            results['vulnerabilities'].append({
                                'url': url,
                                'type': f'graphql_{test_name}',
                                'severity': test_result['severity'],
                                'details': test_result.get('details', {})
                            })

            # Print summary
            self._print_analysis_summary(results)
            return results
            
        except Exception as e:
            print(self.formatter.error(f"Error during analysis: {str(e)}"))
            return results

    def _print_analysis_summary(self, results: Dict[str, Any]):
        """Print analysis summary"""
        endpoints = len(results['endpoints'])
        vulns = len(results['vulnerabilities'])
        
        print(self.formatter.info(f"\nGraphQL Analysis Summary:"))
        print(f"Endpoints discovered: {endpoints}")
        print(f"Vulnerabilities found: {vulns}")
        
        if vulns > 0:
            severity_count = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            for vuln in results['vulnerabilities']:
                severity_count[vuln['severity']] += 1
                
            print(f"Severity breakdown:")
            print(f"  HIGH: {severity_count['HIGH']}")
            print(f"  MEDIUM: {severity_count['MEDIUM']}")
            print(f"  LOW: {severity_count['LOW']}")
            
            if severity_count['HIGH'] > 0:
                print(self.formatter.error("\nHigh Severity Findings:"))
                for vuln in results['vulnerabilities']:
                    if vuln['severity'] == 'HIGH':
                        print(f"  - {vuln['type']} in {vuln['location']}")

    def analyze(self) -> Dict[str, Any]:
        """Main entry point for GraphQL analysis"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self._analyze())
            finally:
                loop.close()
        except Exception as e:
            print(self.formatter.error(f"Error during GraphQL analysis: {str(e)}"))
            return {
                'error': str(e),
                'endpoints': {},
                'vulnerabilities': [],
                'schema_analysis': {},
                'test_results': {}
            }
=======
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
>>>>>>> 7e3c8bf9a36facf0d0f80cf45b2e0b541100c092
