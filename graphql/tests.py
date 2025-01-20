# raptor/graphql/tests.py

import asyncio
import json
from typing import Dict, List, Any
import requests
from output.formatter import OutputFormatter

class GraphQLTester:
    """GraphQL Security Testing Module"""

    def __init__(self, session: requests.Session, formatter: OutputFormatter):
        self.session = session
        self.formatter = formatter
        self.timeout = 10

    async def run_tests(self, url: str) -> Dict[str, Any]:
        """Run all GraphQL security tests"""
        results = {
            'introspection': await self.test_introspection(url),
            'batch_queries': await self.test_batch_queries(url),
            'depth_limit': await self.test_query_depth(url),
            'cost_limit': await self.test_query_cost(url),
            'field_suggestion': await self.test_field_suggestions(url),
            'dos_protection': await self.test_dos_protection(url),
            'auth_bypass': await self.test_auth_bypass(url),
        }

        # Add overall risk score
        results['risk_score'] = self._calculate_risk_score(results)
        return results

    async def test_introspection(self, url: str) -> Dict[str, Any]:
        """Test introspection query vulnerabilities"""
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'LOW'
        }

        queries = [
            # Full introspection query
            '''
            query IntrospectionQuery {
                __schema {
                    types { name }
                }
            }
            ''',
            # Partial introspection
            '{ __schema { types { name } } }',
            # Type introspection
            '{ __type(name: "User") { name fields { name type { name } } } }'
        ]

        for query in queries:
            try:
                response = await self._make_graphql_request(url, query)
                if response and 'data' in response:
                    result['vulnerable'] = True
                    result['details']['query_type'] = query.split('{')[1].split('}')[0].strip()
                    result['severity'] = 'MEDIUM'
                    break
            except Exception:
                continue

        return result

    async def test_batch_queries(self, url: str) -> Dict[str, Any]:
        """Test for batch query vulnerabilities"""
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'LOW'
        }

        # Test batch query
        batch_query = [
            {'query': '{ __typename }'},
            {'query': '{ __typename }'}
        ]

        try:
            response = await self._make_request('POST', url, json=batch_query)
            if response.status_code == 200:
                if isinstance(response.json(), list):
                    result['vulnerable'] = True
                    result['severity'] = 'MEDIUM'
                    result['details']['supports_batching'] = True
        except Exception:
            pass

        return result

    async def test_query_depth(self, url: str) -> Dict[str, Any]:
        """Test for query depth limitations"""
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'LOW'
        }

        # Generate deeply nested query
        deep_query = self._generate_deep_query(depth=10)

        try:
            response = await self._make_graphql_request(url, deep_query)
            if response and 'data' in response:
                result['vulnerable'] = True
                result['severity'] = 'HIGH'
                result['details']['max_depth_tested'] = 10
        except Exception as e:
            if 'depth' in str(e).lower():
                result['details']['depth_limit_detected'] = True

        return result

    async def test_dos_protection(self, url: str) -> Dict[str, Any]:
        """Test for DoS protections"""
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'LOW'
        }

        # Test rapid requests
        requests_count = 10
        success_count = 0

        for _ in range(requests_count):
            try:
                response = await self._make_graphql_request(url, '{ __typename }')
                if response and 'data' in response:
                    success_count += 1
            except Exception:
                break

        if success_count == requests_count:
            result['vulnerable'] = True
            result['severity'] = 'HIGH'
            result['details']['no_rate_limiting'] = True

        return result

    def _calculate_risk_score(self, test_results: Dict) -> int:
        """Calculate overall risk score"""
        severity_scores = {
            'LOW': 1,
            'MEDIUM': 2,
            'HIGH': 3
        }

        score = 0
        for test, result in test_results.items():
            if isinstance(result, dict) and result.get('vulnerable'):
                score += severity_scores.get(result.get('severity', 'LOW'), 1)

        return score

    async def _make_graphql_request(self, url: str, query: str) -> Dict:
        """Make a GraphQL request"""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        data = {'query': query}
        response = await self._make_request('POST', url, headers=headers, json=data)
        
        if response.status_code == 200:
            return response.json()
        return None

    async def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling"""
        try:
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            print(self.formatter.error(f"Request error: {str(e)}"))
            raise

    def _generate_deep_query(self, depth: int) -> str:
        """Generate a deeply nested query"""
        def _nest(current_depth: int) -> str:
            if current_depth <= 0:
                return "{ field }"
            return f"{{ nested {_nest(current_depth - 1)} }}"

        return f"query deep {_nest(depth)}"