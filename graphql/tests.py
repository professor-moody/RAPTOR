# raptor/graphql/tests.py

import asyncio
import json
from typing import Dict, List, Any
import requests
import time
from output.formatter import OutputFormatter

class GraphQLTester:
    def __init__(self, session: requests.Session, formatter: OutputFormatter):
        self.session = session
        self.formatter = formatter
        self.timeout = 10

    async def run_tests(self, url: str) -> Dict[str, Any]:
        tests = {
            'introspection': self.test_introspection,
            'batch_queries': self.test_batch_queries,
            'depth_limit': self.test_query_depth,
            'field_suggestions': self.test_field_suggestions,
            'dos_protection': self.test_dos_protection,
            'auth_bypass': self.test_auth_bypass,
            'injection': self.test_injection,
            'error_exposure': self.test_error_exposure
        }

        results = {}
        for test_name, test_func in tests.items():
            try:
                results[test_name] = await test_func(url)
            except Exception as e:
                print(self.formatter.error(f"Error in {test_name}: {str(e)}"))
                results[test_name] = {'vulnerable': False, 'error': str(e)}

        results['risk_score'] = self._calculate_risk_score(results)
        return results

    async def test_introspection(self, url: str) -> Dict[str, Any]:
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'MEDIUM'
        }

        queries = [
            # Full introspection
            '''query IntrospectionQuery {
                __schema {
                    types { name kind fields { name type { name kind } } }
                }
            }''',
            # Type information
            '{ __type(name: "User") { name fields { name type { name } } } }',
            # Schema structure
            '{ __schema { types { name } } }',
            # Directives
            '{ __schema { directives { name description args { name } } } }'
        ]

        for query in queries:
            try:
                response = await self._make_graphql_request(url, query)
                if response and 'data' in response:
                    result['vulnerable'] = True
                    result['details']['query_type'] = query.split('{')[1].split('}')[0].strip()
                    result['details']['response_size'] = len(str(response))
                    break
            except Exception:
                continue

        return result

    async def test_query_depth(self, url: str) -> Dict[str, Any]:
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'HIGH'
        }

        depths = [5, 10, 15, 20]
        for depth in depths:
            query = self._generate_deep_query(depth)
            try:
                response = await self._make_graphql_request(url, query)
                if response and 'data' in response:
                    result['vulnerable'] = True
                    result['details']['max_depth'] = depth
                    result['details']['response_size'] = len(str(response))
            except Exception as e:
                if 'depth' in str(e).lower():
                    result['details']['depth_limit'] = depth
                    break

        return result

    async def test_field_suggestions(self, url: str) -> Dict[str, Any]:
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'LOW'
        }

        test_queries = [
            '{ user { name email passsword } }',  # Misspelled field
            '{ users { username passwords } }',    # Non-existent field
            '{ user { username creditcard } }'     # Wrong field name
        ]

        for query in test_queries:
            try:
                response = await self._make_graphql_request(url, query)
                if response and 'errors' in response:
                    errors = response['errors']
                    for error in errors:
                        if 'Did you mean' in str(error):
                            result['vulnerable'] = True
                            result['details']['suggestions'] = True
                            result['details']['error_message'] = error.get('message', '')
            except Exception:
                continue

        return result

    async def test_dos_protection(self, url: str) -> Dict[str, Any]:
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'HIGH'
        }

        request_times = []
        for _ in range(10):
            start_time = time.time()
            try:
                response = await self._make_graphql_request(url, '{ __typename }')
                if response:
                    request_times.append(time.time() - start_time)
            except Exception:
                break

        if len(request_times) == 10:
            result['vulnerable'] = True
            result['details']['avg_response_time'] = sum(request_times) / len(request_times)
            result['details']['no_rate_limiting'] = True

        large_query = 'query { ' + ' '.join([f'field{i}: __typename ' for i in range(100)]) + ' }'
        try:
            response = await self._make_graphql_request(url, large_query)
            if response and 'data' in response:
                result['details']['allows_large_queries'] = True
        except Exception:
            result['details']['query_size_limited'] = True

        return result

    async def test_auth_bypass(self, url: str) -> Dict[str, Any]:
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'HIGH'
        }

        headers_to_try = {
            'no_auth': {},
            'null_token': {'Authorization': 'null'},
            'empty_token': {'Authorization': ''},
            'bearer_null': {'Authorization': 'Bearer null'},
            'basic_null': {'Authorization': 'Basic bnVsbA=='},
            'custom_auth': {'X-Auth-Token': 'null'}
        }

        baseline_query = '{ __schema { types { name } } }'
        baseline = await self._make_graphql_request(url, baseline_query)

        for test_name, headers in headers_to_try.items():
            try:
                response = await self._make_graphql_request(url, baseline_query, headers)
                if response and response == baseline:
                    result['vulnerable'] = True
                    result['details']['bypass_method'] = test_name
                    result['details']['headers'] = headers
                    break
            except Exception:
                continue

        return result

    async def test_injection(self, url: str) -> Dict[str, Any]:
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'CRITICAL'
        }

        injection_tests = [
            {'query': '{ user(id: "1 OR 1=1") { id name } }'},
            {'query': '{ user(id: "1\' UNION SELECT NULL--") { id } }'},
            {'query': '{ user(id: {$gt: ""}) { id } }'},
            {'query': '{ user(id: {$where: "1==1"}) { id } }'},
            {'query': '{ user(id: "1; sleep 5") { id } }'},
            {'query': '{ user(id: "`sleep 5`") { id } }'},
        ]

        for test in injection_tests:
            start_time = time.time()
            try:
                response = await self._make_request('POST', url, json=test)
                execution_time = time.time() - start_time

                if execution_time > 5:
                    result['vulnerable'] = True
                    result['details']['injection_type'] = 'time-based'
                    result['details']['payload'] = test['query']
                    break
                    
                if response.status_code == 200:
                    data = response.json()
                    if 'errors' in data:
                        error_msg = str(data['errors']).lower()
                        if any(keyword in error_msg for keyword in ['sql', 'mongo', 'database']):
                            result['vulnerable'] = True
                            result['details']['injection_type'] = 'error-based'
                            result['details']['payload'] = test['query']
                            result['details']['error'] = error_msg
                            break
                            
            except Exception:
                continue

        return result

    async def test_error_exposure(self, url: str) -> Dict[str, Any]:
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'MEDIUM'
        }

        error_tests = [
            '{ user(id: END_BRACKET_MISSING {',
            '{ missingField { id } }',
            '{ user(id: true) { id } }',
            '{ user { id(invalid: "param") } }',
            'notAValidQuery',
            '{ "not": "valid" }',
        ]

        error_patterns = {
            'stack_trace': ['at ', 'line ', 'stack', 'trace'],
            'system_info': ['version', 'runtime', 'environment'],
            'db_info': ['database', 'query', 'sql', 'mongo'],
            'file_paths': ['/', '\\', '.js', '.py']
        }

        for test in error_tests:
            try:
                response = await self._make_graphql_request(url, test)
                if 'errors' in response:
                    error_msg = str(response['errors']).lower()
                    
                    for error_type, patterns in error_patterns.items():
                        if any(pattern in error_msg for pattern in patterns):
                            result['vulnerable'] = True
                            if error_type not in result['details']:
                                result['details'][error_type] = []
                            result['details'][error_type].append(error_msg[:100])
                            
            except Exception:
                continue

        return result

    async def test_batch_queries(self, url: str) -> Dict[str, Any]:
        result = {
            'vulnerable': False,
            'details': {},
            'severity': 'HIGH'
        }

        batch_queries = [
            [{'query': '{ __typename }'}, {'query': '{ __typename }'}],
            [
                {'query': '{ __schema { types { name } } }'},
                {'query': '{ __type(name: "User") { name } }'}
            ],
            [{'query': '{ __typename }'} for _ in range(10)]
        ]

        for queries in batch_queries:
            try:
                response = await self._make_request('POST', url, json=queries)
                if response.status_code == 200:
                    if isinstance(response.json(), list):
                        result['vulnerable'] = True
                        result['details']['batch_size'] = len(queries)
                        result['details']['supports_batching'] = True
                        break
            except Exception:
                continue

        return result

    def _calculate_risk_score(self, test_results: Dict) -> int:
        severity_scores = {
            'CRITICAL': 4,
            'HIGH': 3,
            'MEDIUM': 2,
            'LOW': 1
        }

        score = 0
        for test, result in test_results.items():
            if isinstance(result, dict) and result.get('vulnerable'):
                score += severity_scores.get(result.get('severity', 'LOW'), 1)

        return score

    def _generate_deep_query(self, depth: int) -> str:
        def _nest(current_depth: int) -> str:
            if current_depth <= 0:
                return "{ id name }"
            return f"{{ nested {_nest(current_depth - 1)} }}"

        return f"query deep {_nest(depth)}"

    async def _make_graphql_request(self, url: str, query: str, headers: Dict = None) -> Dict:
        if headers is None:
            headers = {}
            
        headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

        data = {'query': query}
        response = await self._make_request('POST', url, headers=headers, json=data)
        
        if response.status_code == 200:
            return response.json()
        return None

    async def _make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        try:
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            print(self.formatter.error(f"Request error: {str(e)}"))
            raise