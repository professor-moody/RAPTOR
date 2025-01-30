# raptor/graphql/schema.py

from typing import Dict, List, Any, Set
from output.formatter import OutputFormatter

class SchemaAnalyzer:
    def __init__(self, formatter: OutputFormatter):
        self.formatter = formatter
        self.sensitive_patterns = {
            'authentication': ['login', 'auth', 'token', 'password', 'credential', 'session', 'jwt'],
            'pii': ['ssn', 'social', 'tax', 'passport', 'license', 'dob', 'birthdate', 'address'],
            'financial': ['credit', 'card', 'payment', 'bank', 'account', 'routing', 'invoice', 'billing'],
            'sensitive': ['secret', 'private', 'internal', 'restricted', 'admin', 'key', 'hash', 'salt']
        }
        
        self.dangerous_mutations = [
            'delete', 'remove', 'drop', 'truncate', 'purge',
            'update', 'modify', 'change', 'set',
            'create', 'insert', 'add',
            'execute', 'run', 'perform',
            'grant', 'revoke', 'authorize'
        ]

async def analyze(self, schema: Dict) -> Dict[str, Any]:
    try:
        # Add debugging
        print(self.formatter.info("Analyzing schema structure..."))
        schema_data = schema.get('__schema', {})
        if not schema_data:
            print(self.formatter.error("No schema data found"))
            return {}

        analysis = {
            'types': self._analyze_types(schema_data),  # Changed from schema to schema_data
            'queries': self._analyze_queries(schema_data),
            'mutations': self._analyze_mutations(schema_data),
            'security_concerns': self._analyze_security(schema_data),
            'metrics': self._calculate_metrics(schema_data),
            'attack_surface': self._analyze_attack_surface(schema_data)
        }
        
        # Add debug output
        print(self.formatter.info(f"Found {len(analysis['security_concerns'])} security concerns"))
        print(self.formatter.info(f"Analyzed {analysis['metrics']['total_types']} types"))
        
        analysis['risk_score'] = self._calculate_risk_score(analysis)
        return analysis
        
    except Exception as e:
        print(self.formatter.error(f"Error analyzing schema: {str(e)}"))
        import traceback
        print(traceback.format_exc())
        return {}

    def _analyze_types(self, schema: Dict) -> Dict[str, Any]:
        types_info = {
            'total_count': 0,
            'by_kind': {},
            'custom_types': [],
            'interfaces': [],
            'unions': [],
            'sensitive_types': [],
            'recursive_types': [],
            'type_dependencies': {}
        }

        type_deps = {}
        for type_def in schema.get('__schema', {}).get('types', []):
            if type_def['name'].startswith('__'):
                continue
                
            types_info['total_count'] += 1
            kind = type_def['kind']
            types_info['by_kind'][kind] = types_info['by_kind'].get(kind, 0) + 1

            if self._is_sensitive_type(type_def):
                types_info['sensitive_types'].append(type_def['name'])

            deps = self._get_type_dependencies(type_def)
            if deps:
                type_deps[type_def['name']] = deps
                if type_def['name'] in deps:
                    types_info['recursive_types'].append(type_def['name'])

            if kind == 'OBJECT':
                types_info['custom_types'].append(type_def['name'])
            elif kind == 'INTERFACE':
                types_info['interfaces'].append(type_def['name'])
            elif kind == 'UNION':
                types_info['unions'].append(type_def['name'])

        types_info['type_dependencies'] = type_deps
        return types_info

    def _analyze_attack_surface(self, schema: Dict) -> Dict[str, Any]:
        surface = {
            'entry_points': [],
            'dangerous_mutations': [],
            'exposed_data': [],
            'auth_flows': []
        }

        query_type = schema.get('__schema', {}).get('queryType', {})
        if query_type and 'fields' in query_type:
            surface['entry_points'].extend([
                f['name'] for f in query_type['fields']
            ])

        mutations = self._get_mutations(schema)
        for mutation in mutations:
            if self._is_dangerous_mutation(mutation):
                surface['dangerous_mutations'].append({
                    'name': mutation['name'],
                    'risk': self._assess_mutation_risk(mutation)
                })

        for type_def in schema.get('__schema', {}).get('types', []):
            if self._is_sensitive_type(type_def):
                surface['exposed_data'].append({
                    'type': type_def['name'],
                    'fields': self._get_sensitive_fields(type_def)
                })

        auth_patterns = ['login', 'authenticate', 'token']
        for type_def in schema.get('__schema', {}).get('types', []):
            fields = type_def.get('fields', [])
            for field in fields:
                if any(pattern in field['name'].lower() for pattern in auth_patterns):
                    surface['auth_flows'].append({
                        'type': type_def['name'],
                        'field': field['name']
                    })

        return surface

    def _analyze_security(self, schema: Dict) -> List[Dict]:
        concerns = []
        
        for type_def in schema.get('__schema', {}).get('types', []):
            if type_def['name'].startswith('__'):
                continue
                
            if self._is_sensitive_type(type_def):
                concerns.append({
                    'type': 'sensitive_info_exposure',
                    'location': f"Type: {type_def['name']}",
                    'description': 'Type contains potentially sensitive information',
                    'severity': 'HIGH',
                    'fields': self._get_sensitive_fields(type_def)
                })

        mutations = self._get_mutations(schema)
        for mutation in mutations:
            if self._is_dangerous_mutation(mutation):
                risk = self._assess_mutation_risk(mutation)
                concerns.append({
                    'type': 'dangerous_mutation',
                    'location': f"Mutation: {mutation['name']}",
                    'description': f'Potentially dangerous mutation with {risk} risk',
                    'severity': 'MEDIUM' if risk == 'LOW' else 'HIGH',
                    'details': {
                        'risk_level': risk,
                        'args': [arg['name'] for arg in mutation.get('args', [])]
                    }
                })

        for type_def in schema.get('__schema', {}).get('types', []):
            deps = self._get_type_dependencies(type_def)
            if type_def['name'] in deps:
                concerns.append({
                    'type': 'recursive_type',
                    'location': f"Type: {type_def['name']}",
                    'description': 'Recursive type could lead to DoS',
                    'severity': 'MEDIUM'
                })

        return concerns

    def _is_sensitive_type(self, type_def: Dict) -> bool:
        type_name = type_def['name'].lower()
        fields = type_def.get('fields', [])
        
        for patterns in self.sensitive_patterns.values():
            if any(pattern in type_name for pattern in patterns):
                return True

        for field in fields:
            field_name = field['name'].lower()
            for patterns in self.sensitive_patterns.values():
                if any(pattern in field_name for pattern in patterns):
                    return True
        return False

    def _get_mutations(self, schema: Dict) -> List[Dict]:
        mutation_type = schema.get('__schema', {}).get('mutationType', {})
        if not mutation_type:
            return []
        fields = mutation_type.get('fields', [])
        return fields if fields else []

    def _analyze_queries(self, schema: Dict) -> List[Dict]:
        query_type = schema.get('__schema', {}).get('queryType', {})
        if not query_type:
            return []
        return query_type.get('fields', [])

    def _analyze_mutations(self, schema: Dict) -> List[Dict]:
        return self._get_mutations(schema)

    def _is_dangerous_mutation(self, mutation: Dict) -> bool:
        name = mutation['name'].lower()
        return any(pattern in name for pattern in self.dangerous_mutations)

    def _assess_mutation_risk(self, mutation: Dict) -> str:
        name = mutation['name'].lower()
        args = mutation.get('args', [])
        
        high_risk = ['delete', 'drop', 'truncate', 'grant', 'revoke']
        if any(p in name for p in high_risk):
            return 'HIGH'
            
        for arg in args:
            arg_type = arg.get('type', {}).get('name', '').lower()
            if 'id' in arg_type or 'input' in arg_type:
                return 'MEDIUM'
                
        return 'LOW'

    def _get_sensitive_fields(self, type_def: Dict) -> List[str]:
        sensitive_fields = []
        for field in type_def.get('fields', []):
            field_name = field['name'].lower()
            for patterns in self.sensitive_patterns.values():
                if any(pattern in field_name for pattern in patterns):
                    sensitive_fields.append(field['name'])
        return sensitive_fields

    def _calculate_risk_score(self, analysis: Dict) -> int:
        score = 0
        concerns = analysis.get('security_concerns', [])
        for concern in concerns:
            if concern['severity'] == 'HIGH':
                score += 3
            elif concern['severity'] == 'MEDIUM':
                score += 2
            else:
                score += 1

        score += len(analysis['types']['sensitive_types']) * 2
        surface = analysis.get('attack_surface', {})
        score += len(surface.get('dangerous_mutations', [])) * 2
        score += len(surface.get('exposed_data', [])) * 3
        
        return score

    def _get_type_dependencies(self, type_def: Dict) -> Set[str]:
        deps = set()
        for field in type_def.get('fields', []):
            field_type = field.get('type', {})
            while field_type:
                if 'name' in field_type:
                    deps.add(field_type['name'])
                field_type = field_type.get('ofType')
        return deps
from typing import Dict, List, Any, Set
from output.formatter import OutputFormatter

class SchemaAnalyzer:
    def __init__(self, formatter: OutputFormatter):
        self.formatter = formatter
        self.sensitive_patterns = {
            'authentication': ['login', 'auth', 'token', 'password', 'credential', 'session', 'jwt'],
            'pii': ['ssn', 'social', 'tax', 'passport', 'license', 'dob', 'birthdate', 'address'],
            'financial': ['credit', 'card', 'payment', 'bank', 'account', 'routing', 'invoice', 'billing'],
            'sensitive': ['secret', 'private', 'internal', 'restricted', 'admin', 'key', 'hash', 'salt']
        }
        
        self.dangerous_mutations = [
            'delete', 'remove', 'drop', 'truncate', 'purge',
            'update', 'modify', 'change', 'set',
            'create', 'insert', 'add',
            'execute', 'run', 'perform',
            'grant', 'revoke', 'authorize'
        ]

    async def analyze(self, schema: Dict) -> Dict[str, Any]:
        try:
            print(self.formatter.info("Analyzing schema structure..."))
            schema_data = schema.get('__schema', {})
            if not schema_data:
                print(self.formatter.error("No schema data found"))
                return {}

            analysis = {
                'types': self._analyze_types(schema_data),
                'queries': self._analyze_queries(schema_data),
                'mutations': self._analyze_mutations(schema_data),
                'security_concerns': self._analyze_security(schema_data),
                'metrics': self._calculate_metrics(schema_data),
                'attack_surface': self._analyze_attack_surface(schema_data)
            }
            
            print(self.formatter.info(f"Found {len(analysis['security_concerns'])} security concerns"))
            print(self.formatter.info(f"Analyzed {analysis['metrics']['total_types']} types"))
            
            analysis['risk_score'] = self._calculate_risk_score(analysis)
            return analysis
        except Exception as e:
            print(self.formatter.error(f"Schema analysis failed: {str(e)}"))
            return {}

    def _analyze_types(self, schema_data: Dict) -> List[Dict]:
        types = []
        for type_def in schema_data.get('types', []):
            if self._is_sensitive_type(type_def):
                types.append({
                    'name': type_def['name'],
                    'sensitive': True,
                    'fields': self._analyze_sensitive_fields(type_def)
                })
        return types

    def _analyze_sensitive_fields(self, type_def: Dict) -> List[Dict]:
        sensitive_fields = []
        for field in type_def.get('fields', []):
            field_name = field['name'].lower()
            for category, patterns in self.sensitive_patterns.items():
                if any(pattern in field_name for pattern in patterns):
                    sensitive_fields.append({
                        'name': field['name'],
                        'category': category,
                        'severity': 'HIGH' if category in ['authentication', 'financial'] else 'MEDIUM'
                    })
        return sensitive_fields

    def _analyze_queries(self, schema_data: Dict) -> List[Dict]:
        query_type = schema_data.get('queryType', {})
        if not query_type:
            return []
        
        queries = []
        for field in query_type.get('fields', []):
            complexity = self._calculate_query_complexity(field)
            queries.append({
                'name': field['name'],
                'complexity': complexity,
                'risky': complexity > 5
            })
        return queries

    def _analyze_mutations(self, schema_data: Dict) -> List[Dict]:
        mutations = self._get_mutations(schema_data)
        analyzed_mutations = []
        
        for mutation in mutations:
            risk_level = self._assess_mutation_risk(mutation)
            analyzed_mutations.append({
                'name': mutation['name'],
                'dangerous': self._is_dangerous_mutation(mutation),
                'risk_level': risk_level,
                'args': len(mutation.get('args', []))
            })
        return analyzed_mutations

    def _analyze_security(self, schema_data: Dict) -> List[Dict]:
        concerns = []
        
        # Check introspection
        if self._has_introspection_enabled(schema_data):
            concerns.append({
                'type': 'INTROSPECTION',
                'severity': 'HIGH',
                'description': 'GraphQL introspection is enabled'
            })
            
        # Check authentication
        if not self._has_auth_mechanisms(schema_data):
            concerns.append({
                'type': 'AUTHENTICATION',
                'severity': 'CRITICAL',
                'description': 'No authentication mechanisms detected'
            })
            
        return concerns

    def _calculate_metrics(self, schema_data: Dict) -> Dict:
        return {
            'total_types': len(schema_data.get('types', [])),
            'total_queries': len(self._analyze_queries(schema_data)),
            'total_mutations': len(self._get_mutations(schema_data)),
            'sensitive_types': len([t for t in schema_data.get('types', []) if self._is_sensitive_type(t)])
        }

    def _analyze_attack_surface(self, schema_data: Dict) -> Dict:
        mutations = self._analyze_mutations(schema_data)
        return {
            'dangerous_mutations': len([m for m in mutations if m['dangerous']]),
            'high_risk_operations': len([m for m in mutations if m['risk_level'] == 'HIGH']),
            'exposed_sensitive_fields': self._count_exposed_sensitive_fields(schema_data)
        }

    def _calculate_query_complexity(self, query: Dict) -> int:
        complexity = 1
        args = query.get('args', [])
        complexity += len(args)
        
        # Add complexity for nested types
        type_info = query.get('type', {})
        while type_info:
            if type_info.get('kind') == 'LIST':
                complexity += 2
            type_info = type_info.get('ofType')
        
        return complexity

    def _is_sensitive_type(self, type_def: Dict) -> bool:
        type_name = type_def['name'].lower()
        fields = type_def.get('fields', [])
        
        for patterns in self.sensitive_patterns.values():
            if any(pattern in type_name for pattern in patterns):
                return True

        for field in fields:
            field_name = field['name'].lower()
            for patterns in self.sensitive_patterns.values():
                if any(pattern in field_name for pattern in patterns):
                    return True
        return False

    def _get_mutations(self, schema: Dict) -> List[Dict]:
        mutation_type = schema.get('mutationType', {})
        if not mutation_type:
            return []
        return mutation_type.get('fields', [])

    def _is_dangerous_mutation(self, mutation: Dict) -> bool:
        name = mutation['name'].lower()
        return any(pattern in name for pattern in self.dangerous_mutations)

    def _assess_mutation_risk(self, mutation: Dict) -> str:
        name = mutation['name'].lower()
        args = mutation.get('args', [])
        
        high_risk = ['delete', 'drop', 'truncate', 'grant', 'revoke']
        if any(p in name for p in high_risk):
            return 'HIGH'
            
        medium_risk = ['update', 'modify', 'create']
        if any(p in name for p in medium_risk):
            return 'MEDIUM'
            
        return 'LOW'

    def _has_introspection_enabled(self, schema_data: Dict) -> bool:
        types = schema_data.get('types', [])
        return any(t['name'] == '__Schema' for t in types)

    def _has_auth_mechanisms(self, schema_data: Dict) -> bool:
        auth_types = ['JWT', 'Auth', 'Token', 'Session']
        types = schema_data.get('types', [])
        return any(any(auth in t['name'] for auth in auth_types) for t in types)

    def _count_exposed_sensitive_fields(self, schema_data: Dict) -> int:
        count = 0
        for type_def in schema_data.get('types', []):
            for field in type_def.get('fields', []):
                if self._is_sensitive_field(field['name']):
                    count += 1
        return count

    def _is_sensitive_field(self, field_name: str) -> bool:
        field_name = field_name.lower()
        return any(
            any(pattern in field_name for pattern in patterns)
            for patterns in self.sensitive_patterns.values()
        )

    def _calculate_risk_score(self, analysis: Dict) -> float:
        score = 0.0
        
        # Weight security concerns
        score += len(analysis['security_concerns']) * 2.0
        
        # Weight dangerous mutations
        score += analysis['attack_surface']['dangerous_mutations'] * 1.5
        
        # Weight sensitive data exposure
        score += analysis['attack_surface']['exposed_sensitive_fields'] * 1.0
        
        return min(10.0, score)