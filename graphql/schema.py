# raptor/graphql/schema.py

from typing import Dict, List, Any
from output.formatter import OutputFormatter

class SchemaAnalyzer:
    """GraphQL Schema Analysis"""

    def __init__(self, formatter: OutputFormatter):
        self.formatter = formatter
        
        # Patterns for security analysis
        self.sensitive_patterns = {
            'authentication': ['login', 'auth', 'token', 'password', 'credential'],
            'pii': ['ssn', 'social', 'tax', 'passport', 'license'],
            'financial': ['credit', 'card', 'payment', 'bank', 'account'],
            'sensitive': ['secret', 'private', 'internal', 'restricted']
        }

    async def analyze(self, schema: Dict) -> Dict[str, Any]:
        """Analyze GraphQL schema for security and structure"""
        analysis = {
            'types': self._analyze_types(schema),
            'queries': self._analyze_queries(schema),
            'mutations': self._analyze_mutations(schema),
            'security_concerns': self._analyze_security(schema),
            'metrics': self._calculate_metrics(schema)
        }
        
        return analysis

    def _analyze_types(self, schema: Dict) -> Dict[str, Any]:
        """Analyze GraphQL types"""
        types_info = {
            'total_count': 0,
            'by_kind': {},
            'custom_types': [],
            'interfaces': [],
            'unions': [],
            'sensitive_types': []
        }

        for type_def in schema.get('__schema', {}).get('types', []):
            if type_def['name'].startswith('__'):  # Skip built-in types
                continue
                
            types_info['total_count'] += 1
            kind = type_def['kind']
            types_info['by_kind'][kind] = types_info['by_kind'].get(kind, 0) + 1

            if self._is_sensitive_type(type_def):
                types_info['sensitive_types'].append(type_def['name'])

            if kind == 'OBJECT':
                types_info['custom_types'].append(type_def['name'])
            elif kind == 'INTERFACE':
                types_info['interfaces'].append(type_def['name'])
            elif kind == 'UNION':
                types_info['unions'].append(type_def['name'])

        return types_info

    def _is_sensitive_type(self, type_def: Dict) -> bool:
        """Check if a type contains sensitive information"""
        type_name = type_def['name'].lower()
        fields = type_def.get('fields', [])
        
        # Check type name
        for category, patterns in self.sensitive_patterns.items():
            if any(pattern in type_name for pattern in patterns):
                return True

        # Check field names
        for field in fields:
            field_name = field['name'].lower()
            for category, patterns in self.sensitive_patterns.items():
                if any(pattern in field_name for pattern in patterns):
                    return True

        return False

    def _analyze_security(self, schema: Dict) -> List[Dict]:
        """Analyze schema for security concerns"""
        concerns = []
        
        # Check for sensitive types exposure
        sensitive_types = []
        for type_def in schema.get('__schema', {}).get('types', []):
            if type_def['name'].startswith('__'):
                continue
                
            if self._is_sensitive_type(type_def):
                sensitive_types.append(type_def['name'])
                concerns.append({
                    'type': 'sensitive_info_exposure',
                    'location': f"Type: {type_def['name']}",
                    'description': 'Type contains potentially sensitive information',
                    'severity': 'HIGH'
                })

        # Check for dangerous mutations
        mutations = self._get_mutations(schema)
        for mutation in mutations:
            if self._is_dangerous_mutation(mutation):
                concerns.append({
                    'type': 'dangerous_mutation',
                    'location': f"Mutation: {mutation['name']}",
                    'description': 'Potentially dangerous mutation detected',
                    'severity': 'MEDIUM'
                })

        return concerns

    def _get_mutations(self, schema: Dict) -> List[Dict]:
        """Get all mutations from schema"""
        mutation_type = schema.get('__schema', {}).get('mutationType', {})
        if not mutation_type:
            return []
            
        fields = mutation_type.get('fields', [])
        return fields if fields else []

    def _is_dangerous_mutation(self, mutation: Dict) -> bool:
        """Check if a mutation is potentially dangerous"""
        dangerous_patterns = [
            'delete', 'remove', 'drop', 'truncate', 'purge',
            'update', 'modify', 'change', 'set',
            'create', 'insert', 'add',
            'execute', 'run', 'perform'
        ]
        
        mutation_name = mutation['name'].lower()
        return any(pattern in mutation_name for pattern in dangerous_patterns)

    def _calculate_metrics(self, schema: Dict) -> Dict[str, Any]:
        """Calculate schema metrics"""
        return {
            'total_types': len(schema.get('__schema', {}).get('types', [])),
            'queries': len(self._get_queries(schema)),
            'mutations': len(self._get_mutations(schema)),
            'interfaces': len([t for t in schema.get('__schema', {}).get('types', [])
                             if t.get('kind') == 'INTERFACE']),
            'complexity_score': self._calculate_complexity(schema)
        }

    def _calculate_complexity(self, schema: Dict) -> int:
        """Calculate schema complexity score"""
        score = 0
        
        for type_def in schema.get('__schema', {}).get('types', []):
            if type_def['name'].startswith('__'):
                continue
                
            # Add points for each field
            fields = type_def.get('fields', [])
            score += len(fields)
            
            # Add points for nested types
            for field in fields:
                score += self._get_field_complexity(field)

        return score

    def _get_field_complexity(self, field: Dict, depth: int = 0) -> int:
        """Calculate field complexity"""
        if depth > 5:  # Prevent infinite recursion
            return 0
            
        score = 1
        
        # Add points for arguments
        score += len(field.get('args', []))
        
        # Add points for nested types
        field_type = field.get('type', {})
        if field_type.get('kind') == 'OBJECT':
            score += 2
        elif field_type.get('kind') == 'LIST':
            score += 3
            if 'ofType' in field_type:
                score += self._get_field_complexity(
                    {'type': field_type['ofType']}, 
                    depth + 1
                )

        return score