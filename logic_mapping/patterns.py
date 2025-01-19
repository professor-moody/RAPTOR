# raptor/logic_mapping/patterns.py

from typing import Dict, List, Optional, Set
import re
from .data_structures import Workflow, WorkflowStep

class PatternMatcher:
    """Pattern matching for API workflows"""
    
    def __init__(self):
        self.patterns = self._load_default_patterns()
        
    def _load_default_patterns(self) -> Dict[str, Dict]:
        """Load default workflow patterns"""
        return {
            'authentication': {
                'endpoints': [
                    r'/login',
                    r'/auth',
                    r'/oauth',
                    r'/token'
                ],
                'parameters': [
                    'username',
                    'password',
                    'token',
                    'refresh_token'
                ],
                'sequence': ['login', 'token', 'refresh']
            },
            'e_commerce': {
                'endpoints': [
                    r'/products?',
                    r'/cart',
                    r'/checkout',
                    r'/orders?'
                ],
                'parameters': [
                    'product_id',
                    'quantity',
                    'cart_id',
                    'order_id'
                ],
                'sequence': ['browse', 'cart', 'checkout', 'order']
            },
            # Add more patterns as needed
        }
    
    def match_workflow(self, endpoints: List[str]) -> List[Dict]:
        """Match endpoints against known workflow patterns"""
        matches = []
        
        for pattern_name, pattern in self.patterns.items():
            matched_endpoints = []
            for endpoint in endpoints:
                if any(re.search(p, endpoint) for p in pattern['endpoints']):
                    matched_endpoints.append(endpoint)
            
            if matched_endpoints:
                matches.append({
                    'pattern': pattern_name,
                    'matched_endpoints': matched_endpoints
                })
        
        return matches

    def detect_sequence(self, requests: List[Dict]) -> Optional[str]:
        """Detect workflow sequence from a series of requests"""
        for pattern_name, pattern in self.patterns.items():
            if self._matches_sequence(requests, pattern['sequence']):
                return pattern_name
        return None

    def _matches_sequence(self, requests: List[Dict], sequence: List[str]) -> bool:
        """Check if requests match a workflow sequence"""
        seq_idx = 0
        for request in requests:
            current_step = sequence[seq_idx]
            if self._request_matches_step(request, current_step):
                seq_idx += 1
                if seq_idx == len(sequence):
                    return True
        return False

    def _request_matches_step(self, request: Dict, step: str) -> bool:
        """Check if a request matches a workflow step"""
        endpoint = request.get('url', '')
        method = request.get('method', '')
        
        # Define step patterns
        step_patterns = {
            'login': (r'/login|/auth', 'POST'),
            'token': (r'/token', 'POST'),
            'browse': (r'/products?', 'GET'),
            'cart': (r'/cart', 'POST'),
            'checkout': (r'/checkout', 'POST'),
            'order': (r'/orders?', 'POST')
        }
        
        if step in step_patterns:
            pattern, expected_method = step_patterns[step]
            return (re.search(pattern, endpoint) and 
                   (method == expected_method or not expected_method))
        
        return False