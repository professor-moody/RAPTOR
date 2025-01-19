# raptor/logic_mapping/data_structures.py

from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional
from datetime import datetime

@dataclass
class EndpointData:
    """Data structure for storing endpoint information"""
    url: str
    method: str = 'GET'
    parameters: Dict[str, List[str]] = field(default_factory=lambda: {
        'path': [],
        'query': [],
        'body': [],
        'header': []
    })
    response_codes: Dict[int, int] = field(default_factory=dict)
    content_types: Set[str] = field(default_factory=set)
    auth_required: bool = False
    response_patterns: List[Dict] = field(default_factory=list)
    headers_seen: Dict[str, Set[str]] = field(default_factory=dict)
    avg_response_time: float = 0.0
    last_seen: datetime = field(default_factory=datetime.now)
    successful_calls: int = 0
    failed_calls: int = 0

@dataclass
class WorkflowStep:
    """Represents a step in a workflow"""
    endpoint: str
    method: str
    required_params: List[str]
    optional_params: List[str]
    expected_status: List[int]
    next_steps: List[str] = field(default_factory=list)

@dataclass
class Workflow:
    """Represents a complete workflow"""
    name: str
    steps: List[WorkflowStep]
    entry_points: List[str]
    exit_points: List[str]
    authentication_required: bool = False

@dataclass
class APIState:
    """Represents the state of an API endpoint"""
    endpoint: str
    current_state: str
    valid_transitions: List[str]
    parameters: Dict[str, str]
    timestamp: datetime = field(default_factory=datetime.now)