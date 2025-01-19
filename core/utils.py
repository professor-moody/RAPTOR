# raptor/core/utils.py

import logging
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin
import requests

def setup_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Set up a logger with the specified name and level"""
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    return logger

def is_valid_url(url: str) -> bool:
    """Check if a URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def make_request(
    session: requests.Session,
    url: str,
    method: str = 'GET',
    **kwargs
) -> Dict[str, Any]:
    """Make a request with error handling and timing"""
    try:
        response = session.request(method, url, **kwargs)
        return {
            'success': True,
            'response': response,
            'status_code': response.status_code,
            'error': None
        }
    except requests.RequestException as e:
        return {
            'success': False,
            'response': None,
            'error': str(e)
        }

def extract_endpoints(content: str) -> List[str]:
    """Extract potential endpoints from content"""
    # Implementation for endpoint extraction
    pass