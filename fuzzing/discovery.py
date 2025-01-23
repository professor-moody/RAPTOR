import requests
import logging
from typing import Dict, List, Set, Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from .payloads import DEFAULT_WORDLIST, HTTP_METHODS
from output.formatter import OutputFormatter

logger = logging.getLogger(__name__)

class DiscoveryFuzzer:
    def __init__(self, session: requests.Session, base_url: str, formatter: OutputFormatter):
        self.session = session
        self.base_url = base_url.rstrip('/')
        self.formatter = formatter
        self.discovered_endpoints: Set[str] = set()
        
    def discover(self, wordlist: List[str] = None, threads: int = 10) -> Set[str]:
        """
        Discover API endpoints using wordlist-based fuzzing
        
        Args:
            wordlist: List of paths to check
            threads: Number of concurrent threads
            
        Returns:
            Set of discovered endpoints
        """
        try:
            paths_to_check = self._generate_paths(wordlist or DEFAULT_WORDLIST)
            logger.info(f"Starting discovery with {len(paths_to_check)} paths to check")
            
            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = [
                    executor.submit(self._probe_endpoint, urljoin(self.base_url, path))
                    for path in paths_to_check
                ]
                
                for future in as_completed(futures):
                    try:
                        if result := future.result():
                            self.discovered_endpoints.add(result['url'])
                            logger.info(f"Discovered endpoint: {result['url']}")
                            print(self.formatter.success(
                                f"Found endpoint: {result['url']} ({result['status']})"
                            ))
                    except Exception as e:
                        logger.error(f"Error processing future: {str(e)}")
                        
            logger.info(f"Discovery completed. Found {len(self.discovered_endpoints)} endpoints")
            return self.discovered_endpoints
            
        except Exception as e:
            logger.error(f"Error during discovery: {str(e)}")
            raise
    
    def _generate_paths(self, wordlist: List[str]) -> Set[str]:
        """Generate paths to check from wordlist"""
        try:
            paths = set()
            extensions = ['.json', '.xml', '', '/']
            
            for word in wordlist:
                for ext in extensions:
                    paths.add(f"/{word}{ext}")
                    paths.add(f"/api/{word}{ext}")
                    paths.add(f"/v1/{word}{ext}")
                    paths.add(f"/v2/{word}{ext}")
                    
            logger.debug(f"Generated {len(paths)} paths to check")
            return paths
            
        except Exception as e:
            logger.error(f"Error generating paths: {str(e)}")
            raise
        
    def _probe_endpoint(self, url: str) -> Optional[Dict]:
        """Probe a single endpoint for existence"""
        try:
            logger.debug(f"Probing {url}")
            response = self.session.get(url, timeout=10)
            
            if response.status_code != 404:
                result = {
                    'url': url,
                    'status': response.status_code,
                    'content_type': response.headers.get('content-type', '')
                }
                logger.debug(f"Probe result for {url}: {result}")
                return result
                
        except requests.Timeout:
            logger.warning(f"Timeout probing {url}")
        except requests.RequestException as e:
            logger.warning(f"Request error probing {url}: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error probing {url}: {str(e)}")
            
        return None