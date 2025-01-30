#!/usr/bin/env python3

import requests
import json
import yaml
import logging
import sys
import argparse
from typing import Dict, Set, Optional, Any
from datetime import datetime
import colorama
from colorama import Fore, Style
from urllib3.exceptions import InsecureRequestWarning

# Local imports
from output.formatter import OutputFormatter
from output.report_handler import ReportHandler  # Add this line
from fuzzing import FuzzingAnalyzer, DiscoveryFuzzer
from auth import AuthDetector
from graphql import GraphQLAnalyzer

# Setup logging
logger = logging.getLogger(__name__)

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def print_banner():
    """Print the RAPTOR tool banner with colors"""
    banner = f"""
{Fore.CYAN}╭──────────────────────────────────────────────────────────────╮
│{Style.RESET_ALL}                                                              {Fore.CYAN}│
│   {Fore.RED}██████╗   █████╗  ██████╗ ████████╗ █████╗ ██████╗       {Fore.CYAN}│
│   {Fore.RED}██╔══██╗ ██╔══██╗ ██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗      {Fore.CYAN}│
│   {Fore.RED}██████╔╝ ███████║ ██████╔╝   ██║   ██║  ██║██████╔╝      {Fore.CYAN}│
│   {Fore.RED}██╔══██╗ ██╔══██║ ██╔═══╝    ██║   ██║  ██║██╔══██╗      {Fore.CYAN}│
│   {Fore.RED}██║  ██║ ██║  ██║ ██║        ██║   ╚█████╔╝██║  ██║      {Fore.CYAN}│
│   {Fore.RED}╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚═╝        ╚═╝    ╚════╝ ╚═╝  ╚═╝      {Fore.CYAN}│
│{Style.RESET_ALL}                                                              {Fore.CYAN}│
├──────────────────────────────────────────────────────────────┤
│{Fore.WHITE}      Rapid API Testing and Operation Reconnaissance v1.5     {Fore.CYAN}│
├──────────────────────────────────────────────────────────────┤
│{Fore.YELLOW}  [*] API Discovery  [*] Auth Detection  [*] Schema Analysis  {Fore.CYAN}│
╰──────────────────────────────────────────────────────────────╯{Style.RESET_ALL}
"""
    print(banner)

class RAPTOR:
    """RAPTOR - Rapid API Testing and Operation Reconnaissance"""
    
    def __init__(self, base_url: str, wordlist_path: Optional[str] = None, options: Dict = None):
        logger.info("Initializing RAPTOR")
        try:
            # Initialize basic attributes first
            self.base_url = base_url.rstrip('/')
            self.options = options or {}
            self.discovered_endpoints: Set[str] = set()
            self.formatter = OutputFormatter()
            
            # Setup session after options are initialized
            self.session = self._setup_session()
            
            # Initialize components
            logger.debug("Initializing RAPTOR components")
            self.discovery_fuzzer = DiscoveryFuzzer(
                session=self.session,
                base_url=self.base_url,
                formatter=self.formatter
            )
            
            self.auth_detector = AuthDetector(
                session=self.session,
                formatter=self.formatter
            )
            
            self.fuzzing_analyzer = FuzzingAnalyzer(
                session=self.session,
                formatter=self.formatter
            )
            
        except Exception as e:
            logger.error(f"Error initializing RAPTOR: {str(e)}")
            raise

    def _setup_session(self) -> requests.Session:
        """Set up requests session with proper configuration"""
        try:
            session = requests.Session()
            
            # Configure connection pooling and retries
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=10,
                pool_maxsize=10,
                max_retries=3,
                pool_block=False
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            
            # Set default headers and timeouts
            session.headers.update({
                'User-Agent': 'RAPTOR/1.0',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            })
            
            # Set longer timeouts
            session.timeout = (10, 30)  # (connect timeout, read timeout)
            
            # Verify SSL based on options
            session.verify = not self.options.get('no_ssl_verify', False)
            
            return session
            
        except Exception as e:
            logger.error(f"Error setting up session: {str(e)}")
            raise

    def scan(self) -> Dict[str, Any]:
        try:
            results = {
                'scan_info': {
                'base_url': self.base_url,
                'scan_time': datetime.now().isoformat(),
                'options': self.options
            }
        }
        
        # Phase 1: Endpoint Discovery
            self.discovered_endpoints = self.discovery_fuzzer.discover(
                threads=self.options.get('threads', 10)
        )
        
            results['discovery'] = {
                'endpoints_found': len(self.discovered_endpoints),
                'endpoints': sorted(list(self.discovered_endpoints))
        }
        
        # Phase 2: GraphQL Analysis
            logger.info("Starting GraphQL analysis phase")
            print(self.formatter.info("\nStarting GraphQL analysis..."))
            graphql_analyzer = GraphQLAnalyzer(self.session, self.base_url, self.formatter)
            graphql_results = graphql_analyzer.analyze()
        
            if graphql_results.get('endpoints'):
                results['graphql'] = graphql_results
            # Add GraphQL endpoints to discovered endpoints
                self.discovered_endpoints.update(graphql_results['endpoints'].keys())
            
        # Continue with auth and fuzzing phases...
            
            if self.discovered_endpoints:
                # Phase 2: Authentication Detection
                if not self.options.get('no_auth'):
                    logger.info("Starting authentication detection phase")
                    print(self.formatter.info("\nStarting authentication analysis..."))
                    
                    auth_results = self.auth_detector.detect_auth_methods(
                        base_url=self.base_url,
                        endpoints=self.discovered_endpoints,
                        threads=self.options.get('threads', 10)
                    )
                    results['authentication'] = auth_results
                
                # Phase 3: Fuzzing Analysis
                if not self.options.get('no_fuzzing'):
                    logger.info("Starting fuzzing analysis phase")
                    print(self.formatter.info("\nStarting fuzzing analysis..."))
                    
                    fuzzing_results = self.fuzzing_analyzer.fuzz_endpoints_concurrent(
                        urls=list(self.discovered_endpoints),
                        threads=self.options.get('threads', 5)
                    )
                    results['fuzzing'] = fuzzing_results
            
            logger.info("Scan completed successfully")
            return results
            
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            raise
        except Exception as e:
            logger.error(f"Error during scan: {str(e)}")
            raise

def main():
    parser = argparse.ArgumentParser(
        description='RAPTOR - Rapid API Testing and Operation Reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument('url', help='Base URL to scan')
    
    # Optional arguments
    parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    parser.add_argument('-o', '--output-dir', default='reports',
                      help='Output directory for reports (default: reports)')
    parser.add_argument('--format', choices=['json', 'html', 'both'], default='both',
                      help='Report format (default: both)')
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of threads for concurrent operations (default: 10)')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Timeout for requests in seconds (default: 30)')
    
    # Logging and output options
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Minimize output, only show important messages')
    
    args = parser.parse_args()

    # Configure logging
    log_level = logging.WARNING
    if args.verbose:
        log_level = logging.INFO
    elif args.quiet:
        log_level = logging.ERROR
        
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    try:
        # Initialize report handler
        report_handler = ReportHandler(args.output_dir)
        
        # Initialize RAPTOR
        raptor = RAPTOR(args.url, args.wordlist, {
            'threads': args.threads,
            'timeout': args.timeout,
            'verbose': args.verbose,
            'quiet': args.quiet
        })
        
        # Start scan
        if not args.quiet:
            print_banner()
            print(f"[*] Starting scan of {args.url}")
            
        results = raptor.scan()
        
        # Save reports
        if args.format in ['json', 'both']:
            json_file = report_handler.save_json_report(results, args.url)
            if not args.quiet:
                print(f"[+] JSON report saved to: {json_file}")
                
        if args.format in ['html', 'both']:
            html_file = report_handler.save_html_report(results, args.url)
            if not args.quiet:
                print(f"[+] HTML report saved to: {html_file}")
        
        # Print brief summary unless quiet mode
        if not args.quiet:
            print("\nScan Summary:")
            print(f"Endpoints discovered: {len(results['discovery']['endpoints'])}")
            if 'authentication' in results:
                print(f"Auth methods found: {len(results['authentication']['auth_methods'])}")
            if 'fuzzing' in results:
                vulns = results['fuzzing']['vulnerabilities']
                print(f"Vulnerabilities found: {len(vulns)}")
                
                # Print high-severity findings
                high_sev_vulns = [v for v in vulns if v['severity'] == 'HIGH']
                if high_sev_vulns:
                    print("\nHigh Severity Findings:")
                    for vuln in high_sev_vulns:
                        print(f"- {vuln['type']} in {vuln['url']}")

    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] An error occurred: {str(e)}")
        if args.verbose:
            logger.exception("Detailed error information:")
        sys.exit(1)

if __name__ == '__main__':
    main()