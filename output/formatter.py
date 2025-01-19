# raptor/output/formatter.py

from colorama import init, Fore, Style
from typing import Any, Dict, List
import json

# Initialize colorama for cross-platform color support
init()

class OutputFormatter:
    """Handle formatted console output"""
    
    @staticmethod
    def success(message: str) -> str:
        return f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}"
    
    @staticmethod
    def info(message: str) -> str:
        return f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}"
    
    @staticmethod
    def warning(message: str) -> str:
        return f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}"
    
    @staticmethod
    def error(message: str) -> str:
        return f"{Fore.RED}[-] {message}{Style.RESET_ALL}"

    @staticmethod
    def format_workflow(workflow: Dict) -> str:
        """Format workflow information for display"""
        output = []
        output.append("\nWorkflow Analysis:")
        output.append("=" * 50)
        
        for step in workflow.get('steps', []):
            output.append(f"\nStep: {step['name']}")
            output.append(f"Endpoint: {step['endpoint']}")
            output.append(f"Method: {step['method']}")
            output.append("Required Parameters:")
            for param in step.get('required_params', []):
                output.append(f"  - {param}")
        
        return "\n".join(output)

    @staticmethod
    def format_json_output(data: Dict[str, Any], indent: int = 2) -> str:
        """Format JSON data for output"""
        return json.dumps(data, indent=indent, sort_keys=True)

    @staticmethod
    def create_report(
        workflows: List[Dict],
        vulnerabilities: List[Dict],
        statistics: Dict
    ) -> str:
        """Create a formatted report"""
        report = []
        
        # Add banner
        report.append(OutputFormatter._create_banner())
        
        # Add summary
        report.append("\nScan Summary:")
        report.append("-" * 50)
        report.append(f"Total Workflows: {len(workflows)}")
        report.append(f"Vulnerabilities Found: {len(vulnerabilities)}")
        
        # Add workflow details
        if workflows:
            report.append("\nWorkflows Discovered:")
            report.append("-" * 50)
            for workflow in workflows:
                report.append(f"\nWorkflow: {workflow['name']}")
                report.append(f"Steps: {len(workflow['steps'])}")
                report.append("Sequence:")
                for step in workflow['steps']:
                    report.append(f"  → {step['name']}")
        
        # Add vulnerability details
        if vulnerabilities:
            report.append("\nVulnerabilities:")
            report.append("-" * 50)
            for vuln in vulnerabilities:
                report.append(f"\n{Fore.RED}[!] {vuln['title']}{Style.RESET_ALL}")
                report.append(f"Severity: {vuln['severity']}")
                report.append(f"Location: {vuln['location']}")
                report.append(f"Description: {vuln['description']}")
        
        return "\n".join(report)

    @staticmethod
    def _create_banner() -> str:
        """Create the RAPTOR banner"""
        return f"""
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
│{Fore.WHITE}      Rapid API Testing and Operation Reconnaissance v1.0     {Fore.CYAN}│
├──────────────────────────────────────────────────────────────┤
│{Fore.YELLOW}  [*] API Discovery  [*] Auth Detection  [*] Schema Analysis  {Fore.CYAN}│
╰──────────────────────────────────────────────────────────────╯{Style.RESET_ALL}
"""