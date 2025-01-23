import json
import os
from datetime import datetime
from typing import Dict, Any

class ReportHandler:
    """Handles report generation and file output for RAPTOR"""
    
    def __init__(self, base_path: str = "reports"):
        self.base_path = base_path
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create reports directory if it doesn't exist
        if not os.path.exists(base_path):
            os.makedirs(base_path)

    def save_json_report(self, data: Dict[str, Any], target: str) -> str:
        """Save scan results to JSON file"""
        # Create filename based on target and timestamp
        filename = f"{self.base_path}/raptor_scan_{self._sanitize_filename(target)}_{self.timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            return filename
        except Exception as e:
            raise Exception(f"Error saving JSON report: {str(e)}")

    def save_html_report(self, data: Dict[str, Any], target: str) -> str:
        """Generate and save HTML report"""
        filename = f"{self.base_path}/raptor_scan_{self._sanitize_filename(target)}_{self.timestamp}.html"
        
        try:
            html_content = self._generate_html_report(data, target)
            with open(filename, 'w') as f:
                f.write(html_content)
            return filename
        except Exception as e:
            raise Exception(f"Error saving HTML report: {str(e)}")

    def _generate_html_report(self, data: Dict[str, Any], target: str) -> str:
        """Generate HTML report from scan data"""
        # Convert auth findings to HTML
        auth_findings = self._format_auth_findings(data.get('authentication', {}))
        
        # Convert fuzzing findings to HTML
        fuzzing_findings = self._format_fuzzing_findings(data.get('fuzzing', {}))
        
        # Generate the HTML report
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>RAPTOR Scan Report - {target}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                .header {{
                    text-align: center;
                    padding: 20px 0;
                    border-bottom: 2px solid #eee;
                }}
                .section {{
                    margin: 20px 0;
                    padding: 20px;
                    background-color: #fff;
                    border-radius: 5px;
                }}
                .finding {{
                    margin: 10px 0;
                    padding: 10px;
                    border-left: 4px solid #ccc;
                }}
                .high {{
                    border-left-color: #dc3545;
                }}
                .medium {{
                    border-left-color: #ffc107;
                }}
                .low {{
                    border-left-color: #17a2b8;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                }}
                th, td {{
                    padding: 8px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>RAPTOR Scan Report</h1>
                    <p>Target: {target}</p>
                    <p>Scan Time: {data['scan_info']['scan_time']}</p>
                </div>

                <div class="section">
                    <h2>Summary</h2>
                    <table>
                        <tr>
                            <td>Endpoints Discovered</td>
                            <td>{data['discovery']['endpoints_found']}</td>
                        </tr>
                        <tr>
                            <td>Authentication Methods</td>
                            <td>{len(data.get('authentication', {}).get('auth_methods', []))}</td>
                        </tr>
                        <tr>
                            <td>Vulnerabilities Found</td>
                            <td>{len(data.get('fuzzing', {}).get('vulnerabilities', []))}</td>
                        </tr>
                    </table>
                </div>

                <div class="section">
                    <h2>Authentication Findings</h2>
                    {auth_findings}
                </div>

                <div class="section">
                    <h2>Fuzzing Results</h2>
                    {fuzzing_findings}
                </div>

                <div class="section">
                    <h2>Discovered Endpoints</h2>
                    <pre>{json.dumps(data['discovery']['endpoints'], indent=2)}</pre>
                </div>
            </div>
        </body>
        </html>
        """

    def _format_auth_findings(self, auth_data: Dict) -> str:
        """Format authentication findings as HTML"""
        if not auth_data:
            return "<p>No authentication findings</p>"
            
        html = "<table>"
        html += "<tr><th>Method</th><th>Endpoints</th></tr>"
        
        for finding in auth_data.get('auth_findings', []):
            html += f"""
            <tr>
                <td>{finding['method']}</td>
                <td><ul>{"".join(f"<li>{e}</li>" for e in finding['endpoints'])}</ul></td>
            </tr>
            """
            
        html += "</table>"
        return html

    def _format_fuzzing_findings(self, fuzzing_data: Dict) -> str:
        """Format fuzzing findings as HTML"""
        if not fuzzing_data:
            return "<p>No fuzzing findings</p>"
            
        html = ""
        for vuln in fuzzing_data.get('vulnerabilities', []):
            severity_class = vuln['severity'].lower()
            html += f"""
            <div class="finding {severity_class}">
                <h3>[{vuln['severity']}] {vuln['type']}</h3>
                <p><strong>URL:</strong> {vuln['url']}</p>
                <p><strong>Details:</strong></p>
                <pre>{json.dumps(vuln['details'], indent=2)}</pre>
            </div>
            """
            
        return html

    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize the target name for use in filenames"""
        # Remove protocol prefix
        filename = filename.replace('http://', '').replace('https://', '')
        # Replace invalid filename characters
        filename = filename.replace('/', '_').replace(':', '_')
        return filename