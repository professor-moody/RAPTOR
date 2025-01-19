# RAPTOR

<p align="center">
  <img src="banner.png" alt="RAPTOR Banner">
</p>

**R**apid **A**PI **T**esting and **O**peration **R**econnaissance

RAPTOR is an advanced API discovery and analysis tool designed for security researchers and penetration testers. It automates the process of API endpoint discovery, authentication analysis, and schema detection while providing detailed insights into API structure and behavior.

## Features

- 🔍 **API Discovery**
  - Automated endpoint enumeration
  - Documentation parsing (Swagger/OpenAPI)
  - Parameter detection
  - GraphQL schema analysis

- 🔒 **Authentication Analysis**
  - Multiple auth method detection
  - OAuth/OpenID workflow discovery
  - JWT token analysis
  - API key detection

- 📊 **Comprehensive Reporting**
  - Detailed JSON output
  - Color-coded terminal feedback
  - Progress tracking
  - Structured findings

## Installation

### Prerequisites
- Python 3.8+
- pip

### Quick Install
```bash
# Clone the repository
git clone https://github.com/yourusername/raptor.git

# Navigate to the directory
cd raptor

# Create a virtual environment (recommended)
python -m venv venv

# Activate the virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python raptor.py https://api.example.com
```

### Advanced Options
```bash
# With custom wordlist
python raptor.py -w wordlist.txt https://api.example.com

# Save results to file
python raptor.py -o results.json https://api.example.com

# Adjust thread count
python raptor.py -t 20 https://api.example.com

# Verbose output
python raptor.py -v https://api.example.com
```

### Command Line Arguments
```
usage: raptor.py [-h] [-w WORDLIST] [-o OUTPUT] [-t THREADS] [--timeout TIMEOUT] [-v] url

positional arguments:
  url                   Base URL to scan

optional arguments:
  -h, --help           show this help message and exit
  -w, --wordlist       Custom wordlist file
  -o, --output         Output file for results (JSON)
  -t, --threads        Number of concurrent threads (default: 10)
  --timeout            Request timeout in seconds (default: 30)
  -v, --verbose        Enable verbose output
```

## Example Output
```json
{
  "base_url": "https://api.example.com",
  "authentication": {
    "detected_methods": ["Bearer Token", "API Key"],
    "protected_endpoints": {
      "/api/v1/users": ["Bearer Token"],
      "/api/v1/admin": ["API Key"]
    }
  },
  "endpoints": {
    "total_discovered": 15,
    "listing": ["/api/v1/users", "/api/v1/products", ...]
  }
}
```

## Safe Usage Guidelines

- Always ensure you have permission to test the target API
- Use appropriate thread counts to avoid overwhelming the target
- Respect rate limiting and robots.txt
- Consider the impact of automated testing on production systems

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## Todo

- [ ] Business logic mapping
- [ ] Enhanced authentication testing
- [ ] Custom plugin system
- [ ] API behavior monitoring
- [ ] Integration with other security tools

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Designed to be a project for learning python.
- Thanks to AI for guiding me and holding my hand. (let's be real, this is the future)
- Built with Python and love for the security community

## Security

Please report security issues responsibly by emailing professor.moody@pm.me

## Support

For support, questions, or feedback:
- Open an issue
