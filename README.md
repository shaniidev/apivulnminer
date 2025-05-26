# 🎯 APIVulnMiner

**Advanced API Vulnerability Scanner** - Automated endpoint discovery and security testing for modern APIs.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-1.0.0-orange.svg)

![APIVulnMiner Screenshot](https://raw.githubusercontent.com/shaniidev/apivulnminer/refs/heads/master/examples/1.PNG)

## 🚀 Features

### 🔍 **Smart Endpoint Discovery**
- **AI-Powered Pattern Recognition**: Analyzes discovered endpoints to generate likely additional endpoints
- **Comprehensive Wordlists**: Built-in wordlists with 200+ common API endpoints
- **Custom Wordlist Support**: Load your own wordlists for targeted scanning
- **Endpoint Variations**: Automatically generates CRUD operations and nested resource patterns

### 🛡️ **Advanced Vulnerability Testing**
- **OWASP API Top 10**: Complete coverage of OWASP API Security Top 10 vulnerabilities
- **SQL Injection Detection**: Advanced payloads for various database types
- **XSS Testing**: Comprehensive cross-site scripting vulnerability detection
- **Authentication Bypass**: Tests for broken authentication and authorization
- **IDOR Detection**: Insecure Direct Object Reference vulnerability testing
- **Rate Limiting**: Identifies missing rate limiting controls
- **Information Disclosure**: Detects sensitive data exposure

### 📊 **Beautiful Reporting**
- **Multiple Formats**: JSON, HTML, CSV, and TXT reports
- **Professional HTML Reports**: Beautiful, responsive reports with charts and statistics
- **Detailed Vulnerability Information**: Complete CVSS scoring and remediation guidance
- **Executive Summaries**: High-level overviews for management

### ⚡ **High Performance**
- **Async HTTP Requests**: Lightning-fast concurrent scanning
- **Smart Rate Limiting**: Configurable delays to avoid detection
- **Connection Pooling**: Efficient resource utilization
- **Progress Tracking**: Real-time progress bars and statistics

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Install (Linux/Mac - Recommended)
```bash
# Clone the repository
git clone https://github.com/shaniidev/apivulnminer.git
cd apivulnminer

# Run the installation script
chmod +x install.sh
sudo ./install.sh

# Now you can use apivulnminer from anywhere!
apivulnminer --help
```

### Windows Installation
```cmd
# Clone the repository
git clone https://github.com/shaniidev/apivulnminer.git
cd apivulnminer

# Install dependencies
pip install -r requirements.txt

# Run directly
python apivulnminer.py --help

# Or install as system command (optional)
pip install -e .
apivulnminer --help
```

### Manual Install (All Platforms)
```bash
# Clone the repository
git clone https://github.com/shaniidev/apivulnminer.git
cd apivulnminer

# Install dependencies
pip install -r requirements.txt

# Option 1: Run directly
python apivulnminer.py -u https://api.example.com

# Option 2: Install as system command
pip install -e .
apivulnminer -u https://api.example.com

# Option 3: Install for current user only
pip install --user -e .
apivulnminer -u https://api.example.com
```

### Docker Installation (Optional)
```bash
# Build Docker image
docker build -t apivulnminer .

# Run with Docker
docker run -it apivulnminer python main.py --help
```

## 🎯 Usage

### Basic Scan
```bash
# If installed as system command
apivulnminer -u https://api.example.com

# Or run directly (Windows/any platform)
python apivulnminer.py -u https://api.example.com
```

### Advanced Scan with Custom Options
```bash
# If installed as system command
apivulnminer \
  -u https://api.example.com \
  -w custom_wordlist.txt \
  -t 50 \
  -d 0.1 \
  --timeout 15 \
  -o html \
  --output-file scan_report.html \
  --verbose

# Or run directly (Windows/any platform)
python apivulnminer.py \
  -u https://api.example.com \
  -w custom_wordlist.txt \
  -t 50 \
  -d 0.1 \
  --timeout 15 \
  -o html \
  --output-file scan_report.html \
  --verbose
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-u, --url` | Target URL to scan | **Required** |
| `-w, --wordlist` | Custom wordlist file | Built-in wordlist |
| `-t, --threads` | Number of concurrent threads | 20 |
| `-d, --delay` | Delay between requests (seconds) | 0.05 |
| `--timeout` | Request timeout (seconds) | 10 |
| `-H, --headers` | Custom headers (JSON format) | None |
| `--auth-token` | Authorization token | None |
| `--proxy` | Proxy URL | None |
| `-o, --output` | Output format (json/html/csv/txt) | json |
| `--output-file` | Output file path | Auto-generated |
| `-v, --verbose` | Verbose logging | False |

### Examples

#### 1. Basic API Scan
```bash
# Installed command
apivulnminer -u https://jsonplaceholder.typicode.com

# Direct execution
python apivulnminer.py -u https://jsonplaceholder.typicode.com
```

#### 2. Authenticated Scan with Custom Headers
```bash
# Installed command
apivulnminer \
  -u https://api.example.com \
  --auth-token "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H '{"X-API-Key": "your-api-key"}'

# Direct execution
python apivulnminer.py \
  -u https://api.example.com \
  --auth-token "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H '{"X-API-Key": "your-api-key"}'
```

#### 3. Stealth Scan with Proxy
```bash
# Installed command
apivulnminer \
  -u https://api.target.com \
  --proxy http://127.0.0.1:8080 \
  -d 1.0 \
  -t 5

# Direct execution
python apivulnminer.py \
  -u https://api.target.com \
  --proxy http://127.0.0.1:8080 \
  -d 1.0 \
  -t 5
```

#### 4. Comprehensive Scan with Custom Wordlist
```bash
# Installed command
apivulnminer \
  -u https://api.example.com \
  -w /path/to/api_endpoints.txt \
  -t 30 \
  -o html \
  --output-file detailed_report.html \
  --verbose

# Direct execution
python apivulnminer.py \
  -u https://api.example.com \
  -w /path/to/api_endpoints.txt \
  -t 30 \
  -o html \
  --output-file detailed_report.html \
  --verbose
```

## 📋 Sample Output

### Console Output
```
🎯 APIVulnMiner - Advanced API Vulnerability Scanner
Target: https://api.example.com | Threads: 20 | Wordlist: 250 endpoints

[✓] Discovered: GET /api/users [200]
[✓] Discovered: POST /api/users [201]
[!] Vulnerability: SQL Injection in /api/users?id=1 [HIGH]
[✓] Discovered: GET /api/products [200]
[!] Vulnerability: IDOR in /api/users/profile [MEDIUM]

Scan Complete! Found 15 endpoints, 3 vulnerabilities
Report saved: scan_report_20231201_143022.html
```

### HTML Report Preview
The HTML reports include:
- Executive summary with statistics
- Vulnerability details with CVSS scores
- Discovered endpoints list
- Remediation recommendations
- Beautiful charts and visualizations

## 🖥️ Cross-Platform Compatibility

APIVulnMiner works on all major operating systems:

### Linux/Mac (Recommended)
- Use the automated install script for system-wide installation
- Run `sudo ./install.sh` for best experience
- Command available globally: `apivulnminer`

### Windows
- Install dependencies: `pip install -r requirements.txt`
- Run directly: `python apivulnminer.py -u https://api.example.com`
- Optional: Install globally with `pip install -e .`

### Any Platform (Manual)
- Clone repository and install dependencies
- Run with: `python apivulnminer.py [options]`
- Works with Python 3.8+ on any OS

## 🔧 Configuration

### Custom Wordlists
Create custom wordlists for specific targets:

```text
# api_endpoints.txt
api/v1/users
api/v1/products
api/v1/orders
admin/users
admin/settings
internal/debug
```

### Environment Variables
```bash
export APIVULNMINER_PROXY="http://127.0.0.1:8080"
export APIVULNMINER_DELAY="0.1"
export APIVULNMINER_THREADS="25"
```

## 🛡️ Vulnerability Detection

### Supported Vulnerability Types

| Vulnerability | OWASP API | Severity | Detection Method |
|---------------|-----------|----------|------------------|
| SQL Injection | API1 | High | Payload-based testing |
| XSS | API1 | Medium | Reflection analysis |
| Broken Authentication | API2 | Critical | Auth bypass testing |
| Excessive Data Exposure | API3 | Medium | Response analysis |
| Rate Limiting | API4 | Low | Request flooding |
| BOLA/IDOR | API5 | High | Object reference testing |
| Mass Assignment | API6 | Medium | Parameter pollution |
| Security Misconfiguration | API7 | Medium | Header analysis |
| Injection Flaws | API8 | High | Multiple payload types |
| Improper Asset Management | API9 | Low | Version detection |
| Insufficient Logging | API10 | Low | Error analysis |

## 📊 Report Formats

### JSON Report
```json
{
  "scan_info": {
    "target_url": "https://api.example.com",
    "timestamp": "2023-12-01T14:30:22",
    "scanner_version": "1.0.0"
  },
  "summary": {
    "total_endpoints_tested": 250,
    "endpoints_found": 15,
    "total_vulnerabilities": 3,
    "high_severity_count": 1
  },
  "vulnerabilities": [...]
}
```

### HTML Report Features
- 📊 Interactive charts and graphs
- 🎨 Professional styling with dark/light themes
- 📱 Mobile-responsive design
- 🔍 Searchable vulnerability database
- 📋 Executive summary for management
- 🛠️ Technical details for developers

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone repository
git clone https://github.com/yourusername/apivulnminer.git
cd apivulnminer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**For Educational and Authorized Testing Only**

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security research and education
- ✅ Bug bounty programs
- ✅ Internal security assessments

**Do NOT use this tool for:**
- ❌ Unauthorized testing of systems you don't own
- ❌ Malicious activities
- ❌ Violating terms of service
- ❌ Illegal activities

The authors are not responsible for misuse of this tool. Always ensure you have proper authorization before testing any systems.

## 🙏 Acknowledgments

- OWASP API Security Project
- The cybersecurity community
- All contributors and testers

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/shaniidev/apivulnminer/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/shaniidev/apivulnminer/discussions)
- 💼 **LinkedIn**: [linkedin.com/in/shaniii](https://linkedin.com/in/shaniii)
- 🐙 **GitHub**: [github.com/shaniidev](https://github.com/shaniidev)

---

**Made with ❤️ for the ethical hacking community**

## 👨‍💻 Author

**Shani** - Cybersecurity Enthusiast & Ethical Hacker
- 💼 LinkedIn: [linkedin.com/in/shaniii](https://linkedin.com/in/shaniii)
- 🐙 GitHub: [github.com/shaniidev](https://github.com/shaniidev)
- 🎯 Specializing in API Security, Penetration Testing & Vulnerability Research 