# Knox Suite

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Release-v1.0.0-blue" alt="Release">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey" alt="Platform">
</p>

<p align="center">
  <strong>Lightweight Automated Penetration Testing Suite</strong>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#modules">Modules</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#output">Output</a> •
  <a href="#contributing">Contributing</a>
</p>

---

A modular, single-binary CLI suite for automated penetration testing. Give it a domain, and it runs reconnaissance, vulnerability scanning, and AI-powered analysis using Anthropic Claude.

## Features

- 🎯 **Single Target Input** - Just provide a domain (e.g., `example.com`)
- 🔍 **Modular Reconnaissance** - Subdomain enumeration, DNS records, SSL info, live host detection, port scanning, technology detection, directory enumeration, URL discovery
- 🛡️ **Vulnerability Scanning** - Nuclei templates, Nikto, SSL scanning, directory/file exposure checks
- 🤖 **AI Analysis** - Anthropic Claude provides executive summary, risk prioritization, attack paths, and remediation
- 📄 **Multiple Report Formats** - Markdown, HTML, JSON, and raw data files
- ⚡ **Fast & Lightweight** - Single Go binary (~10MB), no database, no web UI, no Docker required
- 🔧 **Parallel Execution** - Runs multiple tools concurrently for speed
- 📦 **Zero Runtime Dependencies** - Uses system-installed security tools
- 🏗️ **Modular Architecture** - Each module can be used independently

## Installation

### Pre-built Binaries (Recommended)

Download the latest release for your platform:

| Platform | Download |
|----------|----------|
| Linux (amd64) | [knox-linux-amd64.tar.gz](https://github.com/yourusername/knox-suite/releases/latest/download/knox-linux-amd64.tar.gz) |
| macOS (Intel) | [knox-darwin-amd64.tar.gz](https://github.com/yourusername/knox-suite/releases/latest/download/knox-darwin-amd64.tar.gz) |
| macOS (Apple Silicon) | [knox-darwin-arm64.tar.gz](https://github.com/yourusername/knox-suite/releases/latest/download/knox-darwin-arm64.tar.gz) |
| Windows (amd64) | [knox-windows-amd64.zip](https://github.com/yourusername/knox-suite/releases/latest/download/knox-windows-amd64.zip) |

```bash
# Linux/macOS example
tar -xzf knox-linux-amd64.tar.gz
sudo mv knox /usr/local/bin/
```

### Build from Source

```bash
# Requirements: Go 1.23+
git clone https://github.com/yourusername/knox-suite.git
cd knox-suite
make build
# Binary at ./build/knox
```

### Install Security Tools

The suite uses these external security tools (install via your package manager):

```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y nmap nuclei subfinder httpx dnsx sslscan whatweb nikto dirsearch sqlmap ffuf katana gau waybackurls amass

# macOS (Homebrew)
brew install nmap nuclei subfinder httpx dnsx sslscan whatweb nikto dirsearch sqlmap ffuf katana gau waybackurls amass

# Arch Linux
sudo pacman -S nmap nuclei subfinder httpx dnsx sslscan whatweb nikto dirsearch sqlmap ffuf katana gau waybackurls amass

# Or use Go install for some tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

### Docker

```bash
# Build
docker build -t knox-suite .

# Run
docker run --rm -it \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd)/reports:/reports \
  knox-suite scan example.com

# Or use docker-compose
docker compose run --rm knox scan example.com
```

## Quick Start

```bash
# Set your Anthropic API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Run full penetration test
knox scan example.com

# Run only reconnaissance
knox recon example.com

# Run specific module
knox module subdomain example.com
knox module portscan example.com
knox module vulnscan example.com

# Custom output directory
knox scan example.com --output ./my-reports

# Disable AI analysis (tools only)
knox scan example.com --no-ai

# Verbose output
knox scan example.com --verbose
```

## Usage

### Commands

| Command | Description |
|---------|-------------|
| `scan` | Full automated penetration test (recon + vuln scan + AI) |
| `recon` | Reconnaissance only |
| `module` | Run individual module (subdomain, dns, http, portscan, tech, dir, url, vuln) |
| `report` | Generate report from previous scan data |
| `version` | Show version information |
| `completion` | Generate shell completion scripts |

### Global Options

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--target` | `-t` | Target domain | (required) |
| `--output` | `-o` | Output directory | `./reports` |
| `--config` | `-c` | Config file path | - |
| `--verbose` | `-v` | Enable verbose logging | `false` |
| `--anthropic-key` | | Anthropic API key | `ANTHROPIC_API_KEY` env |
| `--model` | | Anthropic model | `claude-3-5-sonnet-20241022` |
| `--timeout` | | Overall timeout (seconds) | `300` |
| `--no-ai` | | Disable AI analysis | `false` |
| `--modules` | `-m` | Comma-separated modules to run | all |

### Module Subcommands

```bash
# List available modules
knox module list

# Run individual modules
knox module subdomain example.com      # Subdomain enumeration
knox module dns example.com            # DNS records
knox module http example.com           # HTTP probing & tech detection
knox module portscan example.com       # Port scanning
knox module tech example.com           # Technology detection
knox module dir example.com            # Directory enumeration
knox module url example.com            # URL discovery
knox module vuln example.com           # Vulnerability scanning

# Run multiple modules
knox scan example.com -m subdomain,http,vuln
```

### Examples

```bash
# Basic scan
knox scan example.com

# With custom options
knox scan example.com \
  --output ./reports \
  --model claude-3-5-haiku-20241022 \
  --timeout 600 \
  --verbose

# CI/CD friendly (exit code based on severity)
knox scan example.com --fail-on high

# Using config file
cp config.yaml.example ~/.knox/config.yaml
# Edit config with your API key
knox scan example.com

# Using .env file
cp .env.example .env
# Edit .env with your API key
knox scan example.com

# Shell completion
knox completion bash > /etc/bash_completion.d/knox
knox completion zsh > ~/.zsh/completion/_knox
```

## Modules

Knox Suite is built with a modular architecture. Each module can be run independently:

### Reconnaissance Modules

| Module | Tool | Description |
|--------|------|-------------|
| `subdomain` | subfinder, amass, crt.sh | Subdomain enumeration |
| `dns` | dnsx | DNS record enumeration (A, AAAA, CNAME, MX, NS, TXT) |
| `http` | httpx | HTTP probing, status codes, tech detection, titles |
| `ssl` | sslscan | SSL/TLS certificate analysis |

### Scanning Modules

| Module | Tool | Description |
|--------|------|-------------|
| `portscan` | nmap | TCP SYN scan (top 1000 ports) |
| `tech` | whatweb | Technology fingerprinting |
| `dir` | dirsearch, ffuf | Directory/file enumeration |
| `url` | katana, gau, waybackurls | URL discovery from crawling & archives |

### Vulnerability Modules

| Module | Tool | Description |
|--------|------|-------------|
| `vuln` | nuclei | 1000+ vulnerability templates (CVE, misconfig, exposure) |
| `nikto` | nikto | Web server vulnerability scanning |
| `ssl-vuln` | sslscan | SSL/TLS configuration issues |

## Configuration

### Config File (`~/.knox/config.yaml` or `./config.yaml`)

```yaml
# Knox Suite Configuration
anthropic_key: ""              # Anthropic API key (or ANTHROPIC_API_KEY env)
model: "claude-3-5-sonnet-20241022"  # Model to use
timeout: 300                   # Overall timeout in seconds
output_dir: "./reports"        # Output directory
verbose: false                 # Verbose logging
no_ai: false                   # Disable AI analysis
fail_on: ""                    # Exit code threshold: critical, high, medium, low
modules: []                    # Default modules to run (empty = all)
```

### Environment Variables

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
export ANTHROPIC_MODEL="claude-3-5-sonnet-20241022"
export KNOX_TIMEOUT=600
export KNOX_OUTPUT_DIR="./reports"
export KNOX_VERBOSE=true
export KNOX_NO_AI=false
export KNOX_FAIL_ON="high"
```

### Priority Order

1. Command line flags
2. Environment variables
3. Config file (`~/.knox/config.yaml` → `./config.yaml`)
4. Defaults

## Output

Reports are saved to `{output_dir}/{target}-{timestamp}/`:

```
example.com-20240115-143022/
├── report.md          # Markdown report (human-readable)
├── report.html        # HTML report (styled, shareable)
├── report.json        # JSON report (machine-readable)
├── summary.txt        # Quick summary
├── subdomains.txt     # Raw subdomain list
├── live_hosts.txt     # Live hosts with status codes
├── open_ports.txt     # Open ports list
├── urls.txt           # Discovered URLs
├── vulnerabilities.json  # Structured vuln data
└── raw/               # Raw tool outputs
    ├── subfinder.txt
    ├── httpx.json
    ├── nmap.gnmap
    ├── nuclei.json
    └── ...
```

### Report Contents

1. **Executive Summary** - High-level findings and risk overview
2. **Reconnaissance Details** - Subdomains, live hosts, ports, technologies, SSL, directories
3. **Vulnerability Details** - Grouped by severity (Critical → Info)
4. **AI Analysis** - Expert analysis with attack paths and remediation
5. **Recommendations** - Prioritized action items

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no findings above threshold |
| 1 | General error |
| 2 | Critical findings found (if `--fail-on critical`) |
| 3 | High findings found (if `--fail-on high`) |
| 4 | Medium findings found (if `--fail-on medium`) |

## CI/CD Integration

### GitHub Actions

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  schedule:
    - cron: '0 2 * * 1'  # Weekly Monday 2AM
  workflow_dispatch:
    inputs:
      target:
        required: true
        type: string
      fail_on:
        required: false
        type: choice
        options: ['critical', 'high', 'medium', 'low']
        default: 'high'

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      
      - name: Install tools
        run: |
          go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
          go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
          go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
          go install -v github.com/projectdiscovery/katana/cmd/katana@latest
          go install -v github.com/lc/gau/v2/cmd/gau@latest
          go install -v github.com/tomnomnom/waybackurls@latest
          go install -v github.com/ffuf/ffuf/v2@latest
          sudo apt-get update && sudo apt-get install -y nmap nikto sslscan whatweb dirsearch sqlmap amass
          nuclei -update-templates
          echo "$(go env GOPATH)/bin" >> $GITHUB_PATH

      - name: Build Knox
        run: make build

      - name: Run Scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          ./build/knox scan "${{ github.event.inputs.target }}" \
            --output ./scan-report \
            --fail-on "${{ github.event.inputs.fail_on }}" \
            --timeout 1800 \
            --verbose

      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: knox-report-${{ github.event.inputs.target }}
          path: scan-report/
          retention-days: 30
```

### GitLab CI

```yaml
# .gitlab-ci.yml
security_scan:
  image: golang:1.23
  stage: security
  variables:
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
  script:
    - make build
    - ./build/knox scan $TARGET --fail-on high --output ./report
  artifacts:
    paths:
      - report/
    expire_in: 30 days
  only:
    - schedules
    - web
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Knox Suite                               │
├─────────────────────────────────────────────────────────────────┤
│  CLI Layer (Cobra)                                              │
│  ├── scan      - Full pipeline orchestration                    │
│  ├── recon     - Reconnaissance pipeline                        │
│  ├── module    - Individual module execution                    │
│  ├── report    - Report generation from saved data              │
│  └── completion - Shell completions                             │
├─────────────────────────────────────────────────────────────────┤
│  Core Modules (Internal Packages)                               │
│  ├── config    - Configuration management (Viper)               │
│  ├── tools     - Tool runner (exec, timeout, parallel)          │
│  ├── scanner   - Module implementations                         │
│  │   ├── recon.go      - Reconnaissance modules                 │
│  │   ├── scan.go       - Scanning modules                       │
│  │   └── vuln.go       - Vulnerability modules                  │
│  ├── llm       - Anthropic Claude integration                   │
│  └── report    - Multi-format report generator                  │
├─────────────────────────────────────────────────────────────────┤
│  External Tools (System-installed)                              │
│  subfinder, amass, crt.sh, dnsx, httpx, nmap, whatweb,         │
│  nuclei, nikto, sslscan, dirsearch, ffuf, katana, gau,         │
│  waybackurls, sqlmap, amass                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Requirements

- **Go 1.23+** (for building)
- **Security tools** (see Installation)
- **Anthropic API key** (for AI analysis)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

⚠️ **For authorized testing only.** Only use this tool on systems you own or have explicit written permission to test. Unauthorized penetration testing is illegal in most jurisdictions.

The authors are not responsible for any misuse or damage caused by this tool.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run `make fmt vet test`
5. Submit a PR

## Acknowledgments

- Security tools by ProjectDiscovery, OWASP, and the open source community
- Anthropic for Claude API
- Inspired by penetration testing frameworks and methodologies

## Support

- 📖 [Documentation](https://github.com/yourusername/knox-suite/wiki)
- 🐛 [Issue Tracker](https://github.com/yourusername/knox-suite/issues)
- 💬 [Discussions](https://github.com/yourusername/knox-suite/discussions)
- 🔒 [Security Policy](SECURITY.md)