# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in Knox Suite, please report it responsibly.

### How to Report

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email us at **security@knox-suite.example.com** (replace with actual email) with the following details:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** assessment
4. **Suggested fix** (if any)
5. Your **contact information** for follow-up

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Within 90 days

## Security Considerations

### Tool Execution

Knox Suite executes external security tools (nmap, nuclei, subfinder, etc.) on the target domain. These tools:

- Run with the permissions of the user executing Knox Suite
- May send network traffic to the target
- Should only be used against authorized targets

### Data Handling

- **No data persistence**: Knox Suite does not store scan results persistently beyond the report output directory
- **No telemetry**: No usage data is collected or transmitted
- **API Keys**: Anthropic API key is only used for AI analysis and never logged
- **Reports**: Generated reports contain scan results - handle according to your data classification policy

### Network Security

- Knox Suite makes outbound connections to:
  - Target domain (for scanning)
  - crt.sh (for certificate transparency)
  - Anthropic API (for AI analysis)
  - GitHub API (for update checks, if enabled)
- No inbound listeners are created
- Docker container runs as non-root user (UID 1000)

### Supply Chain Security

- Dependencies are pinned in `go.mod` and `go.sum`
- Docker base images are pinned to specific versions
- Security tools are installed from official package repositories
- Go modules are verified with `go mod verify`

## Best Practices for Users

1. **Always run in isolated environments** (VM, container, dedicated host)
2. **Use least privilege** - run as non-root user
3. **Restrict network access** - use firewall rules to limit outbound connections
4. **Review reports before sharing** - they may contain sensitive information
5. **Keep tools updated** - run `nuclei -update-templates` regularly
6. **Use `.env` file** for API keys - never commit to version control

## Disclosure Policy

When we receive a valid security report:

1. We'll acknowledge receipt within 48 hours
2. We'll investigate and validate the issue
3. We'll develop and test a fix
4. We'll coordinate disclosure with the reporter
5. We'll release a security advisory and patched version
6. We'll credit the reporter (unless they prefer anonymity)

## Contact

- **Security Email**: security@knox-suite.example.com
- **PGP Key**: Available on request
- **Bug Bounty**: Not currently offered

---

*This policy is inspired by industry best practices and may be updated as the project evolves.*