# Contributing to Knox Suite

Thank you for your interest in contributing to Knox Suite! This document provides guidelines for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Adding New Modules](#adding-new-modules)

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to conduct@knox-suite.example.com.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/knox-suite.git`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Submit a pull request

## Development Setup

### Prerequisites

- Go 1.23+
- Make
- Git
- Security tools (for testing):
  ```bash
  # Ubuntu/Debian
  sudo apt install nmap nuclei subfinder httpx dnsx sslscan whatweb nikto dirsearch ffuf katana gau waybackurls amass
  
  # Or install via Go
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  # ... etc
  ```

### Environment Setup

```bash
# Clone and enter directory
cd knox-suite

# Copy config template
cp config.yaml.example config.yaml

# Edit config with your API key (optional for development)
# ANTHROPIC_API_KEY=your_key_here

# Install dependencies
go mod tidy

# Run tests
make test

# Build
make build

# Run locally
./build/knox scan example.com --verbose --no-ai
```

## Making Changes

### Branch Naming

- Features: `feature/short-description`
- Bug fixes: `fix/short-description`
- Documentation: `docs/short-description`
- Refactoring: `refactor/short-description`

### Code Organization

```
knox-suite/
├── cmd/knox/           # CLI entry point
├── internal/
│   ├── cli/           # Cobra commands
│   ├── config/        # Configuration management
│   ├── tools/         # Tool execution wrapper
│   ├── scanner/       # Modular scanning logic
│   ├── llm/           # LLM integration
│   └── report/        # Report generation
├── scripts/           # Installer scripts
├── .github/workflows/ # CI/CD pipelines
└── ...
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific package
go test ./internal/scanner/... -v

# Run with race detector
go test -race ./...
```

### Writing Tests

- Place tests in `*_test.go` files alongside the code
- Test public functions and critical logic
- Use table-driven tests for multiple cases
- Mock external dependencies (tools, APIs)

### Test Guidelines

- Unit tests should be fast (< 1s each)
- Integration tests can be slower but should be marked
- Use `testify` for assertions if needed
- Aim for >80% coverage on new code

## Code Style

### Go Style

Follow standard Go conventions:

- Run `make fmt` before committing
- Run `make vet` to catch issues
- Run `make lint` for comprehensive linting
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Follow [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

### Project-Specific Style

- Use `color` package for colored output
- Use `charmbracelet/log` for logging
- Keep functions small and focused
- Use meaningful variable names
- Add comments for exported functions
- Handle errors explicitly (no naked returns)

### Error Handling

```go
// Good
result, err := runner.Run("nmap", "-sS", target)
if err != nil {
    return fmt.Errorf("nmap scan failed: %w", err)
}

// Avoid
result, _ := runner.Run("nmap", "-sS", target) // Ignoring error!
```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): short description

Longer description if needed.

Fixes #123
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting, missing semicolons, etc.
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes

### Examples

```
feat(scanner): add new SSL vulnerability module

Add ssl-vuln module that checks for weak ciphers and expired certificates
using sslscan tool.

Fixes #45
```

```
fix(report): handle empty findings in JSON output

When no vulnerabilities found, JSON output was malformed.
Now outputs empty array correctly.
```

## Pull Request Process

1. **Update documentation** - README, comments, etc.
2. **Add tests** - For new features and bug fixes
3. **Run checks** - `make fmt vet lint test`
4. **Update CHANGELOG** - If applicable
5. **Submit PR** - With clear description

### PR Requirements

- [ ] All tests pass
- [ ] Code formatted (`make fmt`)
- [ ] No lint errors (`make lint`)
- [ ] No vet warnings (`make vet`)
- [ ] Documentation updated
- [ ] Tests added for new functionality
- [ ] Commit messages follow convention

### Review Process

1. Automated checks must pass
2. At least one maintainer review
3. Address all review comments
4. Squash commits if requested
5. Merge after approval

## Adding New Modules

Knox Suite's modular architecture makes it easy to add new scanning capabilities.

### 1. Define Module Name

Add to `internal/scanner/scanner.go` in `GetModuleNames()`:

```go
func GetModuleNames() []string {
    return []string{
        // ... existing modules
        "your-module",  // Add here
    }
}
```

### 2. Add Module Logic

Add a case to `RunModule()`:

```go
func RunModule(ctx context.Context, runner *tools.Runner, target string, moduleName string, verbose bool) (interface{}, error) {
    switch moduleName {
    // ... existing cases
    case "your-module":
        return runYourModule(ctx, runner, target, verbose)
    }
}
```

### 3. Implement Module Function

```go
func runYourModule(ctx context.Context, runner *tools.Runner, target string, verbose bool) (interface{}, error) {
    // Check tool availability
    if !runner.IsToolAvailable("yourtool") {
        return nil, fmt.Errorf("yourtool not available")
    }
    
    // Run tool
    out, err := runner.Run("yourtool", "args", target)
    if err != nil {
        return nil, err
    }
    
    // Parse output
    results := parseYourToolOutput(out)
    
    return map[string]interface{}{"results": results}, nil
}
```

### 4. Integrate with Pipeline (Optional)

If the module should run as part of `scan` command, add to appropriate phase in `RunReconnaissance`, `RunScanning`, or `RunVulnerabilityScan`.

### 5. Add Tests

Create tests in `scanner_test.go`:

```go
func TestYourModule(t *testing.T) {
    // Test parsing logic
    output := `sample tool output`
    results := parseYourToolOutput(output)
    
    if len(results) == 0 {
        t.Error("Expected parsed results")
    }
}
```

### 6. Update Documentation

- Add to `README.md` module list
- Update `PENTAGI_COMPARISON.md` if needed
- Add command examples

### Module Guidelines

- **Single responsibility**: One module = one capability
- **Tool independence**: Gracefully handle missing tools
- **Parallel safe**: Don't share state between modules
- **Configurable**: Respect timeout and verbose flags
- **Structured output**: Return `map[string]interface{}` for JSON serialization

## Questions?

- Open a [Discussion](https://github.com/yourusername/knox-suite/discussions)
- Check existing [Issues](https://github.com/yourusername/knox-suite/issues)
- Review [Documentation](https://github.com/yourusername/knox-suite/wiki)

Thank you for contributing! 🎉