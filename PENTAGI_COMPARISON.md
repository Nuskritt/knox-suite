# PentAGI vs Knox Suite - Architecture Comparison

This document explains how Knox Suite was derived from PentAGI and the key architectural differences.

## PentAGI Architecture (Original)

```
┌─────────────────────────────────────────────────────────────────┐
│                        PentAGI Stack                            │
├─────────────────────────────────────────────────────────────────┤
│  Frontend (React/TS)  │  Backend (Go/GraphQL)  │  PostgreSQL   │
│  ──────────────────   │  ────────────────────  │  + pgvector   │
│  - Flow management    │  - Multi-agent system  │  - Memory     │
│  - Real-time logs     │  - Tool orchestration  │  - Embeddings │
│  - Settings UI        │  - LLM provider mgmt   │  - Tasks      │
├─────────────────────────────────────────────────────────────────┤
│  Optional Services                                                    │
│  ├── Neo4j + Graphiti (Knowledge Graph)                              │
│  ├── Langfuse + ClickHouse (LLM Analytics)                           │
│  ├── Grafana + VictoriaMetrics + Loki + Jaeger (Observability)       │
│  └── Scraper (Browser automation)                                    │
├─────────────────────────────────────────────────────────────────┤
│  Docker Sandbox (per-flow containers with 20+ security tools)      │
└─────────────────────────────────────────────────────────────────┘
```

**Key Characteristics:**
- 10+ Docker containers
- Multi-agent system (12+ agent types)
- Persistent memory with vector search
- Knowledge graph integration
- Web UI with real-time updates
- Complex configuration (100+ env vars)
- Enterprise features (multi-tenancy, RBAC, OAuth)

## Knox Suite Architecture (Lightweight)

```
┌─────────────────────────────────────────────────────────────────┐
│                      Knox Suite                                 │
├─────────────────────────────────────────────────────────────────┤
│  Single Go Binary (~10MB)                                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │   CLI       │  │  Scanner    │  │   LLM       │              │
│  │  (Cobra)    │──│  (Modular)  │──│  (Anthropic)│              │
│  │             │  │             │  │             │              │
│  └─────────────┘  └─────────────┘  └─────────────┘              │
│         │                │                │                      │
│         └────────────────┼────────────────┘                      │
│                          ▼                                       │
│                 ┌─────────────────┐                              │
│                 │  Report Gen     │                              │
│                 │  (MD/HTML/JSON) │                              │
│                 └─────────────────┘                              │
├─────────────────────────────────────────────────────────────────┤
│  External Tools (system-installed)                               │
│  nmap, nuclei, subfinder, httpx, dnsx, sslscan, whatweb,        │
│  nikto, dirsearch, ffuf, katana, gau, waybackurls, amass        │
└─────────────────────────────────────────────────────────────────┘
```

**Key Characteristics:**
- Single binary (~10MB)
- No database, no persistent memory
- No web UI, CLI only
- Single LLM provider (Anthropic)
- 14 external tools (system-installed)
- Modular architecture (run individual modules)
- Simple configuration (10 options max)
- Designed for quick assessments, CI/CD, bug bounty

## Code Mapping

| PentAGI Component | Knox Suite Equivalent | Notes |
|------------------|----------------------|-------|
| `backend/pkg/tools/terminal.go` | `internal/tools/runner.go` | Simplified exec, no Docker sandbox |
| `backend/pkg/tools/web_search.go` | `internal/scanner/scanner.go` | Modular tool calls, no fallback chains |
| `backend/pkg/providers/` | `internal/llm/analyzer.go` | Single Anthropic provider |
| `backend/pkg/controller/` | `internal/scanner/scanner.go` | Linear pipeline, no agent orchestration |
| `backend/pkg/graph/` | N/A | No GraphQL API |
| `backend/pkg/database/` | N/A | No persistence |
| `frontend/` | N/A | No web UI |
| `docker-compose.yml` | `Dockerfile` + `docker-compose.yml` | Single container |
| `pkg/csum/` (summarization) | N/A | Single-shot prompts |
| `pkg/templates/` (prompts) | `internal/llm/analyzer.go` | Hardcoded prompt template |

## Simplified Flow

### PentAGI Flow
```
User Creates Flow
       │
       ▼
Primary Agent decomposes → Tasks
       │
       ▼
Generator/Refiner plan → SubTasks
       │
       ▼
Specialist Agents (Researcher, Developer, Executor)
       │
       ├── Terminal Tool → Docker sandbox
       ├── Web Search Tool → Multiple engines
       ├── Browser Tool → Scraper
       ├── Memory Tool → pgvector
       └── Knowledge Tool → Graphiti
       │
       ▼
Results stored in PostgreSQL
       │
       ▼
Real-time updates via GraphQL subscriptions
       │
       ▼
Web UI displays progress
```

### Knox Suite Flow
```
User runs: knox scan example.com
       │
       ▼
┌──────────────────────────────────────┐
│ Phase 1: Reconnaissance (Parallel)   │
│ ├─ subdomain  - subfinder/amass/crt.sh│
│ ├─ dns        - dnsx                  │
│ ├─ http       - httpx                 │
│ └─ ssl        - sslscan               │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ Phase 2: Scanning (Parallel)         │
│ ├─ portscan   - nmap                  │
│ ├─ tech       - whatweb               │
│ ├─ dir        - dirsearch/ffuf        │
│ └─ url        - katana/gau/wayback    │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ Phase 3: Vulnerability Assessment    │
│ ├─ vuln       - nuclei (1000+ templates)│
│ ├─ nikto      - web server scanning   │
│ └─ ssl-vuln   - SSL/TLS issues        │
└──────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────┐
│ Phase 4: AI Analysis (Optional)      │
│ └─ Anthropic Claude → Report         │
└──────────────────────────────────────┘
       │
       ▼
Generate Reports (MD/HTML/JSON)
```

## Module System

Knox Suite introduces a modular architecture where each capability is a separate module:

```
knox module list                 # List all modules
knox module subdomain example.com  # Run single module
knox module vuln example.com       # Run vulnerability scan only
knox scan example.com -m subdomain,http,vuln  # Run selected modules
```

### Available Modules

| Category | Modules | Tools |
|----------|---------|-------|
| **Reconnaissance** | subdomain, dns, http, ssl | subfinder, amass, crt.sh, dnsx, httpx, sslscan |
| **Scanning** | portscan, tech, dir, url | nmap, whatweb, dirsearch, ffuf, katana, gau, waybackurls |
| **Vulnerability** | vuln, nikto, ssl-vuln | nuclei, nikto, sslscan |

## When to Use Each

### Use PentAGI When:
- ✅ Enterprise continuous penetration testing
- ✅ Team collaboration with web UI
- ✅ Need persistent learning/memory across tests
- ✅ Complex multi-step attack chains
- ✅ Compliance reporting requirements
- ✅ Integration with existing SIEM/SOAR
- ✅ Multiple LLM providers needed
- ✅ Knowledge graph for attack path analysis

### Use Knox Suite When:
- ✅ Quick one-off assessments
- ✅ Bug bounty reconnaissance
- ✅ CTF competitions
- ✅ CI/CD pipeline integration
- ✅ No Docker/infrastructure available
- ✅ Simple "give me a domain, get a report" workflow
- ✅ Prefer CLI over web UI
- ✅ Want single binary deployment
- ✅ Need modular execution (run only what you need)
- ✅ Want fail-on-severity for CI gates

## Migration Path

If you outgrow Knox Suite:

1. **Start with Knox Suite** for initial recon
2. **Import findings** into PentAGI as a starting flow
3. **Use PentAGI's agents** for deep exploitation
4. **Leverage memory** for future tests on same target

## Design Decisions

### What We Kept from PentAGI
- Tool orchestration patterns (parallel execution, error handling)
- Reconnaissance methodology (subdomain → DNS → HTTP → Ports)
- Vulnerability scanning approach (Nuclei + Nikto + SSL)
- Report structure (Executive Summary → Details → Recommendations)
- Configuration via env vars + config file

### What We Removed
- Multi-agent system → Single linear pipeline
- Docker sandbox → System tools directly
- Persistent memory → In-memory only
- GraphQL API → CLI only
- Web UI → Terminal output
- Multiple LLM providers → Anthropic only
- Knowledge graph → Simple correlation
- Complex config → 10 options max

### What We Added
- Single binary distribution
- Modular architecture (run individual modules)
- GitHub Actions CI/CD template with fail-on-severity
- Docker image with all tools pre-installed
- Installer scripts (bash + PowerShell)
- Multiple report formats (MD/HTML/JSON)
- Severity-based exit codes for CI
- Shell completions (bash, zsh, fish, powershell)
- Module system for granular control