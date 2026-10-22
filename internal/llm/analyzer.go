package llm

import (
	"context"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/charmbracelet/log"

	"knox-suite/internal/scanner"
)

type Analyzer struct {
	client  *anthropic.Client
	model   string
	verbose bool
}

func NewAnalyzer(apiKey, model string, verbose bool) *Analyzer {
	client := anthropic.NewClient(
		option.WithAPIKey(apiKey),
	)
	return &Analyzer{
		client:  client,
		model:   model,
		verbose: verbose,
	}
}

func (a *Analyzer) Analyze(ctx context.Context, target string, recon *scanner.ReconResults, scan *scanner.ScanResults, vuln *scanner.VulnResults) (string, error) {
	prompt := a.buildPrompt(target, recon, scan, vuln)

	if a.verbose {
		log.Debug("Sending prompt to Anthropic", "length", len(prompt))
	}

	msg, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(a.model),
		MaxTokens: 8192,
		Messages: []anthropic.MessageParam{
			{
				Role: "user",
				Content: []anthropic.ContentBlockParamUnion{
					{OfText: &anthropic.TextBlockParam{Text: prompt}},
				},
			},
		},
		System: []anthropic.TextBlockParam{{
			Text: `You are an expert penetration tester and security analyst. 
Analyze the provided reconnaissance and vulnerability scan results.
Provide a professional security assessment with:
1. Executive Summary
2. Key Findings (prioritized by risk)
3. Attack Path Analysis
4. Remediation Recommendations
5. Compliance Considerations

Be concise, actionable, and technically accurate. Use markdown formatting.`,
		}},
	})

	if err != nil {
		return "", fmt.Errorf("anthropic API error: %w", err)
	}

	if len(msg.Content) > 0 {
		if text, ok := msg.Content[0].(anthropic.TextBlock); ok {
			return text.Text, nil
		}
	}

	return "", fmt.Errorf("no response content")
}

func (a *Analyzer) buildPrompt(target string, recon *scanner.ReconResults, scan *scanner.ScanResults, vuln *scanner.VulnResults) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Knox Suite Penetration Test Analysis for: %s\n\n", target))
	sb.WriteString(fmt.Sprintf("Scan Date: %s\n\n", recon.Timestamp.Format("2006-01-02 15:04:05")))

	// Reconnaissance Summary
	sb.WriteString("## Reconnaissance Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **Subdomains Discovered**: %d\n", len(recon.Subdomains)))
	sb.WriteString(fmt.Sprintf("- **Live Hosts**: %d\n", len(recon.LiveHosts)))
	sb.WriteString(fmt.Sprintf("- **DNS Records**: %d\n", len(recon.DNSRecords)))
	sb.WriteString(fmt.Sprintf("- **SSL Certificates**: %d\n", len(recon.SSLInfo)))
	sb.WriteString(fmt.Sprintf("- **Open Ports**: %d\n", len(scan.OpenPorts)))
	sb.WriteString(fmt.Sprintf("- **Technologies Detected**: %d\n", len(scan.Technologies)))
	sb.WriteString(fmt.Sprintf("- **Directories Found**: %d\n", len(scan.Directories)))
	sb.WriteString(fmt.Sprintf("- **URLs Discovered**: %d\n\n", len(scan.URLs)))

	if len(recon.Subdomains) > 0 {
		sb.WriteString("### Top Subdomains\n")
		for i, sub := range recon.Subdomains {
			if i >= 20 {
				sb.WriteString(fmt.Sprintf("... and %d more\n", len(recon.Subdomains)-20))
				break
			}
			sb.WriteString(fmt.Sprintf("- %s\n", sub))
		}
		sb.WriteString("\n")
	}

	if len(recon.LiveHosts) > 0 {
		sb.WriteString("### Live Hosts\n")
		for _, h := range recon.LiveHosts {
			sb.WriteString(fmt.Sprintf("- %s (Status: %d", h.Host, h.StatusCode)
			if h.Title != "" {
				sb.WriteString(fmt.Sprintf(", Title: %s", h.Title))
			}
			if len(h.Tech) > 0 {
				sb.WriteString(fmt.Sprintf(", Tech: %s", strings.Join(h.Tech, ", ")))
			}
			sb.WriteString(")\n")
		}
		sb.WriteString("\n")
	}

	if len(scan.OpenPorts) > 0 {
		sb.WriteString("### Open Ports\n")
		for _, p := range scan.OpenPorts {
			sb.WriteString(fmt.Sprintf("- %s:%d/%s (%s) - %s\n", p.Host, p.Port, p.Proto, p.State, p.Service))
		}
		sb.WriteString("\n")
	}

	if len(scan.Technologies) > 0 {
		sb.WriteString("### Technologies\n")
		for _, t := range scan.Technologies {
			sb.WriteString(fmt.Sprintf("- %s\n", t))
		}
		sb.WriteString("\n")
	}

	if len(recon.SSLInfo) > 0 {
		sb.WriteString("### SSL Certificates\n")
		for _, s := range recon.SSLInfo {
			sb.WriteString(fmt.Sprintf("- %s: Issuer=%s, Valid=%s to %s\n", s.Host, s.Issuer, s.NotBefore, s.NotAfter))
		}
		sb.WriteString("\n")
	}

	// Vulnerability Summary
	sb.WriteString("## Vulnerability Scan Results\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Findings**: %d\n\n", len(vuln.Findings)))

	if len(vuln.Findings) > 0 {
		bySeverity := make(map[string][]scanner.Finding)
		for _, f := range vuln.Findings {
			bySeverity[f.Severity] = append(bySeverity[f.Severity], f)
		}

		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			findings := bySeverity[sev]
			if len(findings) == 0 {
				continue
			}
			sb.WriteString(fmt.Sprintf("### %s Severity (%d)\n", strings.ToUpper(sev), len(findings)))
			for i, f := range findings {
				if i >= 10 {
					sb.WriteString(fmt.Sprintf("... and %d more\n", len(findings)-10))
					break
				}
				sb.WriteString(fmt.Sprintf("- **%s** (%s)\n", f.Name, f.Tool))
				sb.WriteString(fmt.Sprintf("  Target: %s\n", f.Target))
				sb.WriteString(fmt.Sprintf("  Description: %s\n", f.Description))
				if f.CVE != "" {
					sb.WriteString(fmt.Sprintf("  CVE: %s\n", f.CVE))
				}
				if f.CVSS > 0 {
					sb.WriteString(fmt.Sprintf("  CVSS: %.1f\n", f.CVSS))
				}
				if f.Evidence != "" {
					evidence := f.Evidence
					if len(evidence) > 200 {
						evidence = evidence[:200] + "..."
					}
					sb.WriteString(fmt.Sprintf("  Evidence: %s\n", evidence))
				}
				sb.WriteString("\n")
			}
		}
	} else {
		sb.WriteString("No vulnerabilities found by automated scanners.\n\n")
	}

	sb.WriteString("---\n\n")
	sb.WriteString("Please provide a professional penetration test analysis with the sections mentioned in the system prompt.")

	return sb.String()
}