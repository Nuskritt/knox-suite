package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"

	"knox-suite/internal/scanner"
)

type Generator struct {
	outputDir string
	target    string
}

func NewGenerator(outputDir, target string) *Generator {
	return &Generator{
		outputDir: outputDir,
		target:    sanitizeFilename(target),
	}
}

func (g *Generator) Generate(recon *scanner.ReconResults, scan *scanner.ScanResults, vuln *scanner.VulnResults, aiAnalysis string) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	reportDir := filepath.Join(g.outputDir, fmt.Sprintf("%s-%s", g.target, timestamp))

	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return "", err
	}

	// Generate Markdown report
	mdPath := filepath.Join(reportDir, "report.md")
	mdContent := g.generateMarkdown(recon, scan, vuln, aiAnalysis)
	if err := os.WriteFile(mdPath, []byte(mdContent), 0644); err != nil {
		return "", err
	}

	// Generate JSON report
	jsonPath := filepath.Join(reportDir, "report.json")
	jsonContent := g.generateJSON(recon, scan, vuln, aiAnalysis)
	if err := os.WriteFile(jsonPath, []byte(jsonContent), 0644); err != nil {
		return "", err
	}

	// Generate HTML report
	htmlPath := filepath.Join(reportDir, "report.html")
	htmlContent := g.generateHTML(recon, scan, vuln, aiAnalysis)
	if err := os.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
		return "", err
	}

	// Save raw data
	g.saveRawData(reportDir, recon, scan, vuln)

	color.Green("📁 Report directory: %s", reportDir)
	return reportDir, nil
}

func (g *Generator) GenerateReconOnly(recon *scanner.ReconResults) (string, error) {
	vuln := &scanner.VulnResults{Target: recon.Target, Timestamp: time.Now()}
	scan := &scanner.ScanResults{Target: recon.Target, Timestamp: time.Now()}
	return g.Generate(recon, scan, vuln, "")
}

func (g *Generator) GenerateModule(moduleName string, data interface{}) (string, error) {
	timestamp := time.Now().Format("20060102-150405")
	reportDir := filepath.Join(g.outputDir, fmt.Sprintf("%s-%s-%s", g.target, moduleName, timestamp))

	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return "", err
	}

	// Generate simple report for module
	mdPath := filepath.Join(reportDir, "report.md")
	mdContent := g.generateModuleMarkdown(moduleName, data)
	if err := os.WriteFile(mdPath, []byte(mdContent), 0644); err != nil {
		return "", err
	}

	color.Green("📁 Module report directory: %s", reportDir)
	return reportDir, nil
}

func (g *Generator) generateMarkdown(recon *scanner.ReconResults, scan *scanner.ScanResults, vuln *scanner.VulnResults, aiAnalysis string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Knox Suite Penetration Test Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Target:** %s  \n", recon.Target))
	sb.WriteString(fmt.Sprintf("**Scan Date:** %s  \n", recon.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n\n", time.Now().Format("2006-01-02 15:04:05")))

	sb.WriteString("---\n\n")

	// Executive Summary
	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("Automated penetration test conducted against **%s** using Knox Suite.\n\n", recon.Target))
	sb.WriteString(fmt.Sprintf("- **Subdomains Discovered:** %d\n", len(recon.Subdomains)))
	sb.WriteString(fmt.Sprintf("- **Live Hosts:** %d\n", len(recon.LiveHosts)))
	sb.WriteString(fmt.Sprintf("- **Open Ports:** %d\n", len(scan.OpenPorts)))
	sb.WriteString(fmt.Sprintf("- **Technologies Detected:** %d\n", len(scan.Technologies)))
	sb.WriteString(fmt.Sprintf("- **Directories Found:** %d\n", len(scan.Directories)))
	sb.WriteString(fmt.Sprintf("- **URLs Discovered:** %d\n", len(scan.URLs)))
	sb.WriteString(fmt.Sprintf("- **Vulnerabilities Found:** %d\n\n", len(vuln.Findings)))

	if len(vuln.Findings) > 0 {
		severityCount := make(map[string]int)
		for _, f := range vuln.Findings {
			severityCount[f.Severity]++
		}
		sb.WriteString("### Vulnerability Breakdown\n\n")
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count := severityCount[sev]; count > 0 {
				sb.WriteString(fmt.Sprintf("- **%s:** %d\n", strings.ToUpper(sev), count))
			}
		}
		sb.WriteString("\n")
	}

	// AI Analysis
	if aiAnalysis != "" {
		sb.WriteString("---\n\n")
		sb.WriteString("## AI Analysis\n\n")
		sb.WriteString(aiAnalysis)
		sb.WriteString("\n\n")
	}

	// Reconnaissance Details
	sb.WriteString("---\n\n")
	sb.WriteString("## Reconnaissance Details\n\n")

	sb.WriteString("### Subdomains\n\n")
	if len(recon.Subdomains) > 0 {
		for _, sub := range recon.Subdomains {
			sb.WriteString(fmt.Sprintf("- %s\n", sub))
		}
	} else {
		sb.WriteString("No subdomains discovered.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("### DNS Records\n\n")
	if len(recon.DNSRecords) > 0 {
		sb.WriteString("| Domain | Type | Value |\n")
		sb.WriteString("|--------|------|-------|\n")
		for _, r := range recon.DNSRecords {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", r.Domain, r.Type, r.Value))
		}
	} else {
		sb.WriteString("No DNS records found.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("### Live Hosts\n\n")
	if len(recon.LiveHosts) > 0 {
		sb.WriteString("| Host | IP | Status | Title | Technologies |\n")
		sb.WriteString("|------|-----|--------|-------|--------------|\n")
		for _, h := range recon.LiveHosts {
			title := h.Title
			if len(title) > 50 {
				title = title[:50] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s |\n",
				h.Host, h.IP, h.StatusCode, title, strings.Join(h.Tech, ", ")))
		}
	} else {
		sb.WriteString("No live hosts found.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("### SSL Certificates\n\n")
	if len(recon.SSLInfo) > 0 {
		sb.WriteString("| Host | Issuer | Subject | Valid From | Valid To |\n")
		sb.WriteString("|------|--------|---------|------------|----------|\n")
		for _, s := range recon.SSLInfo {
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", s.Host, s.Issuer, s.Subject, s.NotBefore, s.NotAfter))
		}
	} else {
		sb.WriteString("No SSL certificate information.\n")
	}
	sb.WriteString("\n")

	// Scanning Details
	sb.WriteString("---\n\n")
	sb.WriteString("## Scanning Details\n\n")

	sb.WriteString("### Open Ports\n\n")
	if len(scan.OpenPorts) > 0 {
		sb.WriteString("| Host | Port | Protocol | State | Service |\n")
		sb.WriteString("|------|------|----------|-------|---------|\n")
		for _, p := range scan.OpenPorts {
			sb.WriteString(fmt.Sprintf("| %s | %d | %s | %s | %s |\n", p.Host, p.Port, p.Proto, p.State, p.Service))
		}
	} else {
		sb.WriteString("No open ports found.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("### Technologies Detected\n\n")
	if len(scan.Technologies) > 0 {
		for _, t := range scan.Technologies {
			sb.WriteString(fmt.Sprintf("- %s\n", t))
		}
	} else {
		sb.WriteString("No technologies detected.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("### Discovered Directories\n\n")
	if len(scan.Directories) > 0 {
		sb.WriteString("| Path | Status | Size |\n")
		sb.WriteString("|------|--------|------|\n")
		for _, d := range scan.Directories {
			sb.WriteString(fmt.Sprintf("| %s | %d | %d |\n", d.Path, d.StatusCode, d.Size))
		}
	} else {
		sb.WriteString("No directories discovered.\n")
	}
	sb.WriteString("\n")

	sb.WriteString("### Discovered URLs\n\n")
	if len(scan.URLs) > 0 {
		for i, u := range scan.URLs {
			if i >= 50 {
				sb.WriteString(fmt.Sprintf("... and %d more\n", len(scan.URLs)-50))
				break
			}
			sb.WriteString(fmt.Sprintf("- %s\n", u))
		}
	} else {
		sb.WriteString("No URLs discovered.\n")
	}
	sb.WriteString("\n")

	// Vulnerability Details
	sb.WriteString("---\n\n")
	sb.WriteString("## Vulnerability Details\n\n")

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
			sb.WriteString(fmt.Sprintf("### %s Severity Findings\n\n", strings.ToUpper(sev)))
			for _, f := range findings {
				sb.WriteString(fmt.Sprintf("#### %s\n\n", f.Name))
				sb.WriteString(fmt.Sprintf("- **Tool:** %s\n", f.Tool))
				sb.WriteString(fmt.Sprintf("- **Target:** %s\n", f.Target))
				sb.WriteString(fmt.Sprintf("- **Severity:** %s\n", strings.ToUpper(f.Severity)))
				if f.CVE != "" {
					sb.WriteString(fmt.Sprintf("- **CVE:** %s\n", f.CVE))
				}
				if f.CVSS > 0 {
					sb.WriteString(fmt.Sprintf("- **CVSS:** %.1f\n", f.CVSS))
				}
				sb.WriteString(fmt.Sprintf("- **Description:** %s\n", f.Description))
				if f.Reference != "" {
					sb.WriteString(fmt.Sprintf("- **Reference:** %s\n", f.Reference))
				}
				if f.Evidence != "" {
					sb.WriteString(fmt.Sprintf("- **Evidence:**\n```\n%s\n```\n", f.Evidence))
				}
				sb.WriteString("\n")
			}
		}
	} else {
		sb.WriteString("No vulnerabilities found by automated scanners.\n\n")
	}

	// Recommendations
	sb.WriteString("---\n\n")
	sb.WriteString("## Recommendations\n\n")
	sb.WriteString("1. **Patch Critical/High Vulnerabilities Immediately** - Address all critical and high severity findings as priority.\n")
	sb.WriteString("2. **Implement WAF Rules** - Deploy Web Application Firewall rules for identified attack vectors.\n")
	sb.WriteString("3. **Update Software** - Ensure all detected technologies are running latest patched versions.\n")
	sb.WriteString("4. **Secure Configuration** - Review and harden server configurations based on findings.\n")
	sb.WriteString("5. **Monitor & Log** - Implement continuous security monitoring and log analysis.\n")
	sb.WriteString("6. **Regular Testing** - Schedule periodic automated and manual penetration tests.\n\n")

	sb.WriteString("---\n\n")
	sb.WriteString("*Report generated by Knox Suite - Lightweight Automated Penetration Testing Suite*\n")

	return sb.String()
}

func (g *Generator) generateJSON(recon *scanner.ReconResults, scan *scanner.ScanResults, vuln *scanner.VulnResults, aiAnalysis string) string {
	var sb strings.Builder
	sb.WriteString("{\n")
	sb.WriteString(fmt.Sprintf("  \"target\": \"%s\",\n", recon.Target))
	sb.WriteString(fmt.Sprintf("  \"scan_date\": \"%s\",\n", recon.Timestamp.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  \"generated\": \"%s\",\n", time.Now().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("  \"subdomains_count\": %d,\n", len(recon.Subdomains)))
	sb.WriteString(fmt.Sprintf("  \"live_hosts_count\": %d,\n", len(recon.LiveHosts)))
	sb.WriteString(fmt.Sprintf("  \"open_ports_count\": %d,\n", len(scan.OpenPorts)))
	sb.WriteString(fmt.Sprintf("  \"technologies_count\": %d,\n", len(scan.Technologies)))
	sb.WriteString(fmt.Sprintf("  \"directories_count\": %d,\n", len(scan.Directories)))
	sb.WriteString(fmt.Sprintf("  \"urls_count\": %d,\n", len(scan.URLs)))
	sb.WriteString(fmt.Sprintf("  \"vulnerabilities_count\": %d,\n", len(vuln.Findings)))
	sb.WriteString("  \"subdomains\": [\n")
	for i, s := range recon.Subdomains {
		sb.WriteString(fmt.Sprintf("    \"%s\"", s))
		if i < len(recon.Subdomains)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("  ],\n")
	sb.WriteString("  \"live_hosts\": [\n")
	for i, h := range recon.LiveHosts {
		sb.WriteString("    {\n")
		sb.WriteString(fmt.Sprintf("      \"host\": \"%s\",\n", h.Host))
		sb.WriteString(fmt.Sprintf("      \"ip\": \"%s\",\n", h.IP))
		sb.WriteString(fmt.Sprintf("      \"status_code\": %d,\n", h.StatusCode))
		sb.WriteString(fmt.Sprintf("      \"title\": \"%s\",\n", escapeJSON(h.Title)))
		sb.WriteString(fmt.Sprintf("      \"technologies\": %s\n", stringsToJSONArray(h.Tech)))
		sb.WriteString("    }")
		if i < len(recon.LiveHosts)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("  ],\n")
	sb.WriteString("  \"open_ports\": [\n")
	for i, p := range scan.OpenPorts {
		sb.WriteString("    {\n")
		sb.WriteString(fmt.Sprintf("      \"host\": \"%s\",\n", p.Host))
		sb.WriteString(fmt.Sprintf("      \"port\": %d,\n", p.Port))
		sb.WriteString(fmt.Sprintf("      \"protocol\": \"%s\",\n", p.Proto))
		sb.WriteString(fmt.Sprintf("      \"state\": \"%s\",\n", p.State))
		sb.WriteString(fmt.Sprintf("      \"service\": \"%s\"\n", p.Service))
		sb.WriteString("    }")
		if i < len(scan.OpenPorts)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("  ],\n")
	sb.WriteString("  \"technologies\": [\n")
	for i, t := range scan.Technologies {
		sb.WriteString(fmt.Sprintf("    \"%s\"", t))
		if i < len(scan.Technologies)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("  ],\n")
	sb.WriteString("  \"vulnerabilities\": [\n")
	for i, f := range vuln.Findings {
		sb.WriteString("    {\n")
		sb.WriteString(fmt.Sprintf("      \"id\": \"%s\",\n", f.ID))
		sb.WriteString(fmt.Sprintf("      \"name\": \"%s\",\n", escapeJSON(f.Name)))
		sb.WriteString(fmt.Sprintf("      \"severity\": \"%s\",\n", f.Severity))
		sb.WriteString(fmt.Sprintf("      \"target\": \"%s\",\n", f.Target))
		sb.WriteString(fmt.Sprintf("      \"tool\": \"%s\",\n", f.Tool))
		sb.WriteString(fmt.Sprintf("      \"description\": \"%s\",\n", escapeJSON(f.Description)))
		if f.CVE != "" {
			sb.WriteString(fmt.Sprintf("      \"cve\": \"%s\",\n", f.CVE))
		}
		if f.CVSS > 0 {
			sb.WriteString(fmt.Sprintf("      \"cvss\": %.1f,\n", f.CVSS))
		}
		sb.WriteString(fmt.Sprintf("      \"evidence\": \"%s\"\n", escapeJSON(f.Evidence)))
		sb.WriteString("    }")
		if i < len(vuln.Findings)-1 {
			sb.WriteString(",")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("  ]\n")
	sb.WriteString("}\n")
	return sb.String()
}

func (g *Generator) generateHTML(recon *scanner.ReconResults, scan *scanner.ScanResults, vuln *scanner.VulnResults, aiAnalysis string) string {
	md := g.generateMarkdown(recon, scan, vuln, aiAnalysis)
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Knox Suite Report - %s</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; line-height: 1.6; }
        h1, h2, h3, h4 { color: #1a1a2e; }
        table { border-collapse: collapse; width: 100%%; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #1a1a2e; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        code { background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
        pre { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .critical { color: #dc2626; font-weight: bold; }
        .high { color: #ea580c; font-weight: bold; }
        .medium { color: #ca8a04; }
        .low { color: #2563eb; }
        .info { color: #0891b2; }
        .severity-critical { background-color: #fef2f2; }
        .severity-high { background-color: #fff7ed; }
        .severity-medium { background-color: #fefce8; }
        .severity-low { background-color: #eff6ff; }
        .severity-info { background-color: #f0f9ff; }
    </style>
</head>
<body>
%s
</body>
</html>`, recon.Target, markdownToHTML(md))
}

func (g *Generator) generateModuleMarkdown(moduleName string, data interface{}) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Knox Suite Module Report: %s\n\n", strings.Title(moduleName)))
	sb.WriteString(fmt.Sprintf("**Target:** %s  \n", g.target))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("```json\n%v\n```\n", data))
	return sb.String()
}

func (g *Generator) saveRawData(reportDir string, recon *scanner.ReconResults, scan *scanner.ScanResults, vuln *scanner.VulnResults) {
	// Save subdomains
	if len(recon.Subdomains) > 0 {
		os.WriteFile(filepath.Join(reportDir, "subdomains.txt"), []byte(strings.Join(recon.Subdomains, "\n")), 0644)
	}
	// Save DNS records
	if len(recon.DNSRecords) > 0 {
		var lines []string
		for _, r := range recon.DNSRecords {
			lines = append(lines, fmt.Sprintf("%s\t%s\t%s", r.Domain, r.Type, r.Value))
		}
		os.WriteFile(filepath.Join(reportDir, "dns_records.txt"), []byte(strings.Join(lines, "\n")), 0644)
	}
	// Save live hosts
	if len(recon.LiveHosts) > 0 {
		var lines []string
		for _, h := range recon.LiveHosts {
			lines = append(lines, fmt.Sprintf("%s\t%d\t%s\t%s", h.Host, h.StatusCode, h.IP, h.Title))
		}
		os.WriteFile(filepath.Join(reportDir, "live_hosts.txt"), []byte(strings.Join(lines, "\n")), 0644)
	}
	// Save SSL info
	if len(recon.SSLInfo) > 0 {
		var lines []string
		for _, s := range recon.SSLInfo {
			lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s\t%s", s.Host, s.Issuer, s.Subject, s.NotBefore, s.NotAfter))
		}
		os.WriteFile(filepath.Join(reportDir, "ssl_info.txt"), []byte(strings.Join(lines, "\n")), 0644)
	}
	// Save open ports
	if len(scan.OpenPorts) > 0 {
		var lines []string
		for _, p := range scan.OpenPorts {
			lines = append(lines, fmt.Sprintf("%s\t%d\t%s\t%s\t%s", p.Host, p.Port, p.Proto, p.State, p.Service))
		}
		os.WriteFile(filepath.Join(reportDir, "open_ports.txt"), []byte(strings.Join(lines, "\n")), 0644)
	}
	// Save technologies
	if len(scan.Technologies) > 0 {
		os.WriteFile(filepath.Join(reportDir, "technologies.txt"), []byte(strings.Join(scan.Technologies, "\n")), 0644)
	}
	// Save directories
	if len(scan.Directories) > 0 {
		var lines []string
		for _, d := range scan.Directories {
			lines = append(lines, fmt.Sprintf("%s\t%d\t%d", d.Path, d.StatusCode, d.Size))
		}
		os.WriteFile(filepath.Join(reportDir, "directories.txt"), []byte(strings.Join(lines, "\n")), 0644)
	}
	// Save URLs
	if len(scan.URLs) > 0 {
		os.WriteFile(filepath.Join(reportDir, "urls.txt"), []byte(strings.Join(scan.URLs, "\n")), 0644)
	}
	// Save vulnerabilities
	if len(vuln.Findings) > 0 {
		var lines []string
		for _, f := range vuln.Findings {
			lines = append(lines, fmt.Sprintf("%s\t%s\t%s\t%s\t%.1f", f.Tool, f.Name, f.Severity, f.Target, f.CVSS))
		}
		os.WriteFile(filepath.Join(reportDir, "vulnerabilities.txt"), []byte(strings.Join(lines, "\n")), 0644)
	}
}

func sanitizeFilename(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	return s
}

func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

func stringsToJSONArray(arr []string) string {
	if len(arr) == 0 {
		return "[]"
	}
	var sb strings.Builder
	sb.WriteString("[")
	for i, s := range arr {
		sb.WriteString(fmt.Sprintf("\"%s\"", escapeJSON(s)))
		if i < len(arr)-1 {
			sb.WriteString(",")
		}
	}
	sb.WriteString("]")
	return sb.String()
}

func markdownToHTML(md string) string {
	html := md
	html = strings.ReplaceAll(html, "\n", "<br>\n")
	html = strings.ReplaceAll(html, "# ", "<h1>")
	html = strings.ReplaceAll(html, "## ", "<h2>")
	html = strings.ReplaceAll(html, "### ", "<h3>")
	html = strings.ReplaceAll(html, "#### ", "<h4>")
	html = strings.ReplaceAll(html, "**", "<strong>")
	html = strings.ReplaceAll(html, "*", "<em>")
	html = strings.ReplaceAll(html, "`", "<code>")
	return html
}