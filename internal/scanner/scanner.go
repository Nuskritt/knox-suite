package scanner

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"knox-suite/internal/tools"

	"github.com/charmbracelet/log"
)

// ReconResults holds reconnaissance results
type ReconResults struct {
	Target       string
	Subdomains   []string
	LiveHosts    []HostInfo
	DNSRecords   []DNSRecord
	SSLInfo      []SSLInfo
	Timestamp    time.Time
}

type HostInfo struct {
	Host       string
	IP         string
	StatusCode int
	Title      string
	Tech       []string
}

type DNSRecord struct {
	Domain string
	Type   string
	Value  string
}

type SSLInfo struct {
	Host      string
	Issuer    string
	Subject   string
	NotBefore string
	NotAfter  string
	SANs      []string
}

// ScanResults holds scanning results
type ScanResults struct {
	Target       string
	OpenPorts    []PortInfo
	Technologies []string
	Directories  []DirectoryInfo
	URLs         []string
	Timestamp    time.Time
}

type PortInfo struct {
	Host    string
	Port    int
	Proto   string
	Service string
	State   string
}

type DirectoryInfo struct {
	Path       string
	StatusCode int
	Size       int64
}

// VulnResults holds vulnerability scanning results
type VulnResults struct {
	Target    string
	Findings  []Finding
	Timestamp time.Time
}

type Finding struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Target      string
	Tool        string
	Reference   string
	CVE         string
	CVSS        float64
	Evidence    string
}

// ModuleResult holds results from a single module
type ModuleResult struct {
	ModuleName string
	Data       interface{}
	Error      error
}

// RunReconnaissance runs reconnaissance modules
func RunReconnaissance(ctx context.Context, runner *tools.Runner, target string, selectedModules []string, verbose bool) (*ReconResults, error) {
	results := &ReconResults{
		Target:    target,
		Timestamp: time.Now(),
	}

	// Determine which modules to run
	runSubdomain := shouldRunModule(selectedModules, "subdomain")
	runDNS := shouldRunModule(selectedModules, "dns")
	runHTTP := shouldRunModule(selectedModules, "http")
	runSSL := shouldRunModule(selectedModules, "ssl")

	var wg sync.WaitGroup
	errChan := make(chan error, 10)

	// Subdomain enumeration
	if runSubdomain {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subdomains, err := enumerateSubdomains(ctx, runner, target)
			if err != nil {
				errChan <- fmt.Errorf("subdomain enum: %w", err)
				return
			}
			results.Subdomains = uniqueStrings(subdomains)
			if verbose {
				log.Info("Subdomain enumeration done", "count", len(results.Subdomains))
			}
		}()
	}

	// DNS records
	if runDNS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			records, err := getDNSRecords(ctx, runner, target)
			if err != nil {
				errChan <- fmt.Errorf("dns records: %w", err)
				return
			}
			results.DNSRecords = records
			if verbose {
				log.Info("DNS records done", "count", len(records))
			}
		}()
	}

	// SSL info
	if runSSL {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ssl, err := getSSLInfo(ctx, runner, target)
			if err != nil {
				errChan <- fmt.Errorf("ssl info: %w", err)
				return
			}
			results.SSLInfo = ssl
			if verbose {
				log.Info("SSL info done", "count", len(ssl))
			}
		}()
	}

	// Wait for initial recon
	wg.Wait()
	close(errChan)
	for err := range errChan {
		if verbose {
			log.Warn("Recon error", "err", err)
		}
	}

	// HTTP probing (needs subdomains)
	if runHTTP && len(results.Subdomains) > 0 {
		hosts := probeLiveHosts(ctx, runner, results.Subdomains, verbose)
		results.LiveHosts = hosts
	}

	return results, nil
}

// RunScanning runs scanning modules
func RunScanning(ctx context.Context, runner *tools.Runner, target string, recon *ReconResults, selectedModules []string, verbose bool) (*ScanResults, error) {
	results := &ScanResults{
		Target:    target,
		Timestamp: time.Now(),
	}

	runPortscan := shouldRunModule(selectedModules, "portscan")
	runTech := shouldRunModule(selectedModules, "tech")
	runDir := shouldRunModule(selectedModules, "dir")
	runURL := shouldRunModule(selectedModules, "url")

	var wg sync.WaitGroup

	// Port scan live hosts
	if runPortscan && len(recon.LiveHosts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ports := scanPorts(ctx, runner, recon.LiveHosts, verbose)
			results.OpenPorts = ports
		}()
	}

	// Technology detection
	if runTech && len(recon.LiveHosts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			techs := detectTechnologies(ctx, runner, recon.LiveHosts, verbose)
			results.Technologies = uniqueStrings(techs)
		}()
	}

	// Directory enumeration
	if runDir && len(recon.LiveHosts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dirs := enumerateDirectories(ctx, runner, recon.LiveHosts, verbose)
			results.Directories = dirs
		}()
	}

	// URL discovery
	if runURL && len(recon.LiveHosts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			urls := discoverURLs(ctx, runner, recon.LiveHosts, verbose)
			results.URLs = uniqueStrings(urls)
		}()
	}

	wg.Wait()
	return results, nil
}

// RunVulnerabilityScan runs vulnerability modules
func RunVulnerabilityScan(ctx context.Context, runner *tools.Runner, target string, recon *ReconResults, scan *ScanResults, selectedModules []string, verbose bool) (*VulnResults, error) {
	results := &VulnResults{
		Target:    target,
		Timestamp: time.Now(),
	}

	var findings []Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	runNuclei := shouldRunModule(selectedModules, "vuln")
	runNikto := shouldRunModule(selectedModules, "nikto")
	runSSLVuln := shouldRunModule(selectedModules, "ssl-vuln")

	// Nuclei scan
	if runNuclei && runner.IsToolAvailable("nuclei") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := runNuclei(ctx, runner, target, recon, scan)
			if err != nil {
				if verbose {
					log.Warn("Nuclei scan failed", "err", err)
				}
				return
			}
			mu.Lock()
			findings = append(findings, f...)
			mu.Unlock()
		}()
	}

	// Nikto scan
	if runNikto && runner.IsToolAvailable("nikto") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := runNikto(ctx, runner, recon.LiveHosts)
			if err != nil {
				if verbose {
					log.Warn("Nikto scan failed", "err", err)
				}
				return
			}
			mu.Lock()
			findings = append(findings, f...)
			mu.Unlock()
		}()
	}

	// SSL vulnerability scan
	if runSSLVuln && runner.IsToolAvailable("sslscan") {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := runSSLScanVulns(ctx, runner, recon.SSLInfo)
			if err != nil {
				if verbose {
					log.Warn("SSL vuln scan failed", "err", err)
				}
				return
			}
			mu.Lock()
			findings = append(findings, f...)
			mu.Unlock()
		}()
	}

	wg.Wait()

	// Deduplicate and sort findings
	results.Findings = deduplicateFindings(findings)
	sort.Slice(results.Findings, func(i, j int) bool {
		severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
		return severityOrder[results.Findings[i].Severity] < severityOrder[results.Findings[j].Severity]
	})

	return results, nil
}

// RunModule runs a single module by name
func RunModule(ctx context.Context, runner *tools.Runner, target string, moduleName string, verbose bool) (interface{}, error) {
	switch moduleName {
	case "subdomain":
		subdomains, err := enumerateSubdomains(ctx, runner, target)
		return map[string]interface{}{"subdomains": uniqueStrings(subdomains)}, err
	case "dns":
		records, err := getDNSRecords(ctx, runner, target)
		return map[string]interface{}{"dns_records": records}, err
	case "http":
		subdomains, _ := enumerateSubdomains(ctx, runner, target)
		hosts := probeLiveHosts(ctx, runner, uniqueStrings(subdomains), verbose)
		return map[string]interface{}{"live_hosts": hosts}, err
	case "ssl":
		ssl, err := getSSLInfo(ctx, runner, target)
		return map[string]interface{}{"ssl_info": ssl}, err
	case "portscan":
		subdomains, _ := enumerateSubdomains(ctx, runner, target)
		hosts := probeLiveHosts(ctx, runner, uniqueStrings(subdomains), verbose)
		ports := scanPorts(ctx, runner, hosts, verbose)
		return map[string]interface{}{"open_ports": ports}, err
	case "tech":
		subdomains, _ := enumerateSubdomains(ctx, runner, target)
		hosts := probeLiveHosts(ctx, runner, uniqueStrings(subdomains), verbose)
		techs := detectTechnologies(ctx, runner, hosts, verbose)
		return map[string]interface{}{"technologies": uniqueStrings(techs)}, err
	case "dir":
		subdomains, _ := enumerateSubdomains(ctx, runner, target)
		hosts := probeLiveHosts(ctx, runner, uniqueStrings(subdomains), verbose)
		dirs := enumerateDirectories(ctx, runner, hosts, verbose)
		return map[string]interface{}{"directories": dirs}, err
	case "url":
		subdomains, _ := enumerateSubdomains(ctx, runner, target)
		hosts := probeLiveHosts(ctx, runner, uniqueStrings(subdomains), verbose)
		urls := discoverURLs(ctx, runner, hosts, verbose)
		return map[string]interface{}{"urls": uniqueStrings(urls)}, err
	case "vuln":
		recon, _ := RunReconnaissance(ctx, runner, target, nil, verbose)
		scan, _ := RunScanning(ctx, runner, target, recon, nil, verbose)
		vuln, _ := RunVulnerabilityScan(ctx, runner, target, recon, scan, nil, verbose)
		return map[string]interface{}{"findings": vuln.Findings}, nil
	case "nikto":
		subdomains, _ := enumerateSubdomains(ctx, runner, target)
		hosts := probeLiveHosts(ctx, runner, uniqueStrings(subdomains), verbose)
		findings, err := runNikto(ctx, runner, hosts)
		return map[string]interface{}{"findings": findings}, err
	case "ssl-vuln":
		ssl, _ := getSSLInfo(ctx, runner, target)
		findings, err := runSSLScanVulns(ctx, runner, ssl)
		return map[string]interface{}{"findings": findings}, err
	default:
		return nil, fmt.Errorf("unknown module: %s", moduleName)
	}
}

func GetModuleNames() []string {
	return []string{
		"subdomain", "dns", "http", "ssl",
		"portscan", "tech", "dir", "url",
		"vuln", "nikto", "ssl-vuln",
	}
}

func shouldRunModule(selectedModules []string, moduleName string) bool {
	if selectedModules == nil {
		return true // run all if none specified
	}
	for _, m := range selectedModules {
		if m == moduleName {
			return true
		}
	}
	return false
}

// ... (rest of the helper functions remain the same)

func enumerateSubdomains(ctx context.Context, runner *tools.Runner, target string) ([]string, error) {
	var allSubdomains []string

	// subfinder
	if out, err := runner.Run("subfinder", "-d", target, "-silent"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.HasSuffix(line, "."+target) {
				allSubdomains = append(allSubdomains, line)
			}
		}
	}

	// crt.sh
	if out, err := runner.Run("curl", "-s", fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", target)); err == nil {
		for _, match := range regexp.MustCompile(`"name_value":"([^"]+)"`).FindAllStringSubmatch(out, -1) {
			if len(match) > 1 {
				for _, name := range strings.Split(match[1], "\n") {
					name = strings.TrimSpace(name)
					if name != "" && strings.HasSuffix(name, "."+target) && !strings.HasPrefix(name, "*.") {
						allSubdomains = append(allSubdomains, name)
					}
				}
			}
		}
	}

	// amass (if available)
	if out, err := runner.Run("amass", "enum", "-d", target, "-silent"); err == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && strings.HasSuffix(line, "."+target) {
				allSubdomains = append(allSubdomains, line)
			}
		}
	}

	return uniqueStrings(allSubdomains), nil
}

func getDNSRecords(ctx context.Context, runner *tools.Runner, target string) ([]DNSRecord, error) {
	if !runner.IsToolAvailable("dnsx") {
		return nil, fmt.Errorf("dnsx not available")
	}

	out, err := runner.Run("dnsx", "-d", target, "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-json")
	if err != nil {
		return nil, err
	}

	var records []DNSRecord
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		if h := extractJSON(line, "host"); h != "" {
			rec := DNSRecord{
				Domain: h,
				Type:   extractJSON(line, "type"),
				Value:  extractJSON(line, "value"),
			}
			records = append(records, rec)
		}
	}
	return records, nil
}

func getSSLInfo(ctx context.Context, runner *tools.Runner, target string) ([]SSLInfo, error) {
	if !runner.IsToolAvailable("sslscan") {
		return nil, fmt.Errorf("sslscan not available")
	}

	var sslInfos []SSLInfo
	hosts := []string{target, "www." + target}

	for _, host := range hosts {
		out, err := runner.Run("sslscan", "--no-colour", host+":443")
		if err != nil {
			continue
		}

		info := SSLInfo{Host: host}
		lines := strings.Split(out, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Issuer:") {
				info.Issuer = strings.TrimSpace(strings.TrimPrefix(line, "Issuer:"))
			} else if strings.HasPrefix(line, "Subject:") {
				info.Subject = strings.TrimSpace(strings.TrimPrefix(line, "Subject:"))
			} else if strings.HasPrefix(line, "Not valid before:") {
				info.NotBefore = strings.TrimSpace(strings.TrimPrefix(line, "Not valid before:"))
			} else if strings.HasPrefix(line, "Not valid after:") {
				info.NotAfter = strings.TrimSpace(strings.TrimPrefix(line, "Not valid after:"))
			} else if strings.HasPrefix(line, "Subject Alt Name:") {
				sans := strings.TrimSpace(strings.TrimPrefix(line, "Subject Alt Name:"))
				info.SANs = strings.Split(sans, ", ")
			}
		}
		if info.Issuer != "" || info.Subject != "" {
			sslInfos = append(sslInfos, info)
		}
	}
	return sslInfos, nil
}

func probeLiveHosts(ctx context.Context, runner *tools.Runner, subdomains []string, verbose bool) []HostInfo {
	if !runner.IsToolAvailable("httpx") {
		if verbose {
			log.Warn("httpx not available, skipping live host probe")
		}
		return nil
	}

	input := strings.Join(subdomains, "\n")
	out, err := runner.RunWithStdin("httpx", input, "-silent", "-json", "-title", "-tech-detect", "-status-code", "-follow-redirects", "-timeout", "10")
	if err != nil {
		if verbose {
			log.Warn("httpx failed", "err", err)
		}
		return nil
	}

	var hosts []HostInfo
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		host := parseHTTPXOutput(line)
		if host.Host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func parseHTTPXOutput(line string) HostInfo {
	host := HostInfo{}
	host.Host = extractJSON(line, "url")
	if host.Host == "" {
		host.Host = extractJSON(line, "input")
	}
	host.IP = extractJSON(line, "ip")
	if sc := extractJSON(line, "status_code"); sc != "" {
		fmt.Sscanf(sc, "%d", &host.StatusCode)
	}
	host.Title = extractJSON(line, "title")
	tech := extractJSON(line, "tech")
	if tech != "" {
		host.Tech = strings.Split(tech, ", ")
	}
	return host
}

func scanPorts(ctx context.Context, runner *tools.Runner, hosts []HostInfo, verbose bool) []PortInfo {
	if !runner.IsToolAvailable("nmap") {
		if verbose {
			log.Warn("nmap not available, skipping port scan")
		}
		return nil
	}

	var ports []PortInfo
	for _, host := range hosts {
		target := host.Host
		target = strings.TrimPrefix(target, "http://")
		target = strings.TrimPrefix(target, "https://")
		target = strings.Split(target, "/")[0]

		out, err := runner.Run("nmap", "-sS", "-T4", "--top-ports", "1000", "-oG", "-", target)
		if err != nil {
			if verbose {
				log.Warn("nmap failed", "host", target, "err", err)
			}
			continue
		}

		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "Ports:") {
				portSection := strings.Split(line, "Ports: ")[1]
				for _, p := range strings.Split(portSection, ", ") {
					parts := strings.Split(p, "/")
					if len(parts) >= 5 {
						port := PortInfo{Host: host.Host}
						fmt.Sscanf(parts[0], "%d", &port.Port)
						port.Proto = parts[1]
						port.State = parts[2]
						port.Service = parts[4]
						if port.State == "open" {
							ports = append(ports, port)
						}
					}
				}
			}
		}
	}
	return ports
}

func detectTechnologies(ctx context.Context, runner *tools.Runner, hosts []HostInfo, verbose bool) []string {
	if !runner.IsToolAvailable("whatweb") {
		return nil
	}

	var techs []string
	for _, host := range hosts {
		out, err := runner.Run("whatweb", "--no-errors", "--color=never", host.Host)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "[") {
				re := regexp.MustCompile(`\[([^\]]+)\]`)
				matches := re.FindAllStringSubmatch(line, -1)
				for _, m := range matches {
					if len(m) > 1 {
						techs = append(techs, m[1])
					}
				}
			}
		}
	}
	return techs
}

func enumerateDirectories(ctx context.Context, runner *tools.Runner, hosts []HostInfo, verbose bool) []DirectoryInfo {
	if !runner.IsToolAvailable("dirsearch") && !runner.IsToolAvailable("ffuf") {
		return nil
	}

	var dirs []DirectoryInfo
	wordlist := "/usr/share/wordlists/dirb/common.txt"
	if _, err := runner.Run("ls", wordlist); err != nil {
		wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
	}

	for _, host := range hosts {
		if runner.IsToolAvailable("dirsearch") {
			out, err := runner.Run("dirsearch", "-u", host.Host, "-w", wordlist, "--json-report", "/dev/stdout", "-t", "50")
			if err == nil {
				for _, line := range strings.Split(out, "\n") {
					if strings.HasPrefix(line, "{") {
						path := extractJSON(line, "path")
						status := extractJSON(line, "status")
						size := extractJSON(line, "size")
						if path != "" {
							var sc int
							var sz int64
							fmt.Sscanf(status, "%d", &sc)
							fmt.Sscanf(size, "%d", &sz)
							dirs = append(dirs, DirectoryInfo{Path: path, StatusCode: sc, Size: sz})
						}
					}
				}
			}
		}
	}
	return dirs
}

func discoverURLs(ctx context.Context, runner *tools.Runner, hosts []HostInfo, verbose bool) []string {
	var urls []string

	// katana
	if runner.IsToolAvailable("katana") {
		for _, host := range hosts {
			out, err := runner.Run("katana", "-u", host.Host, "-silent", "-d", "2", "-jc", "-kf", "-retry", "1")
			if err == nil {
				for _, line := range strings.Split(out, "\n") {
					line = strings.TrimSpace(line)
					if line != "" && (strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://")) {
						urls = append(urls, line)
					}
				}
			}
		}
	}

	// gau
	if runner.IsToolAvailable("gau") {
		for _, host := range hosts {
			target := strings.TrimPrefix(host.Host, "http://")
			target = strings.TrimPrefix(target, "https://")
			target = strings.Split(target, "/")[0]
			out, err := runner.Run("gau", target, "--subs")
			if err == nil {
				for _, line := range strings.Split(out, "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						urls = append(urls, line)
					}
				}
			}
		}
	}

	// waybackurls
	if runner.IsToolAvailable("waybackurls") {
		for _, host := range hosts {
			target := strings.TrimPrefix(host.Host, "http://")
			target = strings.TrimPrefix(target, "https://")
			target = strings.Split(target, "/")[0]
			out, err := runner.Run("waybackurls", target)
			if err == nil {
				for _, line := range strings.Split(out, "\n") {
					line = strings.TrimSpace(line)
					if line != "" {
						urls = append(urls, line)
					}
				}
			}
		}
	}

	return uniqueStrings(urls)
}

func runNuclei(ctx context.Context, runner *tools.Runner, target string, recon *ReconResults, scan *ScanResults) ([]Finding, error) {
	if !runner.IsToolAvailable("nuclei") {
		return nil, fmt.Errorf("nuclei not available")
	}

	// Update nuclei templates first
	runner.Run("nuclei", "-update-templates")

	var findings []Finding
	targets := []string{target}
	for _, h := range recon.LiveHosts {
		targets = append(targets, h.Host)
	}
	targets = uniqueStrings(targets)

	input := strings.Join(targets, "\n")
	out, err := runner.RunWithStdin("nuclei", input, "-silent", "-json", "-severity", "critical,high,medium,low,info", "-rate-limit", "100")
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		f := parseNucleiOutput(line)
		if f.Name != "" {
			findings = append(findings, f)
		}
	}
	return findings, nil
}

func parseNucleiOutput(line string) Finding {
	f := Finding{Tool: "nuclei"}
	f.Name = extractJSON(line, "template-id")
	f.Severity = strings.ToLower(extractJSON(line, "info.severity"))
	f.Description = extractJSON(line, "info.name")
	f.Target = extractJSON(line, "host")
	f.Reference = extractJSON(line, "info.reference")
	f.CVE = extractJSON(line, "info.cve")
	if cvss := extractJSON(line, "info.cvss"); cvss != "" {
		fmt.Sscanf(cvss, "%f", &f.CVSS)
	}
	f.Evidence = extractJSON(line, "matched-at")
	return f
}

func runNikto(ctx context.Context, runner *tools.Runner, hosts []HostInfo) ([]Finding, error) {
	if !runner.IsToolAvailable("nikto") {
		return nil, fmt.Errorf("nikto not available")
	}

	var findings []Finding
	for _, host := range hosts {
		out, err := runner.Run("nikto", "-h", host.Host, "-Format", "txt")
		if err != nil {
			continue
		}

		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "+ ") && (strings.Contains(strings.ToLower(line), "vuln") || strings.Contains(strings.ToLower(line), "cve") || strings.Contains(strings.ToLower(line), "outdated")) {
				f := Finding{
					Tool:     "nikto",
					Name:     "Nikto Finding",
					Severity: "medium",
					Target:   host.Host,
					Evidence: strings.TrimSpace(line),
				}
				if strings.Contains(strings.ToLower(line), "critical") {
					f.Severity = "critical"
				} else if strings.Contains(strings.ToLower(line), "high") {
					f.Severity = "high"
				} else if strings.Contains(strings.ToLower(line), "low") {
					f.Severity = "low"
				}
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

func runSSLScanVulns(ctx context.Context, runner *tools.Runner, sslInfos []SSLInfo) ([]Finding, error) {
	if !runner.IsToolAvailable("sslscan") {
		return nil, fmt.Errorf("sslscan not available")
	}

	var findings []Finding
	for _, ssl := range sslInfos {
		f := Finding{
			Tool:        "sslscan",
			Name:        "SSL Certificate Info",
			Severity:    "info",
			Target:      ssl.Host,
			Description: fmt.Sprintf("Issuer: %s, Valid: %s to %s", ssl.Issuer, ssl.NotBefore, ssl.NotAfter),
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	sort.Strings(result)
	return result
}

func deduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]bool)
	var result []Finding
	for _, f := range findings {
		key := f.Tool + "|" + f.Name + "|" + f.Target + "|" + f.Severity
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}
	return result
}

func extractJSON(jsonStr, key string) string {
	patterns := []string{
		fmt.Sprintf(`"%s"\s*:\s*"([^"]*)"`, key),
		fmt.Sprintf(`"%s"\s*:\s*(\d+)`, key),
		fmt.Sprintf(`"%s"\s*:\s*(\d+\.\d+)`, key),
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(jsonStr)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}