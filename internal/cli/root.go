package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"knox-suite/internal/config"
	"knox-suite/internal/llm"
	"knox-suite/internal/report"
	"knox-suite/internal/scanner"
	"knox-suite/internal/tools"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
)

func NewRootCommand(ctx context.Context) *cobra.Command {
	var cfg *config.Config

	rootCmd := &cobra.Command{
		Use:     "knox",
		Short:   "Knox Suite - Lightweight Automated Penetration Testing Suite",
		Long: `Knox Suite is a modular, single-binary CLI suite for automated penetration testing.
Give it a domain, and it runs reconnaissance, vulnerability scanning, and AI-powered analysis.`,
		Version: Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cfg, err = config.Load()
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}
			return nil
		},
	}

	// Global flags
	rootCmd.PersistentFlags().String("target", "", "Target domain (e.g., example.com)")
	rootCmd.PersistentFlags().String("output", "./reports", "Output directory for reports")
	rootCmd.PersistentFlags().String("config", "", "Config file path")
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose logging")
	rootCmd.PersistentFlags().String("anthropic-key", "", "Anthropic API key (or set ANTHROPIC_API_KEY env)")
	rootCmd.PersistentFlags().String("model", "claude-3-5-sonnet-20241022", "Anthropic model to use")
	rootCmd.PersistentFlags().Int("timeout", 300, "Overall timeout in seconds")
	rootCmd.PersistentFlags().Bool("no-ai", false, "Disable AI analysis, only run tools")
	rootCmd.PersistentFlags().String("fail-on", "", "Exit with error code if findings >= severity (critical, high, medium, low)")
	rootCmd.PersistentFlags().String("modules", "", "Comma-separated modules to run (default: all)")

	viper.BindPFlag("target", rootCmd.PersistentFlags().Lookup("target"))
	viper.BindPFlag("output", rootCmd.PersistentFlags().Lookup("output"))
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	viper.BindPFlag("anthropic_key", rootCmd.PersistentFlags().Lookup("anthropic-key"))
	viper.BindPFlag("model", rootCmd.PersistentFlags().Lookup("model"))
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))
	viper.BindPFlag("no_ai", rootCmd.PersistentFlags().Lookup("no-ai"))
	viper.BindPFlag("fail_on", rootCmd.PersistentFlags().Lookup("fail-on"))
	viper.BindPFlag("modules", rootCmd.PersistentFlags().Lookup("modules"))

	// Config file flag
	rootCmd.PersistentFlags().String("config", "", "Config file path")
	viper.BindPFlag("config_file", rootCmd.PersistentFlags().Lookup("config"))

	// Add subcommands
	rootCmd.AddCommand(newScanCommand(ctx, cfg))
	rootCmd.AddCommand(newReconCommand(ctx, cfg))
	rootCmd.AddCommand(newModuleCommand(ctx, cfg))
	rootCmd.AddCommand(newReportCommand(ctx, cfg))
	rootCmd.AddCommand(newVersionCommand())
	rootCmd.AddCommand(newCompletionCommand())

	return rootCmd
}

func newScanCommand(ctx context.Context, cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan [domain]",
		Short: "Run full automated penetration test (recon + vuln scan + AI)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := viper.GetString("target")
			if len(args) > 0 {
				target = args[0]
			}
			if target == "" {
				return fmt.Errorf("target domain is required (use --target or positional argument)")
			}

			target = normalizeTarget(target)

			outputDir := viper.GetString("output")
			verbose := viper.GetBool("verbose")
			noAI := viper.GetBool("no-ai")
			anthropicKey := viper.GetString("anthropic_key")
			model := viper.GetString("model")
			timeoutSec := viper.GetInt("timeout")
			failOn := viper.GetString("fail_on")
			modulesStr := viper.GetString("modules")

			if verbose {
				log.SetLevel(log.DebugLevel)
			}

			printBanner()
			color.Cyan("🎯 Target: %s", target)
			color.Cyan("📁 Output: %s", outputDir)
			color.Cyan("⏱️  Timeout: %ds", timeoutSec)
			if modulesStr != "" {
				color.Cyan("📦 Modules: %s", modulesStr)
			}

			scanCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
			defer cancel()

			runner := tools.NewRunner(scanCtx, verbose)
			availableTools := runner.CheckTools()
			color.Yellow("🔧 Available tools: %s", strings.Join(availableTools, ", "))
			if len(availableTools) == 0 {
				color.Red("⚠️  No security tools found! Install: nmap, nuclei, subfinder, httpx, dnsx, sslscan, whatweb, nikto, dirsearch, ffuf, katana, gau, waybackurls, amass")
				return fmt.Errorf("no tools available")
			}

			// Parse module selection
			selectedModules := parseModules(modulesStr)

			// Run full pipeline
			color.Blue("\n📡 Phase 1: Reconnaissance")
			reconResults, err := scanner.RunReconnaissance(scanCtx, runner, target, selectedModules, verbose)
			if err != nil {
				color.Red("Reconnaissance failed: %v", err)
			}

			color.Blue("\n🔍 Phase 2: Scanning")
			scanResults, err := scanner.RunScanning(scanCtx, runner, target, reconResults, selectedModules, verbose)
			if err != nil {
				color.Red("Scanning failed: %v", err)
			}

			color.Blue("\n🛡️ Phase 3: Vulnerability Assessment")
			vulnResults, err := scanner.RunVulnerabilityScan(scanCtx, runner, target, reconResults, scanResults, selectedModules, verbose)
			if err != nil {
				color.Red("Vulnerability scanning failed: %v", err)
			}

			// Run AI analysis if enabled
			var aiAnalysis string
			if !noAI && anthropicKey != "" {
				color.Blue("\n🤖 Phase 4: AI Analysis")
				analyzer := llm.NewAnalyzer(anthropicKey, model, verbose)
				aiAnalysis, err = analyzer.Analyze(scanCtx, target, reconResults, scanResults, vulnResults)
				if err != nil {
					color.Red("AI analysis failed: %v", err)
				} else {
					color.Green("✅ AI analysis complete")
				}
			} else if noAI {
				color.Yellow("\n⏭️  Skipping AI analysis (--no-ai flag)")
			} else {
				color.Yellow("\n⏭️  Skipping AI analysis (no API key provided)")
			}

			// Generate report
			color.Blue("\n📄 Phase 5: Report Generation")
			reporter := report.NewGenerator(outputDir, target)
			reportPath, err := reporter.Generate(reconResults, scanResults, vulnResults, aiAnalysis)
			if err != nil {
				return fmt.Errorf("failed to generate report: %w", err)
			}

			color.Green("\n✅ Penetration test complete!")
			color.Green("📄 Report saved to: %s", reportPath)

			// Print summary
			printSummary(reconResults, scanResults, vulnResults, aiAnalysis)

			// Check fail-on threshold
			if failOn != "" {
				if checkFailOn(vulnResults, failOn) {
					color.Red("\n❌ Findings exceed threshold: %s", failOn)
					return fmt.Errorf("fail-on threshold exceeded")
				}
			}

			return nil
		},
	}
	return cmd
}

func newReconCommand(ctx context.Context, cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recon [domain]",
		Short: "Run reconnaissance modules only",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := viper.GetString("target")
			if len(args) > 0 {
				target = args[0]
			}
			if target == "" {
				return fmt.Errorf("target domain is required")
			}
			target = normalizeTarget(target)

			verbose := viper.GetBool("verbose")
			outputDir := viper.GetString("output")
			modulesStr := viper.GetString("modules")

			runner := tools.NewRunner(ctx, verbose)
			availableTools := runner.CheckTools()
			color.Yellow("🔧 Available tools: %s", strings.Join(availableTools, ", "))

			color.Blue("📡 Running reconnaissance on: %s", target)
			selectedModules := parseModules(modulesStr)
			results, err := scanner.RunReconnaissance(ctx, runner, target, selectedModules, verbose)
			if err != nil {
				return fmt.Errorf("reconnaissance failed: %w", err)
			}

			reporter := report.NewGenerator(outputDir, target)
			reportPath, err := reporter.GenerateReconOnly(results)
			if err != nil {
				return fmt.Errorf("failed to generate report: %w", err)
			}

			color.Green("✅ Reconnaissance complete!")
			color.Green("📄 Report saved to: %s", reportPath)
			return nil
		},
	}
	return cmd
}

func newModuleCommand(ctx context.Context, cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "module <name> [domain]",
		Short: "Run individual module",
		Args:  cobra.MinimumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return scanner.GetModuleNames(), cobra.ShellCompDirectiveNoFileComp
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			moduleName := args[0]
			target := ""
			if len(args) > 1 {
				target = args[1]
			} else {
				target = viper.GetString("target")
			}
			if target == "" {
				return fmt.Errorf("target domain is required")
			}
			target = normalizeTarget(target)

			verbose := viper.GetBool("verbose")
			outputDir := viper.GetString("output")

			runner := tools.NewRunner(ctx, verbose)
			availableTools := runner.CheckTools()
			color.Yellow("🔧 Available tools: %s", strings.Join(availableTools, ", "))

			color.Blue("📦 Running module '%s' on: %s", moduleName, target)
			results, err := scanner.RunModule(ctx, runner, target, moduleName, verbose)
			if err != nil {
				return fmt.Errorf("module %s failed: %w", moduleName, err)
			}

			reporter := report.NewGenerator(outputDir, target)
			reportPath, err := reporter.GenerateModule(moduleName, results)
			if err != nil {
				return fmt.Errorf("failed to generate report: %w", err)
			}

			color.Green("✅ Module '%s' complete!", moduleName)
			color.Green("📄 Report saved to: %s", reportPath)
			return nil
		},
	}

	// Add list subcommand
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List available modules",
		Run: func(cmd *cobra.Command, args []string) {
			color.Cyan("Available Modules:")
			fmt.Println()
			fmt.Println("  Reconnaissance:")
			fmt.Println("    subdomain  - Subdomain enumeration (subfinder, amass, crt.sh)")
			fmt.Println("    dns        - DNS records (dnsx)")
			fmt.Println("    http       - HTTP probing & tech detection (httpx)")
			fmt.Println("    ssl        - SSL/TLS certificates (sslscan)")
			fmt.Println()
			fmt.Println("  Scanning:")
			fmt.Println("    portscan   - Port scanning (nmap)")
			fmt.Println("    tech       - Technology detection (whatweb)")
			fmt.Println("    dir        - Directory enumeration (dirsearch, ffuf)")
			fmt.Println("    url        - URL discovery (katana, gau, waybackurls)")
			fmt.Println()
			fmt.Println("  Vulnerability:")
			fmt.Println("    vuln       - Vulnerability scanning (nuclei)")
			fmt.Println("    nikto      - Web server scanning (nikto)")
			fmt.Println("    ssl-vuln   - SSL/TLS issues (sslscan)")
		},
	})

	return cmd
}

func newReportCommand(ctx context.Context, cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report <scan-dir>",
		Short: "Generate report from previous scan data",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanDir := args[0]
			outputDir := viper.GetString("output")

			// Load scan data and regenerate report
			color.Blue("📄 Regenerating report from: %s", scanDir)
			// Implementation would load JSON files and regenerate
			color.Yellow("⚠️  Report regeneration from saved data not yet implemented")
			return nil
		},
	}
	return cmd
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Knox Suite version %s (built %s)\n", Version, BuildTime)
		},
	}
}

func newCompletionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion script",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			shell := "bash"
			if len(args) > 0 {
				shell = args[0]
			}
			switch shell {
			case "bash":
				cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				cmd.Root().GenPowerShellCompletion(os.Stdout)
			default:
				fmt.Fprintf(os.Stderr, "Unsupported shell: %s\n", shell)
				os.Exit(1)
			}
		},
	}
}

func parseModules(modulesStr string) []string {
	if modulesStr == "" {
		return nil // nil means all modules
	}
	var modules []string
	for _, m := range strings.Split(modulesStr, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			modules = append(modules, m)
		}
	}
	return modules
}

func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimSuffix(target, "/")
	return target
}

func printBanner() {
	banner := `
   ██╗  ██╗██╗   ██╗███╗   ██╗
   ██║ ██╔╝██║   ██║████╗  ██║
   █████╔╝ ██║   ██║██╔██╗ ██║
   ██╔═██╗ ██║   ██║██║╚██╗██║
   ██║  ██╗╚██████╔╝██║ ╚████║
   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
        Knox Suite v` + Version + `
`
	color.Cyan(banner)
}

func printSummary(recon *scanner.ReconResults, scan *scanner.ScanResults, vuln *scanner.VulnResults, aiAnalysis string) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	color.Cyan("📊 SUMMARY")
	fmt.Println(strings.Repeat("=", 60))

	color.White("Target: %s", recon.Target)
	color.White("Subdomains: %d", len(recon.Subdomains))
	color.White("Live Hosts: %d", len(recon.LiveHosts))
	color.White("Open Ports: %d", len(scan.OpenPorts))
	color.White("Technologies: %d", len(scan.Technologies))
	color.White("Directories: %d", len(scan.Directories))
	color.White("URLs: %d", len(scan.URLs))
	color.White("Vulnerabilities: %d", len(vuln.Findings))

	if len(vuln.Findings) > 0 {
		fmt.Println("\nVulnerabilities by severity:")
		severityCount := make(map[string]int)
		for _, f := range vuln.Findings {
			severityCount[f.Severity]++
		}
		for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
			if count := severityCount[sev]; count > 0 {
				c := color.New(color.FgWhite)
				switch sev {
				case "critical":
					c = color.New(color.FgRed, color.Bold)
				case "high":
					c = color.New(color.FgRed)
				case "medium":
					c = color.New(color.FgYellow)
				case "low":
					c = color.New(color.FgBlue)
				case "info":
					c = color.New(color.FgCyan)
				}
				c.Printf("  %s: %d\n", strings.ToUpper(sev), count)
			}
		}
	}

	if aiAnalysis != "" {
		fmt.Println("\nAI Analysis: Available in full report")
	}
}

func checkFailOn(vuln *scanner.VulnResults, threshold string) bool {
	thresholdOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	thresholdLevel, ok := thresholdOrder[strings.ToLower(threshold)]
	if !ok {
		return false
	}

	for _, f := range vuln.Findings {
		if level, ok := thresholdOrder[f.Severity]; ok && level <= thresholdLevel {
			return true
		}
	}
	return false
}