package tools

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/log"
)

type Runner struct {
	ctx    context.Context
	verbose bool
}

func NewRunner(ctx context.Context, verbose bool) *Runner {
	return &Runner{
		ctx:     ctx,
		verbose: verbose,
	}
}

func (r *Runner) CheckTools() []string {
	tools := []string{
		"nmap",
		"nuclei",
		"subfinder",
		"httpx",
		"dnsx",
		"sslscan",
		"whatweb",
		"nikto",
		"dirsearch",
		"sqlmap",
		"ffuf",
		"katana",
		"gau",
		"waybackurls",
	}
	var available []string
	for _, tool := range tools {
		if r.isToolAvailable(tool) {
			available = append(available, tool)
		}
	}
	return available
}

func (r *Runner) IsToolAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (r *Runner) isToolAvailable(name string) bool {
	return r.IsToolAvailable(name)
}

func (r *Runner) Run(name string, args ...string) (string, error) {
	if r.verbose {
		log.Debug("Running", "tool", name, "args", args)
	}

	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()

	if r.verbose {
		log.Debug("Tool output", "tool", name, "output", string(output)[:min(500, len(output))])
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%s: timeout", name)
		}
		return "", fmt.Errorf("%s: %w\nOutput: %s", name, err, string(output))
	}

	return string(output), nil
}

func (r *Runner) RunWithStdin(name string, stdin string, args ...string) (string, error) {
	if r.verbose {
		log.Debug("Running with stdin", "tool", name, "args", args)
	}

	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("%s: timeout", name)
		}
		return "", fmt.Errorf("%s: %w\nOutput: %s", name, err, string(output))
	}

	return string(output), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func GetToolVersion(name string) string {
	cmd := exec.Command(name, "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return "unknown"
}

func CheckRuntime() {
	if runtime.GOOS == "windows" {
		log.Warn("Running on Windows - some tools may not be available")
	}
}