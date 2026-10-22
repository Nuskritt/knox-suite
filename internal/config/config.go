package config

import (
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	AnthropicKey string
	Model        string
	Timeout      int
	OutputDir    string
	Verbose      bool
	NoAI         bool
	FailOn       string
	Modules      []string
}

func Load() (*Config, error) {
	// Load .env file if exists
	_ = godotenv.Load()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.knox")
	viper.AddConfigPath("/etc/knox/")

	// Read config file if exists
	_ = viper.ReadInConfig()

	// Environment variable bindings
	viper.BindEnv("anthropic_key", "ANTHROPIC_API_KEY")
	viper.BindEnv("model", "ANTHROPIC_MODEL")
	viper.BindEnv("timeout", "KNOX_TIMEOUT")
	viper.BindEnv("output_dir", "KNOX_OUTPUT_DIR")
	viper.BindEnv("verbose", "KNOX_VERBOSE")
	viper.BindEnv("no_ai", "KNOX_NO_AI")
	viper.BindEnv("fail_on", "KNOX_FAIL_ON")

	// Set defaults
	viper.SetDefault("model", "claude-3-5-sonnet-20241022")
	viper.SetDefault("timeout", 300)
	viper.SetDefault("output_dir", "./reports")
	viper.SetDefault("verbose", false)
	viper.SetDefault("no_ai", false)
	viper.SetDefault("fail_on", "")
	viper.SetDefault("modules", []string{})

	cfg := &Config{
		AnthropicKey: viper.GetString("anthropic_key"),
		Model:        viper.GetString("model"),
		Timeout:      viper.GetInt("timeout"),
		OutputDir:    viper.GetString("output_dir"),
		Verbose:      viper.GetBool("verbose"),
		NoAI:         viper.GetBool("no_ai"),
		FailOn:       viper.GetString("fail_on"),
		Modules:      viper.GetStringSlice("modules"),
	}

	// Ensure output directory exists
	if err := os.MkdirAll(cfg.OutputDir, 0755); err != nil {
		return nil, err
	}

	return cfg, nil
}

func DefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".knox", "config.yaml")
}