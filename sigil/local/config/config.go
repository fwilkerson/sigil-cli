// Package config manages the sigil CLI configuration file.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fwilkerson/sigil-cli/sigil/local/fsutil"
)

// Config holds the trust CLI configuration.
type Config struct {
	// AutoAttest enables automatic positive attestation after tool success.
	// Defaults to true (pit-of-success design).
	AutoAttest *bool `json:"auto_attest,omitempty"`
}

// AutoAttestEnabled returns whether auto-attestation is enabled.
// Defaults to true if not explicitly configured.
func (c *Config) AutoAttestEnabled() bool {
	if c.AutoAttest == nil {
		return true
	}
	return *c.AutoAttest
}

// Dir returns the sigil config directory.
// Uses $XDG_CONFIG_HOME/sigil or ~/.config/sigil as fallback.
func Dir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sigil"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "sigil"), nil
}

// Path returns the path to the config file within the config directory.
func Path(configDir string) string {
	return filepath.Join(configDir, "sigil.json")
}

// Load reads the config from disk. Returns a default config if the file
// does not exist.
func Load(configDir string) (*Config, error) {
	data, err := os.ReadFile(Path(configDir))
	if os.IsNotExist(err) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Save writes the config to disk.
func Save(configDir string, cfg *Config) error {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return fsutil.WriteFileAtomic(Path(configDir), data, 0o600)
}
