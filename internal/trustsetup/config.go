package trustsetup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fwilkerson/sigil-cli/internal/fsutil"
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

// ConfigDir returns the sigil config directory.
// Uses $XDG_CONFIG_HOME/sigil or ~/.config/sigil as fallback.
func ConfigDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sigil"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "sigil"), nil
}

// ConfigPath returns the path to the config file within the config directory.
func ConfigPath(configDir string) string {
	return filepath.Join(configDir, "skill.json")
}

// LoadConfig reads the config from disk. Returns a default config if the file
// does not exist.
func LoadConfig(configDir string) (*Config, error) {
	data, err := os.ReadFile(ConfigPath(configDir))
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

// SaveConfig writes the config to disk.
func SaveConfig(configDir string, cfg *Config) error {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return fsutil.WriteFileAtomic(ConfigPath(configDir), data, 0o600)
}

// BoolPtr returns a pointer to b.
func BoolPtr(b bool) *bool { return &b }
