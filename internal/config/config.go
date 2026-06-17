package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// Default locations. Overridable via env for development.
const (
	DefaultDir = "/etc/sshtunnel-panel"
	DefaultData = "/var/lib/sshtunnel-panel"
)

// Config holds panel-wide settings (not per-tunnel).
type Config struct {
	Listen        string `json:"listen"`         // e.g. "0.0.0.0:2095"
	BasePath      string `json:"base_path"`      // e.g. "/secretpath" or ""
	DataDir       string `json:"data_dir"`       // where store + run files live
	SessionSecret string `json:"session_secret"` // random, signs session cookies
	NodeToken     string `json:"node_token"`     // bearer token for master->node API calls
	MasterEnabled bool   `json:"master_enabled"` // show the central multi-node dashboard
	TLSCert       string `json:"tls_cert"`       // optional path to cert
	TLSKey        string `json:"tls_key"`        // optional path to key

	path string `json:"-"`
}

// Dir returns the config directory (honouring SSHTP_CONFIG_DIR for dev).
func Dir() string {
	if d := os.Getenv("SSHTP_CONFIG_DIR"); d != "" {
		return d
	}
	return DefaultDir
}

// Path is the full path to config.json.
func Path() string { return filepath.Join(Dir(), "config.json") }

// Load reads config.json, creating a default one if missing.
func Load() (*Config, error) {
	p := Path()
	c := &Config{path: p}
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		applyDefaults(c)
		if err := os.MkdirAll(Dir(), 0o700); err != nil {
			return nil, err
		}
		if err := c.Save(); err != nil {
			return nil, err
		}
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	c.path = p
	// Persist any newly-generated secrets (e.g. node_token added to an older
	// config) so every process reads the same value.
	before := c.NodeToken + "|" + c.SessionSecret
	applyDefaults(c)
	if c.NodeToken+"|"+c.SessionSecret != before {
		_ = c.Save()
	}
	return c, nil
}

func applyDefaults(c *Config) {
	if c.Listen == "" {
		c.Listen = "0.0.0.0:2095"
	}
	if c.DataDir == "" {
		c.DataDir = DefaultData
		if d := os.Getenv("SSHTP_DATA_DIR"); d != "" {
			c.DataDir = d
		}
	}
	if c.SessionSecret == "" {
		c.SessionSecret = randHex(32)
	}
	if c.NodeToken == "" {
		c.NodeToken = randHex(24)
	}
	c.BasePath = NormalizeBasePath(c.BasePath)
}

// NormalizeBasePath ensures the path is either "" or "/foo" with no trailing slash.
func NormalizeBasePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	return "/" + p
}

// Save persists the config to disk (mode 0600).
func (c *Config) Save() error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0o600)
}

// RunDir holds per-tunnel stat files written by runners.
func (c *Config) RunDir() string { return filepath.Join(c.DataDir, "run") }

// StorePath is the JSON database file.
func (c *Config) StorePath() string { return filepath.Join(c.DataDir, "store.json") }

// KeysDir holds generated private keys per tunnel.
func (c *Config) KeysDir() string { return filepath.Join(c.DataDir, "keys") }

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
