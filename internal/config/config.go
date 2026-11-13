// Package config loads teamserver/agent/console configuration from a TOML
// file with environment overrides (RS_<SECTION>_<KEY>) and safe defaults
// (README §11). A missing config file is not an error: flags still apply.
package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"reverseshell/internal/protocol"
)

// Config mirrors config.example.toml.
type Config struct {
	Teamserver Teamserver `toml:"teamserver"`
	Listener   Listener   `toml:"listener"`
	Session    Session    `toml:"session"`
	Agent      Agent      `toml:"agent"`
	Auth       Auth       `toml:"auth"`
	Audit      Audit      `toml:"audit"`
}

// Teamserver holds operator API settings.
type Teamserver struct {
	APIHost       string `toml:"api_host"`
	APIPort       int    `toml:"api_port"`
	OperatorToken string `toml:"operator_token"`
}

// Listener holds the embedded session listener settings.
type Listener struct {
	Host          string `toml:"host"`
	Port          int    `toml:"port"`
	Transport     string `toml:"transport"`
	MaxFrameBytes int    `toml:"max_frame_bytes"`
}

// Session holds liveness tuning handed to agents at registration.
type Session struct {
	HeartbeatInterval float64 `toml:"heartbeat_interval"`
	HeartbeatJitter   float64 `toml:"heartbeat_jitter"`
	StaleMultiplier   float64 `toml:"stale_multiplier"`
}

// Agent holds the implant's connect settings.
type Agent struct {
	ConnectHost   string  `toml:"connect_host"`
	ConnectPort   int     `toml:"connect_port"`
	Transport     string  `toml:"transport"`
	ReconnectBase float64 `toml:"reconnect_base"`
	ReconnectCap  float64 `toml:"reconnect_cap"`
}

// Auth holds shared-secret settings (implant HMAC lands in F3).
type Auth struct {
	ImplantToken string `toml:"implant_token"`
}

// Audit holds audit log settings.
type Audit struct {
	Log string `toml:"log"`
}

// Load reads path when present, then applies env overrides and defaults.
func Load(path string) (Config, error) {
	var cfg Config
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			if _, err := toml.DecodeFile(path, &cfg); err != nil {
				return cfg, fmt.Errorf("parse %s: %w", path, err)
			}
		} else if !os.IsNotExist(err) {
			return cfg, fmt.Errorf("stat %s: %w", path, err)
		}
	}
	applyEnv(&cfg)
	applyDefaults(&cfg)
	return cfg, nil
}

// applyEnv maps RS_<SECTION>_<KEY> onto matching fields, using the toml tags
// so the env key matches the documented config key exactly.
func applyEnv(cfg *Config) {
	applyEnvTo(reflect.ValueOf(cfg).Elem(), "")
}

func applyEnvTo(v reflect.Value, prefix string) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		fv := v.Field(i)
		tag := f.Tag.Get("toml")
		if tag == "" {
			tag = f.Name
		}
		if f.Type.Kind() == reflect.Struct {
			applyEnvTo(fv, prefix+strings.ToUpper(tag)+"_")
			continue
		}
		raw, ok := os.LookupEnv("RS_" + prefix + strings.ToUpper(tag))
		if !ok || raw == "" {
			continue
		}
		switch fv.Kind() {
		case reflect.String:
			fv.SetString(raw)
		case reflect.Int:
			if n, err := strconv.Atoi(raw); err == nil {
				fv.SetInt(int64(n))
			}
		case reflect.Float64:
			if n, err := strconv.ParseFloat(raw, 64); err == nil {
				fv.SetFloat(n)
			}
		}
	}
}

func applyDefaults(c *Config) {
	if c.Teamserver.APIHost == "" {
		c.Teamserver.APIHost = "127.0.0.1"
	}
	if c.Teamserver.APIPort == 0 {
		c.Teamserver.APIPort = 5555
	}
	if c.Listener.Host == "" {
		c.Listener.Host = "127.0.0.1"
	}
	if c.Listener.Port == 0 {
		c.Listener.Port = 4444
	}
	if c.Listener.Transport == "" {
		c.Listener.Transport = "tcp"
	}
	if c.Listener.MaxFrameBytes == 0 {
		c.Listener.MaxFrameBytes = protocol.DefaultMaxFrameBytes
	}
	if c.Session.HeartbeatInterval == 0 {
		c.Session.HeartbeatInterval = 15
	}
	if c.Session.HeartbeatJitter == 0 {
		c.Session.HeartbeatJitter = 0.2
	}
	if c.Session.StaleMultiplier == 0 {
		c.Session.StaleMultiplier = 3
	}
	if c.Agent.ConnectHost == "" {
		c.Agent.ConnectHost = "127.0.0.1"
	}
	if c.Agent.ConnectPort == 0 {
		c.Agent.ConnectPort = 4444
	}
	if c.Agent.Transport == "" {
		c.Agent.Transport = "tcp"
	}
	if c.Agent.ReconnectBase == 0 {
		c.Agent.ReconnectBase = 1
	}
	if c.Agent.ReconnectCap == 0 {
		c.Agent.ReconnectCap = 300
	}
	if c.Audit.Log == "" {
		c.Audit.Log = "logs/audit.jsonl"
	}
}
