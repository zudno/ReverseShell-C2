package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileAppliesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listener.Host != "127.0.0.1" || cfg.Listener.Port != 4444 {
		t.Fatalf("listener defaults = %+v", cfg.Listener)
	}
	if cfg.Teamserver.APIHost != "127.0.0.1" || cfg.Teamserver.APIPort != 5555 {
		t.Fatalf("api defaults = %+v", cfg.Teamserver)
	}
	if cfg.Listener.Transport != "tcp" {
		t.Fatalf("transport default = %q", cfg.Listener.Transport)
	}
	if cfg.Session.HeartbeatInterval != 15 || cfg.Session.HeartbeatJitter != 0.2 {
		t.Fatalf("session defaults = %+v", cfg.Session)
	}
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	body := "[listener]\nport = 5599\n\n[teamserver]\noperator_token = \"secret\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listener.Port != 5599 {
		t.Fatalf("port = %d", cfg.Listener.Port)
	}
	if cfg.Teamserver.OperatorToken != "secret" {
		t.Fatalf("token = %q", cfg.Teamserver.OperatorToken)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	t.Setenv("RS_LISTENER_PORT", "6001")
	t.Setenv("RS_TEAMSERVER_OPERATOR_TOKEN", "env-token")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listener.Port != 6001 {
		t.Fatalf("port = %d", cfg.Listener.Port)
	}
	if cfg.Teamserver.OperatorToken != "env-token" {
		t.Fatalf("token = %q", cfg.Teamserver.OperatorToken)
	}
}

func TestLoadExampleTemplateParses(t *testing.T) {
	if _, err := Load("../../config.example.toml"); err != nil {
		t.Fatalf("example template does not parse: %v", err)
	}
}
