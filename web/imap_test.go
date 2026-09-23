package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIMAPSecretTransport(t *testing.T) {
	var c confYAML
	if err := json.Unmarshal([]byte(`{"type":"vpn","vpn":{"totp":true,"totp_imap":{"host":"imap.example.com","user":"user@example.com","password":"placeholder-secret"}}}`), &c); err != nil {
		t.Fatal(err)
	}
	cmd := imapCommand(context.Background(), c.VPN.TotpIMAP, "awaiting_code")
	if strings.Contains(strings.Join(cmd.Args, " "), "placeholder-secret") {
		t.Fatal("password in argv")
	}
	input, _ := io.ReadAll(cmd.Stdin)
	if !strings.Contains(string(input), "placeholder-secret") {
		t.Fatal("missing stdin credentials")
	}
	if c.VPN.TotpIMAP.TLS != nil {
		t.Fatal("omitted TLS should use helper default")
	}
}

func TestIMAPPanelWhitelist(t *testing.T) {
	// Exercise the actual config-to-panel mapping with a stub yq.
	dir := t.TempDir()
	script := "#!/bin/sh\ncat <<'JSON'\n" + `{"type":"vpn","vpn":{"totp":true,"totp_imap":{"host":"imap.example.com","password":"placeholder-secret"}}}` + "\nJSON\n"
	if err := os.WriteFile(filepath.Join(dir, "yq"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	d := &Docker{confDir: dir}
	tun := d.tunnelFromConf("example")
	data, err := json.Marshal(tun)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "placeholder-secret") || strings.Contains(string(data), "imap.example.com") {
		t.Fatal("IMAP config exposed to panel")
	}
	var edit confEdit
	if err := json.Unmarshal([]byte(`{"vpn":{"totp_imap":{"password":"placeholder-secret"}}}`), &edit); err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(edit)
	if strings.Contains(string(data), "placeholder-secret") {
		t.Fatal("IMAP secret in editable whitelist")
	}
}

func TestIMAPUsesExistingCodeCommand(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"yq":        "#!/bin/sh\ncat <<'JSON'\n" + `{"type":"vpn","vpn":{"totp":true,"totp_imap":{"host":"imap.example.com","user":"inbox@example.com","password":"placeholder-secret"}}}` + "\nJSON\n",
		"python3":   "#!/bin/sh\ncat >/dev/null\nprintf '004321\\n'\n",
		"t-forward": "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$TEST_DELIVERY\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	markerDir := filepath.Join(dir, "auth-example")
	if err := os.Mkdir(markerDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markerDir, "awaiting_code"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	delivery := filepath.Join(dir, "delivery")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TEST_DELIVERY", delivery)
	d := &Docker{confDir: dir, stateDir: dir, tfPath: filepath.Join(dir, "t-forward"), armed: map[string]bool{}, hub: NewHub()}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.maybeAutoCode(ctx, "example") // No allowTotpCmd: built-in IMAP needs no shell opt-in.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(delivery)
		if string(data) == "code\nexample\n004321\n" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("IMAP source did not invoke existing code command")
}
