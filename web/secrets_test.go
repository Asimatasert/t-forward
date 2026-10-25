package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTelegramErrorDoesNotLeakToken(t *testing.T) {
	old := telegramAPI
	telegramAPI = "http://127.0.0.1:1" // closed port: connection refused
	defer func() { telegramAPI = old }()
	const token = "123456:AAH-secret-token"
	err := sendTelegram(token, "42", "", "hi")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "AAH-secret") {
		t.Fatalf("bot token leaked in error: %v", err)
	}
}

func TestIMAPHelperIgnoresShadowedStdlib(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	poison := t.TempDir()
	pwned := filepath.Join(poison, "pwned")
	shadow := "open(" + strconv.Quote(pwned) + ", 'w').write('x')\n"
	if err := os.WriteFile(filepath.Join(poison, "json.py"), []byte(shadow), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PYTHONPATH", poison) // would put json.py ahead of the stdlib
	cmd := imapCommand(context.Background(), &totpIMAP{}, filepath.Join(poison, "marker"))
	cmd.Stdin = strings.NewReader("{}")
	_, _ = cmd.CombinedOutput() // exits 1 quietly on the empty config; only the import side effect matters
	if _, err := os.Stat(pwned); err == nil {
		t.Fatal("shadowed json.py from PYTHONPATH was imported by the IMAP helper")
	}
	if cmd.Dir != "/" {
		t.Fatalf("helper cwd should be pinned, got %q", cmd.Dir)
	}
}
