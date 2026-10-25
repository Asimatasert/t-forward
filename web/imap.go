package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"os/exec"
	"path/filepath"
)

// Embedded so installations of the daemon do not need a separate helper file.
//
//go:embed helpers/totp_imap.py
var imapHelper string

// This schema is private configuration, never part of Tunnel or confEdit.
type totpIMAP struct {
	Host       string `json:"host"`
	Port       int    `json:"port,omitempty"`
	User       string `json:"user"`
	Password   string `json:"password"`
	Mailbox    string `json:"mailbox,omitempty"`
	FromFilter string `json:"from_filter,omitempty"`
	TLS        *bool  `json:"tls,omitempty"`
}

// absPath makes the marker path independent of the working directory the helper
// is started in.
func absPath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

func imapCommand(ctx context.Context, config *totpIMAP, marker string) *exec.Cmd {
	input, _ := json.Marshal(config)
	// -I (isolated mode) drops the script directory / cwd from sys.path and
	// ignores PYTHONPATH and the user site, so a stray json.py / ssl.py in the
	// daemon's working directory or environment can never shadow the stdlib
	// modules that receive the IMAP password. The working directory is pinned
	// to the filesystem root for the same reason.
	cmd := exec.CommandContext(ctx, "python3", "-I", "-c", imapHelper, absPath(marker))
	cmd.Dir = "/"
	// Secrets stay in memory and an anonymous pipe, never argv or disk.
	cmd.Stdin = bytes.NewReader(input)
	return cmd
}
