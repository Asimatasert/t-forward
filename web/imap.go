package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"os/exec"
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

func imapCommand(ctx context.Context, config *totpIMAP, marker string) *exec.Cmd {
	input, _ := json.Marshal(config)
	cmd := exec.CommandContext(ctx, "python3", "-c", imapHelper, marker)
	// Secrets stay in memory and an anonymous pipe, never argv or disk.
	cmd.Stdin = bytes.NewReader(input)
	return cmd
}
