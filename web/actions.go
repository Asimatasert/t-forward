package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	// nameRe must forbid a leading '-' so a name can never be parsed as a CLI
	// option (the t-forward CLI has no '--' end-of-options separator: its arg
	// loop dies on any unknown '-*' token). The first char is restricted to
	// alnum/underscore; '.' and '-' are only allowed after it.
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	codeRe = regexp.MustCompile(`^[0-9A-Za-z]{4,}$`)
)

// validName reports whether s is a safe tunnel name to hand to the CLI as an
// argv token: matches nameRe and contains no ".." path/traversal sequence.
func validName(s string) bool {
	return nameRe.MatchString(s) && !strings.Contains(s, "..")
}

// Actions holds the HTTP handlers that shell out to the t-forward CLI.
type Actions struct {
	hub     *Hub
	docker  *Docker
	scanner *Scanner
	tfPath  string // path to the t-forward CLI
}

func NewActions(hub *Hub, d *Docker, sc *Scanner, tfPath string) *Actions {
	return &Actions{hub: hub, docker: d, scanner: sc, tfPath: tfPath}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(r *http.Request) map[string]string {
	m := make(map[string]string)
	if r.Body == nil {
		return m
	}
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
	_ = dec.Decode(&m)
	return m
}

// runTF executes the CLI, streaming each output line as a classified 'event'
// broadcast, and returns the command error (if any).
func (a *Actions) runTF(ctx context.Context, tun string, args ...string) error {
	cmd := exec.CommandContext(ctx, a.tfPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	stream := func(r io.Reader) {
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 32*1024), 512*1024)
		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			if line == "" {
				continue
			}
			a.hub.Broadcast("event", map[string]any{
				"ts":    time.Now().Format(time.RFC3339),
				"level": classify(line),
				"tun":   tun,
				"msg":   line,
			})
		}
		// The scanner may stop early (e.g. bufio.ErrTooLong on a line larger than
		// the 512KB token cap) while the child keeps writing. If we stop reading,
		// the child blocks once the OS pipe buffer fills, the other stream never
		// sees EOF, and cmd.Wait() below hangs forever, pinning the HTTP handler
		// goroutine and leaving the child unreaped. Drain the rest so the child
		// can always make progress to exit (mirrors tailLogs in docker.go).
		_, _ = io.Copy(io.Discard, r)
	}
	done := make(chan struct{}, 2)
	go func() { stream(stdout); done <- struct{}{} }()
	go func() { stream(stderr); done <- struct{}{} }()
	<-done
	<-done
	return cmd.Wait()
}

// handleUp: POST /up {name}
func (a *Actions) handleUp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := decodeBody(r)["name"]
	if !validName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid name"})
		return
	}
	err := a.runTF(r.Context(), name, "up", name, "--no-prompt")
	a.docker.broadcastState()
	if err != nil && exitCode(err) != 3 {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	// exit 3 = detached-TOTP handoff: the container is up and awaiting a
	// verification code (not a failure). The panel shows a code entry.
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "waiting": exitCode(err) == 3})
}

// exitCode returns the process exit code from a run error, or -1 if it isn't one.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// handleDown: POST /down {name|"all"}
func (a *Actions) handleDown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := decodeBody(r)["name"]
	if name != "all" && !validName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid name"})
		return
	}
	err := a.runTF(r.Context(), name, "down", name)
	a.docker.broadcastState()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleCode: POST /code {name,code}
func (a *Actions) handleCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := decodeBody(r)
	a.deliverCode(w, r, body["name"], body["code"])
}

// handleTotp: POST /totp/<name>, code from JSON body {code} or ?code=
func (a *Actions) handleTotp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/totp/")
	name = strings.Trim(name, "/")
	code := r.URL.Query().Get("code")
	if code == "" {
		code = decodeBody(r)["code"]
	}
	a.deliverCode(w, r, name, code)
}

func (a *Actions) deliverCode(w http.ResponseWriter, r *http.Request, name, code string) {
	if !validName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid name"})
		return
	}
	if !codeRe.MatchString(code) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid code"})
		return
	}
	err := a.runTF(r.Context(), name, "code", name, code)
	a.docker.broadcastState()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
