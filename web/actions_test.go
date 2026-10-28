package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ------------------------------------------------------------------ helpers

// actEnv is an Actions wired to a temp config tree, a real Hub and a Docker
// that shares them. Used by the actions/notify/settings tests.
type actEnv struct {
	a    *Actions
	d    *Docker
	hub  *Hub
	root string // parent of conf.d: settings.json / panel-layout.json live here
}

func newActEnv(t *testing.T) *actEnv {
	t.Helper()
	root := t.TempDir()
	hub := NewHub()
	d := NewDocker(hub, root, "t-forward")
	a := NewActions(hub, d, nil, "")
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a.gate.now = func() time.Time { return clock }
	return &actEnv{a: a, d: d, hub: hub, root: root}
}

// writeStubCLI writes an executable shell script standing in for the t-forward
// CLI and returns its path. Skipped where no POSIX sh exists.
func writeStubCLI(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs need a POSIX sh")
	}
	p := filepath.Join(t.TempDir(), "t-forward")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// useStubCLI points e.a at a stub CLI that appends its argv (one line per
// invocation) to the returned log file, prints one stdout and one stderr line,
// and exits with the given code.
func (e *actEnv) useStubCLI(t *testing.T, exit int) (logFile string) {
	t.Helper()
	logFile = filepath.Join(t.TempDir(), "calls.log")
	e.a.tfPath = writeStubCLI(t, fmt.Sprintf(
		"echo \"$*\" >> %q\necho \"hello stdout\"\necho \"ERROR boom\" >&2\nexit %d\n", logFile, exit))
	return logFile
}

// calls returns the recorded CLI invocations.
func calls(t *testing.T, logFile string) []string {
	t.Helper()
	b, err := os.ReadFile(logFile)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

func doReq(h http.HandlerFunc, method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func jsonBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not a JSON object: %v\n%s", err, rec.Body.String())
	}
	return m
}

// drainEvents returns every pending 'event' frame on the client as a map.
func drainEvents(c *client) []map[string]any {
	var out []map[string]any
	for {
		select {
		case f := <-c.lossy:
			s := string(f)
			const head = "event: event\ndata: "
			if !strings.HasPrefix(s, head) {
				continue
			}
			var m map[string]any
			if json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimPrefix(s, head), "\n\n")), &m) == nil {
				out = append(out, m)
			}
		default:
			return out
		}
	}
}

func hasStateFrame(c *client) bool {
	select {
	case <-c.state:
		return true
	default:
		return false
	}
}

// ------------------------------------------------------------ pure helpers

func TestActionsValidName(t *testing.T) {
	good := []string{"a", "prod", "prod-eu", "prod_eu", "prod.eu", "A1_b-2.c", "_x", "0day", "a-b-c"}
	for _, s := range good {
		if !validName(s) {
			t.Errorf("validName(%q) = false, want true", s)
		}
	}
	bad := map[string]string{
		"":          "empty",
		"-x":        "leading dash would parse as a CLI option",
		"--help":    "option-looking",
		"-":         "lone dash",
		".hidden":   "leading dot",
		"a..b":      "traversal sequence inside",
		"..":        "traversal",
		"a/b":       "path separator",
		"a\\b":      "backslash",
		"a b":       "space",
		"a;rm":      "shell metachar",
		"a$(x)":     "substitution",
		"a\n":       "trailing newline",
		"a\nb":      "embedded newline",
		"çay":       "non-ASCII",
		"a=b":       "equals",
		"a\x00b":    "NUL",
		"all/../..": "traversal with separators",
	}
	for s, why := range bad {
		if validName(s) {
			t.Errorf("validName(%q) = true, want false (%s)", s, why)
		}
	}
}

func TestActionsCodeRe(t *testing.T) {
	for _, s := range []string{"1234", "123456", "abcd", "AbC123", "0000000000"} {
		if !codeRe.MatchString(s) {
			t.Errorf("codeRe(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "1", "123", "12 34", "12-34", "123456\n", "12;34", "-1234", "١٢٣٤"} {
		if codeRe.MatchString(s) {
			t.Errorf("codeRe(%q) = true, want false", s)
		}
	}
}

func TestActionsWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusTeapot, map[string]any{"ok": false, "error": "x"})
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	m := jsonBody(t, rec)
	if m["ok"] != false || m["error"] != "x" {
		t.Errorf("body = %v", m)
	}
}

func TestActionsDecodeBody(t *testing.T) {
	t.Run("nil body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		r.Body = nil
		if m := decodeBody(r); m == nil || len(m) != 0 {
			t.Errorf("got %v, want empty non-nil map", m)
		}
	})
	t.Run("valid", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"name":"prod","code":"1234"}`))
		m := decodeBody(r)
		if m["name"] != "prod" || m["code"] != "1234" {
			t.Errorf("got %v", m)
		}
	})
	t.Run("malformed yields empty map, no panic", func(t *testing.T) {
		for _, body := range []string{"", "not json", `{"name":`, `[1,2]`, `null`} {
			r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
			m := decodeBody(r)
			// `null` decodes to a nil map; reads on it are still safe
			if len(m) != 0 || m["name"] != "" {
				t.Errorf("body %q -> %v", body, m)
			}
		}
	})
	t.Run("body capped at 64 KiB", func(t *testing.T) {
		body := `{"name":"prod","pad":"` + strings.Repeat("a", 70<<10) + `"}`
		m := decodeBody(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body)))
		if len(m["pad"]) != 0 {
			t.Errorf("oversized value was fully read (%d bytes)", len(m["pad"]))
		}
	})
}

func TestActionsExitCode(t *testing.T) {
	if got := exitCode(nil); got != -1 {
		t.Errorf("exitCode(nil) = %d, want -1", got)
	}
	if got := exitCode(fmt.Errorf("plain")); got != -1 {
		t.Errorf("exitCode(non-exit error) = %d, want -1", got)
	}
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	err := exec.Command("sh", "-c", "exit 3").Run()
	if got := exitCode(err); got != 3 {
		t.Errorf("exitCode(exit 3) = %d, want 3", got)
	}
	// wrapped errors are still recognised
	if got := exitCode(fmt.Errorf("wrapped: %w", err)); got != 3 {
		t.Errorf("exitCode(wrapped exit 3) = %d, want 3", got)
	}
}

func TestActionsOpCtx(t *testing.T) {
	a := NewActions(NewHub(), nil, nil, "")
	if a.opCtx() == nil {
		t.Fatal("opCtx() = nil without baseCtx")
	}
	type key struct{}
	ctx := context.WithValue(context.Background(), key{}, "daemon")
	a.baseCtx = ctx
	if a.opCtx().Value(key{}) != "daemon" {
		t.Error("opCtx() must return the daemon-lifetime baseCtx when set")
	}
}

// ------------------------------------------------------------------- runTF

func TestActionsRunTFStreamsClassifiedEvents(t *testing.T) {
	e := newActEnv(t)
	e.a.tfPath = writeStubCLI(t, "echo 'tunnel is up'\necho ''\necho 'waiting for code' >&2\necho 'ERROR boom' >&2\necho 'plain line'\nprintf 'crlf line\\r\\n'\n")
	c := e.hub.register()

	if err := e.a.runTF(context.Background(), "prod", "up", "prod"); err != nil {
		t.Fatalf("runTF: %v", err)
	}
	got := map[string]map[string]any{}
	for _, ev := range drainEvents(c) {
		got[ev["msg"].(string)] = ev
	}
	want := map[string]string{
		"tunnel is up":     "tunnel",
		"waiting for code": "auth",
		"ERROR boom":       "error",
		"plain line":       "log",
		"crlf line":        "log", // trailing \r is trimmed
	}
	if len(got) != len(want) {
		t.Fatalf("got %d events %v, want %d (blank lines must be skipped)", len(got), got, len(want))
	}
	for msg, level := range want {
		ev, ok := got[msg]
		if !ok {
			t.Errorf("missing event for %q", msg)
			continue
		}
		if ev["level"] != level {
			t.Errorf("%q level = %v, want %s", msg, ev["level"], level)
		}
		if ev["tun"] != "prod" {
			t.Errorf("%q tun = %v, want prod", msg, ev["tun"])
		}
		ts, _ := ev["ts"].(string)
		if _, err := time.Parse(time.RFC3339, ts); err != nil {
			t.Errorf("%q ts = %q: %v", msg, ts, err)
		}
	}
}

func TestActionsRunTFReturnsExitError(t *testing.T) {
	e := newActEnv(t)
	e.useStubCLI(t, 3)
	err := e.a.runTF(context.Background(), "prod", "up", "prod")
	if err == nil || exitCode(err) != 3 {
		t.Fatalf("err = %v (exit %d), want exit status 3", err, exitCode(err))
	}
}

func TestActionsRunTFStartFailure(t *testing.T) {
	e := newActEnv(t)
	e.a.tfPath = filepath.Join(t.TempDir(), "does-not-exist")
	err := e.a.runTF(context.Background(), "prod", "up", "prod")
	if err == nil {
		t.Fatal("expected a start error for a missing CLI")
	}
	if exitCode(err) != -1 {
		t.Errorf("a start failure must not look like a CLI exit code, got %d", exitCode(err))
	}
}

func TestActionsRunTFContextCancelKillsChild(t *testing.T) {
	e := newActEnv(t)
	e.a.tfPath = writeStubCLI(t, "exec sleep 30\n")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- e.a.runTF(ctx, "prod", "up", "prod") }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("expected an error from a killed child")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runTF did not return after context cancellation")
	}
}

// A line longer than the 512 KiB scanner cap must not wedge the handler: the
// rest of the output is drained so the child can exit and Wait returns.
func TestActionsRunTFDrainsOversizedLine(t *testing.T) {
	e := newActEnv(t)
	e.a.tfPath = writeStubCLI(t, "head -c 1200000 /dev/zero | tr '\\0' a\necho\necho after\n")
	done := make(chan error, 1)
	go func() { done <- e.a.runTF(context.Background(), "prod", "up", "prod") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runTF: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("runTF hung on an oversized output line")
	}
}

// ---------------------------------------------------------------- /up /down

func TestActionsHandleUp(t *testing.T) {
	stubDocker(t)

	t.Run("method not allowed", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			rec := doReq(e.a.handleUp, m, "/up", `{"name":"prod"}`)
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want 405", m, rec.Code)
			}
		}
		if n := calls(t, log); len(n) != 0 {
			t.Errorf("CLI ran on a rejected method: %v", n)
		}
	})

	t.Run("invalid name never reaches the CLI", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		c := e.hub.register()
		for _, body := range []string{``, `{}`, `{"name":""}`, `{"name":"-rf"}`, `{"name":"--help"}`, `{"name":"a..b"}`, `{"name":"a b"}`, `{"name":"all/../x"}`, `garbage`} {
			rec := doReq(e.a.handleUp, http.MethodPost, "/up", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body %q: status = %d, want 400", body, rec.Code)
			}
			m := jsonBody(t, rec)
			if m["ok"] != false || m["error"] != "invalid name" {
				t.Errorf("body %q: response = %v", body, m)
			}
		}
		if n := calls(t, log); len(n) != 0 {
			t.Errorf("CLI ran for invalid names: %v", n)
		}
		if hasStateFrame(c) {
			t.Error("state broadcast for a rejected request")
		}
	})

	t.Run("success runs up <name> --no-prompt and rebroadcasts state", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		c := e.hub.register()
		rec := doReq(e.a.handleUp, http.MethodPost, "/up", `{"name":"prod-eu"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		m := jsonBody(t, rec)
		if m["ok"] != true || m["waiting"] != false {
			t.Errorf("response = %v, want ok:true waiting:false", m)
		}
		if got := calls(t, log); len(got) != 1 || got[0] != "up prod-eu --no-prompt" {
			t.Errorf("CLI calls = %q", got)
		}
		if !hasStateFrame(c) {
			t.Error("no state broadcast after up")
		}
	})

	t.Run("exit 3 means waiting for a TOTP code, not failure", func(t *testing.T) {
		e := newActEnv(t)
		e.useStubCLI(t, 3)
		m := jsonBody(t, doReq(e.a.handleUp, http.MethodPost, "/up", `{"name":"prod"}`))
		if m["ok"] != true || m["waiting"] != true {
			t.Errorf("response = %v, want ok:true waiting:true", m)
		}
	})

	t.Run("other non-zero exit is reported as failure", func(t *testing.T) {
		e := newActEnv(t)
		e.useStubCLI(t, 1)
		c := e.hub.register()
		rec := doReq(e.a.handleUp, http.MethodPost, "/up", `{"name":"prod"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (failures are reported in the body)", rec.Code)
		}
		m := jsonBody(t, rec)
		if m["ok"] != false || !strings.Contains(fmt.Sprint(m["error"]), "exit status 1") {
			t.Errorf("response = %v", m)
		}
		if _, has := m["waiting"]; has {
			t.Errorf("failure response must not carry waiting: %v", m)
		}
		if !hasStateFrame(c) {
			t.Error("state must be rebroadcast even when up fails")
		}
	})

	t.Run("missing CLI binary is a failure", func(t *testing.T) {
		e := newActEnv(t)
		e.a.tfPath = filepath.Join(t.TempDir(), "nope")
		m := jsonBody(t, doReq(e.a.handleUp, http.MethodPost, "/up", `{"name":"prod"}`))
		if m["ok"] != false || m["error"] == "" {
			t.Errorf("response = %v", m)
		}
	})

	t.Run("client disconnect does not abort the CLI", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // the HTTP client is already gone
		req := httptest.NewRequest(http.MethodPost, "/up", strings.NewReader(`{"name":"prod"}`)).WithContext(ctx)
		rec := httptest.NewRecorder()
		e.a.handleUp(rec, req)
		if m := jsonBody(t, rec); m["ok"] != true {
			t.Errorf("response = %v, want ok:true (mutations run on baseCtx)", m)
		}
		if got := calls(t, log); len(got) != 1 {
			t.Errorf("CLI calls = %q", got)
		}
	})

	t.Run("a cancelled daemon context aborts the CLI", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		e.a.baseCtx = ctx
		m := jsonBody(t, doReq(e.a.handleUp, http.MethodPost, "/up", `{"name":"prod"}`))
		if m["ok"] != false {
			t.Errorf("response = %v, want ok:false", m)
		}
		if got := calls(t, log); len(got) != 0 {
			t.Errorf("CLI started on a cancelled context: %q", got)
		}
	})
}

func TestActionsHandleDown(t *testing.T) {
	stubDocker(t)

	t.Run("method not allowed", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		if rec := doReq(e.a.handleDown, http.MethodGet, "/down", `{"name":"prod"}`); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
		if n := calls(t, log); len(n) != 0 {
			t.Errorf("CLI ran: %v", n)
		}
	})

	t.Run("invalid names are rejected, 'all' is allowed", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		for _, body := range []string{``, `{"name":""}`, `{"name":"-all"}`, `{"name":"ALL!"}`, `{"name":"a..b"}`, `{"name":"a/b"}`} {
			rec := doReq(e.a.handleDown, http.MethodPost, "/down", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body %q: status = %d, want 400", body, rec.Code)
			}
		}
		if n := calls(t, log); len(n) != 0 {
			t.Fatalf("CLI ran for invalid names: %v", n)
		}
		m := jsonBody(t, doReq(e.a.handleDown, http.MethodPost, "/down", `{"name":"all"}`))
		if m["ok"] != true {
			t.Errorf("down all: %v", m)
		}
		if got := calls(t, log); len(got) != 1 || got[0] != "down all" {
			t.Errorf("CLI calls = %q, want [down all]", got)
		}
	})

	t.Run("success runs down <name>", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		c := e.hub.register()
		m := jsonBody(t, doReq(e.a.handleDown, http.MethodPost, "/down", `{"name":"prod"}`))
		if m["ok"] != true {
			t.Errorf("response = %v", m)
		}
		if got := calls(t, log); len(got) != 1 || got[0] != "down prod" {
			t.Errorf("CLI calls = %q", got)
		}
		if !hasStateFrame(c) {
			t.Error("no state broadcast after down")
		}
	})

	t.Run("exit 3 is a failure for down (only up treats it as waiting)", func(t *testing.T) {
		e := newActEnv(t)
		e.useStubCLI(t, 3)
		m := jsonBody(t, doReq(e.a.handleDown, http.MethodPost, "/down", `{"name":"prod"}`))
		if m["ok"] != false || !strings.Contains(fmt.Sprint(m["error"]), "exit status 3") {
			t.Errorf("response = %v", m)
		}
	})
}

// ------------------------------------------------------------ /code /totp

func TestActionsHandleCode(t *testing.T) {
	stubDocker(t)

	t.Run("method not allowed", func(t *testing.T) {
		e := newActEnv(t)
		e.useStubCLI(t, 0)
		if rec := doReq(e.a.handleCode, http.MethodGet, "/code", `{"name":"prod","code":"123456"}`); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("validation", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		cases := []struct{ body, err string }{
			{`{"code":"123456"}`, "invalid name"},
			{`{"name":"-x","code":"123456"}`, "invalid name"},
			{`{"name":"a..b","code":"123456"}`, "invalid name"},
			{`{"name":"prod"}`, "invalid code"},
			{`{"name":"prod","code":"123"}`, "invalid code"},
			{`{"name":"prod","code":"12 34 56"}`, "invalid code"},
			{`{"name":"prod","code":"12;rm"}`, "invalid code"},
			{`{"name":"prod","code":"-12345"}`, "invalid code"},
			{`not json`, "invalid name"},
		}
		for _, tc := range cases {
			rec := doReq(e.a.handleCode, http.MethodPost, "/code", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", tc.body, rec.Code)
			}
			if m := jsonBody(t, rec); m["ok"] != false || m["error"] != tc.err {
				t.Errorf("%s: response = %v, want error %q", tc.body, m, tc.err)
			}
		}
		if n := calls(t, log); len(n) != 0 {
			t.Errorf("CLI ran for invalid input: %v", n)
		}
	})

	t.Run("success passes name and code as argv", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		c := e.hub.register()
		m := jsonBody(t, doReq(e.a.handleCode, http.MethodPost, "/code", `{"name":"prod","code":"123456"}`))
		if m["ok"] != true {
			t.Errorf("response = %v", m)
		}
		if got := calls(t, log); len(got) != 1 || got[0] != "code prod 123456" {
			t.Errorf("CLI calls = %q", got)
		}
		if !hasStateFrame(c) {
			t.Error("no state broadcast after code")
		}
	})

	t.Run("CLI failure is reported", func(t *testing.T) {
		e := newActEnv(t)
		e.useStubCLI(t, 2)
		m := jsonBody(t, doReq(e.a.handleCode, http.MethodPost, "/code", `{"name":"prod","code":"123456"}`))
		if m["ok"] != false || !strings.Contains(fmt.Sprint(m["error"]), "exit status 2") {
			t.Errorf("response = %v", m)
		}
	})
}

func TestActionsHandleTotp(t *testing.T) {
	stubDocker(t)

	t.Run("method not allowed", func(t *testing.T) {
		e := newActEnv(t)
		e.useStubCLI(t, 0)
		if rec := doReq(e.a.handleTotp, http.MethodGet, "/totp/prod?code=123456", ""); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("name from path, code from query or body, query wins", func(t *testing.T) {
		cases := []struct {
			name, target, body, want string
		}{
			{"query", "/totp/prod?code=111111", ``, "code prod 111111"},
			{"body", "/totp/prod", `{"code":"222222"}`, "code prod 222222"},
			{"query beats body", "/totp/prod?code=333333", `{"code":"444444"}`, "code prod 333333"},
			{"trailing slash", "/totp/prod/?code=555555", ``, "code prod 555555"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				e := newActEnv(t)
				log := e.useStubCLI(t, 0)
				rec := doReq(e.a.handleTotp, http.MethodPost, tc.target, tc.body)
				if m := jsonBody(t, rec); m["ok"] != true {
					t.Fatalf("response = %v", m)
				}
				if got := calls(t, log); len(got) != 1 || got[0] != tc.want {
					t.Errorf("CLI calls = %q, want [%s]", got, tc.want)
				}
			})
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		e := newActEnv(t)
		log := e.useStubCLI(t, 0)
		cases := []struct{ target, body, err string }{
			{"/totp/?code=123456", ``, "invalid name"},
			{"/totp/?code=123456", `{"code":"123456"}`, "invalid name"},
			{"/totp/..%2Fx?code=123456", ``, "invalid name"},
			{"/totp/-x?code=123456", ``, "invalid name"},
			{"/totp/a..b?code=123456", ``, "invalid name"},
			{"/totp/prod", ``, "invalid code"},
			{"/totp/prod?code=12", ``, "invalid code"},
			{"/totp/prod?code=12%2034", ``, "invalid code"},
			{"/totp/prod", `{"code":"1"}`, "invalid code"},
		}
		for _, tc := range cases {
			rec := doReq(e.a.handleTotp, http.MethodPost, tc.target, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400", tc.target, rec.Code)
			}
			if m := jsonBody(t, rec); m["error"] != tc.err {
				t.Errorf("%s: error = %v, want %q", tc.target, m["error"], tc.err)
			}
		}
		if n := calls(t, log); len(n) != 0 {
			t.Errorf("CLI ran for invalid input: %v", n)
		}
	})
}

// ------------------------------------------------------------------ /layout

func TestActionsHandleLayout(t *testing.T) {
	layoutPath := func(e *actEnv) string { return filepath.Join(e.root, "panel-layout.json") }

	t.Run("GET without a saved layout returns {}", func(t *testing.T) {
		e := newActEnv(t)
		rec := doReq(e.a.handleLayout, http.MethodGet, "/layout", "")
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "{}" {
			t.Errorf("status %d body %q", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
	})

	t.Run("POST then GET round-trips, file is 0600, beside conf.d", func(t *testing.T) {
		e := newActEnv(t)
		body := `{"prod":{"x":10,"y":20},"dev":{"x":-5.5,"y":0}}`
		rec := doReq(e.a.handleLayout, http.MethodPost, "/layout", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST status = %d: %s", rec.Code, rec.Body.String())
		}
		if m := jsonBody(t, rec); m["ok"] != true {
			t.Errorf("POST response = %v", m)
		}
		st, err := os.Stat(layoutPath(e))
		if err != nil {
			t.Fatalf("layout not written beside conf.d: %v", err)
		}
		if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", st.Mode().Perm())
		}
		if ents, _ := os.ReadDir(e.d.confDir); len(ents) != 0 {
			t.Errorf("layout leaked into conf.d: %v", ents)
		}
		got := doReq(e.a.handleLayout, http.MethodGet, "/layout", "")
		var a, b any
		if json.Unmarshal([]byte(body), &a) != nil || json.Unmarshal(got.Body.Bytes(), &b) != nil || fmt.Sprint(a) != fmt.Sprint(b) {
			t.Errorf("GET = %s, want %s", got.Body.String(), body)
		}
	})

	t.Run("POST replaces, leaves no temp files", func(t *testing.T) {
		e := newActEnv(t)
		doReq(e.a.handleLayout, http.MethodPost, "/layout", `{"a":1}`)
		doReq(e.a.handleLayout, http.MethodPost, "/layout", `{"b":2}`)
		b, _ := os.ReadFile(layoutPath(e))
		if string(b) != `{"b":2}` {
			t.Errorf("layout = %s, want {\"b\":2}", b)
		}
		ents, _ := os.ReadDir(e.root)
		for _, en := range ents {
			if strings.HasSuffix(en.Name(), ".tmp") {
				t.Errorf("leftover temp file %s", en.Name())
			}
		}
	})

	t.Run("invalid JSON is rejected and does not clobber the saved layout", func(t *testing.T) {
		e := newActEnv(t)
		doReq(e.a.handleLayout, http.MethodPost, "/layout", `{"keep":true}`)
		for _, body := range []string{``, `not json`, `{"a":`, `{"a":1} trailing`} {
			rec := doReq(e.a.handleLayout, http.MethodPost, "/layout", body)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body %q: status = %d, want 400", body, rec.Code)
			}
			if m := jsonBody(t, rec); m["error"] != "invalid json" {
				t.Errorf("body %q: response = %v", body, m)
			}
		}
		if b, _ := os.ReadFile(layoutPath(e)); string(b) != `{"keep":true}` {
			t.Errorf("layout clobbered: %s", b)
		}
	})

	t.Run("body over 1 MB is truncated and therefore rejected", func(t *testing.T) {
		e := newActEnv(t)
		body := `{"pad":"` + strings.Repeat("a", (1<<20)+10) + `"}`
		rec := doReq(e.a.handleLayout, http.MethodPost, "/layout", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		if _, err := os.Stat(layoutPath(e)); err == nil {
			t.Error("oversized layout was written")
		}
	})

	t.Run("other methods", func(t *testing.T) {
		e := newActEnv(t)
		for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
			if rec := doReq(e.a.handleLayout, m, "/layout", `{}`); rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want 405", m, rec.Code)
			}
		}
	})

	t.Run("unwritable directory gives 500", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a non-root POSIX user to make a directory read-only")
		}
		e := newActEnv(t)
		if err := os.Chmod(e.root, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(e.root, 0o700) })
		rec := doReq(e.a.handleLayout, http.MethodPost, "/layout", `{"a":1}`)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500", rec.Code)
		}
		if m := jsonBody(t, rec); m["ok"] != false || m["error"] != "write" {
			t.Errorf("response = %v", m)
		}
		// the mutex must have been released on the error path
		_ = os.Chmod(e.root, 0o700)
		if rec := doReq(e.a.handleLayout, http.MethodPost, "/layout", `{"a":1}`); rec.Code != http.StatusOK {
			t.Errorf("retry after failure: status = %d (lock leaked?)", rec.Code)
		}
	})

	t.Run("concurrent POSTs leave one complete, valid layout", func(t *testing.T) {
		e := newActEnv(t)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				doReq(e.a.handleLayout, http.MethodPost, "/layout", fmt.Sprintf(`{"writer":%d,"pad":%q}`, i, strings.Repeat("x", 2000)))
			}(i)
		}
		wg.Wait()
		b, err := os.ReadFile(layoutPath(e))
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("layout is not valid JSON after concurrent writes: %v", err)
		}
		ents, _ := os.ReadDir(e.root)
		for _, en := range ents {
			if strings.HasSuffix(en.Name(), ".tmp") {
				t.Errorf("leftover temp file %s", en.Name())
			}
		}
	})
}
