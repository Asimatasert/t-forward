package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

// The admin gate must fail closed: a settings.json that exists but cannot be
// read or parsed is not "no PIN set yet". Only a missing file is first run.

const failClosedPIN = "correct-pin"

// brokenSettings describes one way settings.json can be present but unusable.
// breakFile damages the file a valid PIN was just saved to and returns a
// function reporting whether the damaged file is still exactly as left.
type brokenSettings struct {
	name      string
	breakFile func(t *testing.T, path string) (untouched func() bool)
}

func overwriteWith(content string) func(t *testing.T, path string) func() bool {
	return func(t *testing.T, path string) func() bool {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return func() bool {
			b, err := os.ReadFile(path)
			return err == nil && string(b) == content
		}
	}
}

func brokenSettingsCases() []brokenSettings {
	return []brokenSettings{
		{"empty file", overwriteWith("")},
		{"truncated JSON", overwriteWith(`{"adminSecretHash": "pbkdf2-sha256$600000$c2Fs`)},
		{"garbage", overwriteWith("\x00\x01 not json MARKER-DO-NOT-LOG")},
		{"JSON null", overwriteWith("null")},
		{"wrong top-level type", overwriteWith(`[1,2,3]`)},
		{"wrong-typed hash", overwriteWith(`{"adminSecretHash": 12345}`)},
		{"trailing junk", overwriteWith(`{"adminSecretHash":""}{"x":`)},
		// a read error that also happens when the tests run as root
		{"directory in place of the file", func(t *testing.T, path string) func() bool {
			t.Helper()
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			return func() bool {
				st, err := os.Stat(path)
				return err == nil && st.IsDir()
			}
		}},
		{"unreadable file (mode 000)", func(t *testing.T, path string) func() bool {
			t.Helper()
			if runtime.GOOS == "windows" || os.Geteuid() == 0 {
				t.Skip("needs a non-root POSIX user: root reads a mode-000 file")
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			return func() bool {
				st, err := os.Stat(path)
				if err != nil || st.Mode().Perm() != 0 {
					return false
				}
				_ = os.Chmod(path, 0o600)
				after, err := os.ReadFile(path)
				_ = os.Chmod(path, 0)
				return err == nil && bytes.Equal(before, after)
			}
		}},
	}
}

// refused asserts a fail-closed answer: 5xx, JSON {ok:false,error}, no PIN
// prompt, no bootstrap flag and no admin session.
func refused(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	m := jsonBody(t, rec)
	if rec.Code < 500 || rec.Code > 599 {
		t.Errorf("%s: status = %d, want 5xx", what, rec.Code)
	}
	if m["ok"] != false || m["error"] == nil || m["error"] == "" {
		t.Errorf("%s: response = %v, want ok=false with an error", what, m)
	}
	if _, has := m["needPin"]; has {
		t.Errorf("%s: response asks for a PIN: %v", what, m)
	}
	if _, has := m["adminSet"]; has {
		t.Errorf("%s: response reports adminSet: %v", what, m)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "tf_admin" {
			t.Errorf("%s: an admin session was handed out", what)
		}
	}
}

func TestAdminGateFailsClosedOnBrokenSettings(t *testing.T) {
	for _, tc := range brokenSettingsCases() {
		t.Run(tc.name, func(t *testing.T) {
			e := newActEnv(t)
			e.writeSettings(t, Settings{
				AdminSecretHash: hashPIN(failClosedPIN),
				Telegram:        TelegramConf{BotToken: "savedtok", ChatID: "777"},
				Notify:          NotifyConf{Down: true},
			})
			// a session minted while the file was still fine
			unlock := postJSON(e.a.handleAdminUnlock, "/admin/unlock", `{"pin":"`+failClosedPIN+`"}`, nil)
			session := adminCookie(unlock)
			if session == nil || adminKey(unlock) == "" {
				t.Fatalf("setup: unlock = %d %s", unlock.Code, unlock.Body.String())
			}
			// a session is the cookie plus its key; the cookie alone never passes
			live := map[string]string{"X-Admin-Key": adminKey(unlock)}
			tg := fakeTelegram(t, http.StatusOK, `{"ok":true}`)

			ran := false
			inner := e.a.privileged(func(w http.ResponseWriter, r *http.Request) {
				ran = true
				writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			})
			// the session really is live while the file is intact, so its
			// refusal below is due to the broken file and nothing else
			if rec := postJSON(inner, "/conf/x", `{}`, live, session); rec.Code != http.StatusOK || !ran {
				t.Fatalf("setup: live session refused on an intact file: %d %s", rec.Code, rec.Body.String())
			}
			ran = false
			untouched := tc.breakFile(t, settingsFile(e))

			// privileged route, with and without credentials
			for what, hdr := range map[string]map[string]string{
				"privileged POST":                 nil,
				"privileged POST with PIN header": {"X-Admin-Token": failClosedPIN},
				"privileged POST with wrong PIN":  {"X-Admin-Token": "wrong-pin"},
			} {
				rec := postJSON(inner, "/conf/x", `{}`, hdr)
				refused(t, what, rec)
			}
			rec := postJSON(inner, "/conf/x", `{}`, live, session)
			refused(t, "privileged POST with a live session", rec)
			rec = postJSON(inner, "/conf/x", `{}`, nil, session)
			refused(t, "privileged POST with the session cookie alone", rec)
			if ran {
				t.Error("the privileged handler ran")
			}

			// the PIN cannot be set or replaced, other settings cannot be saved
			rec = e.postSettings(`{"adminPin":"attacker-pin"}`, nil)
			refused(t, "set PIN", rec)
			rec = e.postSettings(`{"adminPin":"attacker-pin"}`, live, session)
			refused(t, "set PIN with a live session", rec)
			rec = e.postSettings(`{"telegramChatId":"1"}`, nil)
			refused(t, "save settings", rec)

			// unlock neither reports "no PIN set" nor mints a session
			rec = postJSON(e.a.handleAdminUnlock, "/admin/unlock", `{"pin":"`+failClosedPIN+`"}`, nil)
			refused(t, "unlock", rec)
			rec = postJSON(e.a.handleAdminUnlock, "/admin/unlock", `{}`, nil)
			refused(t, "unlock without a pin", rec)

			// GET /settings must not tell the panel that no PIN is set
			rec = doReq(e.a.handleSettings, http.MethodGet, "/settings", "")
			refused(t, "GET /settings", rec)

			// an unreadable file is not a wrong PIN: the lockout is not fed
			if e.a.gate.fails != 0 {
				t.Errorf("gate.fails = %d, want 0", e.a.gate.fails)
			}
			// the legacy-hash upgrade must not write defaults over the file
			e.a.upgradePINHash(failClosedPIN, "")

			if !untouched() {
				t.Error("the broken settings file was overwritten")
			}
			ents, _ := os.ReadDir(e.root)
			for _, en := range ents {
				if strings.HasSuffix(en.Name(), ".tmp") {
					t.Errorf("leftover temp file %s", en.Name())
				}
			}

			// notify test: refused even with request-supplied credentials
			rec = postJSON(e.a.handleNotifyTest, "/notify/test", `{"telegramToken":"t","telegramChatId":"1"}`, nil)
			refused(t, "notify test", rec)

			// background reader degrades to defaults: no notification, no panic
			e.d.notifyState("down", "tun", "text")
			expectNoTG(t, tg)
		})
	}
}

func TestAdminGateRecoversWhenSettingsAreRepaired(t *testing.T) {
	e := newActEnv(t)
	good := Settings{AdminSecretHash: hashPIN(failClosedPIN), ClaudeAPIKey: "orig"}
	e.writeSettings(t, good)
	valid, err := os.ReadFile(settingsFile(e))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsFile(e), valid[:len(valid)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := e.postSettings(`{"adminPin":"attacker-pin"}`, nil); rec.Code < 500 {
		t.Fatalf("truncated file: status = %d, want 5xx", rec.Code)
	}
	if err := os.WriteFile(settingsFile(e), valid, 0o600); err != nil {
		t.Fatal(err)
	}
	// the stored PIN is the gate again: still required, still accepted
	if rec := e.postSettings(`{"telegramChatId":"1"}`, nil); rec.Code != http.StatusForbidden {
		t.Errorf("repaired file, no credentials: status = %d, want 403", rec.Code)
	}
	rec := e.postSettings(`{"telegramChatId":"1"}`, map[string]string{"X-Admin-Token": failClosedPIN})
	if rec.Code != http.StatusOK {
		t.Errorf("repaired file, correct PIN: status = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAdminGateBootstrapStaysOpenWithoutSettingsFile(t *testing.T) {
	e := newActEnv(t)
	if _, err := os.Stat(settingsFile(e)); !os.IsNotExist(err) {
		t.Fatalf("setup: settings.json exists (err = %v)", err)
	}
	m, _ := e.getSettings(t)
	if m["adminSet"] != false {
		t.Errorf("GET /settings = %v", m)
	}
	rec := postJSON(e.a.handleAdminUnlock, "/admin/unlock", `{}`, nil)
	if um := jsonBody(t, rec); rec.Code != http.StatusOK || um["adminSet"] != false {
		t.Errorf("unlock = %d %v", rec.Code, um)
	}
	ran := false
	inner := e.a.privileged(func(w http.ResponseWriter, r *http.Request) { ran = true })
	postJSON(inner, "/conf/x", `{}`, nil)
	if !ran {
		t.Error("first run: the privileged handler did not run")
	}
	rec = e.postSettings(`{"adminPin":"`+failClosedPIN+`"}`, nil)
	if rec.Code != http.StatusOK || adminCookie(rec) == nil {
		t.Fatalf("first PIN: status %d cookie %v", rec.Code, adminCookie(rec))
	}
	// an empty object is a valid file without a PIN, not a broken one
	if err := os.WriteFile(settingsFile(e), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := e.postSettings(`{"telegramChatId":"1"}`, nil); rec.Code != http.StatusOK {
		t.Errorf("{} settings file: status = %d, want 200", rec.Code)
	}
}

func TestBrokenSettingsAreLoggedWithoutContents(t *testing.T) {
	e := newActEnv(t)
	const secret = "MARKER-DO-NOT-LOG"
	if err := os.WriteFile(settingsFile(e), []byte(`{"claudeApiKey":"`+secret+`", `+secret), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	rec := e.postSettings(`{"adminPin":"attacker-pin"}`, nil)
	log.SetOutput(os.Stderr)
	if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), e.root) {
		t.Errorf("response leaks file contents or its path: %s", rec.Body.String())
	}
	out := buf.String()
	if !strings.Contains(out, settingsFile(e)) {
		t.Errorf("log does not name the settings file: %q", out)
	}
	if strings.Contains(out, secret) {
		t.Errorf("log leaks file contents: %q", out)
	}
}
