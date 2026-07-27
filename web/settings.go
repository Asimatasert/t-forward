package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Settings is the daemon's persisted configuration blob (Telegram / Claude
// tokens, notification prefs, the admin gate). It lives beside the config tree
// at <configDir>/settings.json, mode 0600 — NOT inside conf.d (which is scanned
// as tunnel *.yaml). Secrets are never returned to the panel; GET /settings
// reports only "configured" flags.
type Settings struct {
	// sha256(hex) of the admin PIN that gates privileged endpoints. Empty until
	// the operator sets one (first-run bootstrap: privileged POSTs are open only
	// while this is empty, so the PIN can be set in the first place).
	AdminSecretHash string       `json:"adminSecretHash,omitempty"`
	Telegram        TelegramConf `json:"telegram"`
	ClaudeAPIKey    string       `json:"claudeApiKey,omitempty"` // optional; else the server's own claude auth
	Notify          NotifyConf   `json:"notify"`
}

type TelegramConf struct {
	BotToken string `json:"botToken,omitempty"`
	ChatID   string `json:"chatId,omitempty"`
}

// NotifyConf holds the global per-event toggles plus per-tunnel / per-host
// overrides (Phase 2 resolves per-host > per-tunnel > global).
type NotifyConf struct {
	Down      bool                  `json:"down"`
	Up        bool                  `json:"up"`
	Warn      bool                  `json:"warn"`
	Reach     bool                  `json:"reach"`
	PerTunnel map[string]EventFlags `json:"perTunnel,omitempty"`
	PerHost   map[string]EventFlags `json:"perHost,omitempty"`
}

// EventFlags is a scoped override; a nil pointer means "fall through to the
// broader scope" so a rule can enable one event for one tunnel without
// re-stating the rest.
type EventFlags struct {
	Down  *bool `json:"down,omitempty"`
	Up    *bool `json:"up,omitempty"`
	Warn  *bool `json:"warn,omitempty"`
	Reach *bool `json:"reach,omitempty"`
}

func hashPIN(pin string) string {
	sum := sha256.Sum256([]byte(pin))
	return hex.EncodeToString(sum[:])
}

func (a *Actions) settingsPath() string {
	return filepath.Join(filepath.Dir(a.docker.confDir), "settings.json")
}

func (a *Actions) loadSettings() Settings {
	var s Settings
	if b, err := os.ReadFile(a.settingsPath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func (a *Actions) saveSettings(s Settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := a.settingsPath()
	// Unique temp name in the same dir (os.CreateTemp yields mode 0600) so
	// concurrent writers never clobber a shared ".tmp"; rename is atomic.
	f, err := os.CreateTemp(filepath.Dir(path), ".settings-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename below has consumed it
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// requirePrivileged reports whether the request may perform a privileged action.
// It writes a 403 (with needPin) and returns false when the admin gate rejects
// it. While no admin PIN is set (first run) everything is open so the PIN can be
// established; once set, an X-Admin-Token header or tf_admin cookie is required.
func (a *Actions) requirePrivileged(w http.ResponseWriter, r *http.Request) bool {
	s := a.loadSettings()
	if s.AdminSecretHash == "" {
		return true // first-run bootstrap
	}
	got := r.Header.Get("X-Admin-Token")
	if got == "" {
		if c, err := r.Cookie("tf_admin"); err == nil {
			got = c.Value
		}
	}
	if got != "" && subtle.ConstantTimeCompare([]byte(hashPIN(got)), []byte(s.AdminSecretHash)) == 1 {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "locked", "needPin": true})
	return false
}

// privileged wraps a handler so mutating methods pass the admin gate; GET/HEAD
// (read-only) are always allowed.
func (a *Actions) privileged(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			h(w, r)
			return
		}
		if !a.requirePrivileged(w, r) {
			return
		}
		h(w, r)
	}
}

// handleSettings: GET returns non-secret config + "configured" flags; POST
// (privileged) merges, overwriting a secret only when a new value is supplied,
// and sets/rotates the admin PIN.
func (a *Actions) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s := a.loadSettings()
		writeJSON(w, http.StatusOK, map[string]any{
			"adminSet":           s.AdminSecretHash != "",
			"telegramConfigured": s.Telegram.BotToken != "" && s.Telegram.ChatID != "",
			"telegramChatId":     s.Telegram.ChatID, // not a secret; helps confirm the target
			"claudeKeySet":       s.ClaudeAPIKey != "",
			"notify":             s.Notify,
		})
	case http.MethodPost:
		if !a.requirePrivileged(w, r) {
			return
		}
		var in struct {
			AdminPin       *string     `json:"adminPin"`
			TelegramToken  *string     `json:"telegramToken"`
			TelegramChatID *string     `json:"telegramChatId"`
			ClaudeAPIKey   *string     `json:"claudeApiKey"`
			Notify         *NotifyConf `json:"notify"`
		}
		if r.Body != nil {
			defer r.Body.Close()
			_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in)
		}
		// Serialize the whole load->mutate->save so two concurrent POSTs can't
		// each read the old blob and lose one another's field updates.
		a.mu.Lock()
		s := a.loadSettings()
		if in.AdminPin != nil && *in.AdminPin != "" {
			s.AdminSecretHash = hashPIN(*in.AdminPin)
		}
		if in.TelegramToken != nil && *in.TelegramToken != "" {
			s.Telegram.BotToken = *in.TelegramToken
		}
		if in.TelegramChatID != nil {
			s.Telegram.ChatID = *in.TelegramChatID
		}
		if in.ClaudeAPIKey != nil && *in.ClaudeAPIKey != "" {
			s.ClaudeAPIKey = *in.ClaudeAPIKey
		}
		if in.Notify != nil {
			s.Notify = *in.Notify
		}
		err := a.saveSettings(s)
		a.mu.Unlock()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdminUnlock: POST {pin} — verify the PIN and set a short-lived tf_admin
// cookie so subsequent privileged requests pass the gate.
func (a *Actions) handleAdminUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s := a.loadSettings()
	if s.AdminSecretHash == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "adminSet": false})
		return
	}
	pin := decodeBody(r)["pin"]
	if pin != "" && subtle.ConstantTimeCompare([]byte(hashPIN(pin)), []byte(s.AdminSecretHash)) == 1 {
		http.SetCookie(w, &http.Cookie{
			Name: "tf_admin", Value: pin, Path: "/",
			HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 8 * 3600,
		})
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wrong pin"})
}
