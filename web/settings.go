package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Settings is the daemon's persisted configuration blob (Telegram / Claude
// tokens, notification prefs, the admin gate). It lives beside the config tree
// at <configDir>/settings.json, mode 0600 — NOT inside conf.d (which is scanned
// as tunnel *.yaml). Secrets are never returned to the panel; GET /settings
// reports only "configured" flags.
type Settings struct {
	// Hash of the admin PIN that gates privileged endpoints (salted PBKDF2, see
	// admin.go; hashes written by older versions are plain hex SHA-256 and are
	// upgraded on the next successful unlock). Empty until the operator sets
	// one (first-run bootstrap: privileged POSTs are open only while this is
	// empty, so the PIN can be set in the first place).
	AdminSecretHash string       `json:"adminSecretHash,omitempty"`
	Telegram        TelegramConf `json:"telegram"`
	ClaudeAPIKey    string       `json:"claudeApiKey,omitempty"` // optional; else the server's own claude auth
	Notify          NotifyConf   `json:"notify"`
}

type TelegramConf struct {
	BotToken string `json:"botToken,omitempty"`
	ChatID   string `json:"chatId,omitempty"`
	// message_thread_id per notify event key ("down"/"up"/"warn"/"reach"), so
	// each event type can post to its own forum topic. A missing/empty key
	// posts to the chat's General topic (or a non-forum chat).
	Topics map[string]string `json:"topics,omitempty"`
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

func settingsPathFor(confDir string) string {
	return filepath.Join(filepath.Dir(confDir), "settings.json")
}

// readSettingsFor loads settings.json. Only a file that does not exist is the
// first run (zero Settings, nil error). A file that exists but cannot be read
// or parsed is an error, never "no PIN set": the admin gate has to fail closed
// on it, and no caller may save over it. The error (logged here) names the
// path and the cause but never the file's contents.
func readSettingsFor(confDir string) (Settings, error) {
	var s Settings
	path := settingsPathFor(confDir)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err == nil && (json.Unmarshal(b, &s) != nil || bytes.Equal(bytes.TrimSpace(b), []byte("null"))) {
		// json's own message can quote bytes of the file, so it is not used
		err = fmt.Errorf("parse %s: not a valid settings JSON object (%d bytes)", path, len(b))
	}
	if err != nil {
		logSettingsErr(err)
		return Settings{}, err
	}
	return s, nil
}

// loadSettingsFor is for readers outside the admin gate: an unusable file
// degrades to the defaults (nothing configured, nothing enabled). Never use it
// to decide whether a PIN is set, or as the base of a save.
func loadSettingsFor(confDir string) Settings {
	s, _ := readSettingsFor(confDir)
	return s
}

// logSettingsErr reports an unusable settings file, at most once a minute per
// distinct error (notifyState reads the file on hot paths).
func logSettingsErr(err error) {
	settingsErrLog.mu.Lock()
	defer settingsErrLog.mu.Unlock()
	msg, now := err.Error(), time.Now()
	if msg == settingsErrLog.msg && now.Sub(settingsErrLog.at) < time.Minute {
		return
	}
	settingsErrLog.msg, settingsErrLog.at = msg, now
	log.Printf("settings: %s; privileged panel actions are refused until the file is repaired or restored", msg)
}

var settingsErrLog struct {
	mu  sync.Mutex
	msg string
	at  time.Time
}

// settingsUnavailable answers a request that needs settings.json while the
// file is unusable. The detail stays in the daemon log.
func settingsUnavailable(w http.ResponseWriter) {
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{
		"ok":    false,
		"error": "settings file is unreadable or corrupt; privileged actions are disabled until it is repaired (see the daemon log)",
	})
}

func (a *Actions) settingsPath() string            { return settingsPathFor(a.docker.confDir) }
func (a *Actions) readSettings() (Settings, error) { return readSettingsFor(a.docker.confDir) }

func (a *Actions) saveSettings(s Settings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	path := a.settingsPath()
	// Unique temp name in the same dir (os.CreateTemp yields mode 0600) so
	// concurrent writers never clobber a shared ".tmp"; rename is atomic. The
	// data is synced before the rename so a crash cannot leave a truncated
	// settings.json behind (which would lock the admin gate, see above).
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
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// best effort: make the rename itself durable
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// requirePrivileged reports whether the request may perform a privileged action.
// It writes a 403 (with needPin) and returns false when the admin gate rejects
// it, or a 503 when settings.json exists but cannot be read or parsed (fail
// closed: an unknown PIN state is not "no PIN", and not even a live session
// passes). While no admin PIN is set (first run: no settings.json, or one
// without a hash) everything is open so the PIN can be
// established; once set, a session token (tf_admin cookie or X-Admin-Token
// header, minted by /admin/unlock) is required. API clients may also send the
// PIN itself in X-Admin-Token; that path is subject to the same lockout as
// /admin/unlock. The cookie only ever carries a session token, never the PIN.
func (a *Actions) requirePrivileged(w http.ResponseWriter, r *http.Request) bool {
	s, err := a.readSettings()
	if err != nil {
		settingsUnavailable(w)
		return false
	}
	if s.AdminSecretHash == "" {
		return true // first-run bootstrap
	}
	if hdr := r.Header.Get("X-Admin-Token"); hdr != "" {
		if a.gate.validSession(hdr) {
			return true
		}
		ok, retry, err := a.checkPIN(hdr)
		if err != nil {
			settingsUnavailable(w)
			return false
		}
		if ok {
			return true
		}
		if retry > 0 {
			lockedResponse(w, retry)
			return false
		}
	} else if c, err := r.Cookie("tf_admin"); err == nil && a.gate.validSession(c.Value) {
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
		s, err := a.readSettings()
		if err != nil {
			// no flags at all: "adminSet": false would offer to set a PIN
			settingsUnavailable(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"adminSet":           s.AdminSecretHash != "",
			"telegramConfigured": s.Telegram.BotToken != "" && s.Telegram.ChatID != "",
			"telegramChatId":     s.Telegram.ChatID, // not a secret; helps confirm the target
			"telegramTopics":     s.Telegram.Topics,
			"claudeKeySet":       s.ClaudeAPIKey != "",
			"notify":             s.Notify,
		})
	case http.MethodPost:
		if !a.requirePrivileged(w, r) {
			return
		}
		var in struct {
			AdminPin       *string           `json:"adminPin"`
			TelegramToken  *string           `json:"telegramToken"`
			TelegramChatID *string           `json:"telegramChatId"`
			TelegramTopics map[string]string `json:"telegramTopics"`
			ClaudeAPIKey   *string           `json:"claudeApiKey"`
			Notify         *NotifyConf       `json:"notify"`
		}
		if r.Body != nil {
			defer r.Body.Close()
			// A body that does not decode (bad JSON, wrong-typed field, over
			// the size cap) is rejected whole: a half-decoded struct could
			// otherwise reset settings, e.g. {"notify":"nope"} allocates the
			// *NotifyConf pointer and zeroes every toggle.
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid settings JSON"})
				return
			}
		}
		newPin := in.AdminPin != nil && *in.AdminPin != ""
		if newPin && !validPINLength(*in.AdminPin) {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok": false, "error": "admin PIN must be at least " + strconv.Itoa(minPINLen) + " characters",
			})
			return
		}
		// Serialize the whole load->mutate->save so two concurrent POSTs can't
		// each read the old blob and lose one another's field updates.
		a.mu.Lock()
		s, err := a.readSettings()
		if err != nil {
			// never save defaults over a file that could not be loaded
			a.mu.Unlock()
			settingsUnavailable(w)
			return
		}
		if newPin {
			s.AdminSecretHash = hashPIN(*in.AdminPin)
		}
		if in.TelegramToken != nil && *in.TelegramToken != "" {
			s.Telegram.BotToken = *in.TelegramToken
		}
		if in.TelegramChatID != nil {
			s.Telegram.ChatID = *in.TelegramChatID
		}
		if in.TelegramTopics != nil {
			topics := map[string]string{}
			for k, v := range in.TelegramTopics {
				if v != "" {
					topics[k] = v
				}
			}
			s.Telegram.Topics = topics
		}
		if in.ClaudeAPIKey != nil && *in.ClaudeAPIKey != "" {
			s.ClaudeAPIKey = *in.ClaudeAPIKey
		}
		if in.Notify != nil {
			s.Notify = *in.Notify
		}
		err = a.saveSettings(s)
		a.mu.Unlock()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if newPin {
			// the PIN changed: every old session dies, the caller (who just
			// proved they may change it) gets a fresh one
			a.gate.revokeAll()
			setAdminCookie(w, a.gate.newSession())
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAdminUnlock: POST {pin} — verify the PIN (with lockout after repeated
// failures) and set a short-lived tf_admin cookie holding a random session
// token, so subsequent privileged requests pass the gate.
func (a *Actions) handleAdminUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s, err := a.readSettings()
	if err != nil {
		settingsUnavailable(w)
		return
	}
	if s.AdminSecretHash == "" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "adminSet": false})
		return
	}
	pin := decodeBody(r)["pin"]
	if pin == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wrong pin"})
		return
	}
	ok, retry, err := a.checkPIN(pin)
	if err != nil {
		settingsUnavailable(w)
		return
	}
	if retry > 0 {
		lockedResponse(w, retry)
		return
	}
	if ok {
		setAdminCookie(w, a.gate.newSession())
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "wrong pin"})
}
