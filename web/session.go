package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Browser sessions. A cookie is scoped by host, NOT by port, and the panel opens
// forwarded services on the same hostname at other ports — so every cookie this
// daemon sets is also sent to those services. A cookie alone must therefore
// never authenticate. The panel's credential is split in two:
//
//   - tf_session, an HttpOnly cookie "<id>.<mac>": the half that leaks to other
//     ports. It holds no token material and is useless by itself.
//   - the session key, HMAC(keyKey, id): handed to the panel inside the page on a
//     token-authenticated load, kept in the page's origin-scoped storage (an
//     origin includes the port) and sent back in the X-Session-Key header.
//
// Both halves are required on every request. Nothing is stored server-side: the
// MAC keys derive from a random secret persisted beside the config (so an open
// panel survives a daemon restart) mixed with the token (so rotating the token
// revokes every session). The secret is independent of the token, so a leaked
// cookie gives no offline oracle for guessing a weak token.
//
// What this does not cover: the key is readable by script running in the panel
// origin (it has to be, to be sent as a header). Key and cookie together,
// replayed from outside the browser, are a valid session that does not expire
// until the token is rotated or the secret file is deleted.
const (
	sessionCookieName = "tf_session"
	sessionKeyHeader  = "X-Session-Key"
	sessionSecretFile = "web-session.key"
	// placeholder in panel/index.html that the / handler fills with the key
	sessionKeyMeta = `<meta name="tf-session-key" content="">`
)

type browserSessions struct {
	cookieKey []byte // authenticates the cookie's id
	keyKey    []byte // derives the origin-scoped key from the id
}

// newBrowserSessions loads (or creates, mode 0600) the persisted secret in
// configDir. If it can be neither read nor written the secret lives in memory
// only, which just means sessions do not survive a restart (logged).
func newBrowserSessions(configDir, token string) *browserSessions {
	secret := loadSessionSecret(filepath.Join(configDir, sessionSecretFile))
	derive := func(label string) []byte {
		m := hmac.New(sha256.New, secret)
		m.Write([]byte(label + "\x00" + token))
		return m.Sum(nil)
	}
	return &browserSessions{cookieKey: derive("tf-session-cookie"), keyKey: derive("tf-session-key")}
}

func loadSessionSecret(path string) []byte {
	read := func() []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		s, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(s) < 32 {
			return nil
		}
		return s
	}
	if s := read(); s != nil {
		// An existing file is trusted as it is; at least stop others reading it.
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
			if err := os.Chmod(path, 0o600); err != nil {
				log.Printf("session secret %s is readable by other users and its mode cannot be tightened: %v", path, err)
			}
		}
		return s
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic("crypto/rand: " + err.Error()) // no safe fallback
	}
	// Write to a private temp file and rename, so a concurrent reader never
	// sees a partial secret. Best effort: on failure keep the in-memory one.
	notSaved := func(err error) []byte {
		log.Printf("session secret not saved (%v): browser sessions will end when the daemon restarts", err)
		return secret
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".web-session-*.tmp")
	if err != nil {
		return notSaved(err)
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename below has consumed it
	_, werr := f.WriteString(hex.EncodeToString(secret) + "\n")
	if cerr := f.Close(); werr != nil || cerr != nil {
		if werr == nil {
			werr = cerr
		}
		return notSaved(werr)
	}
	if err := os.Rename(tmp, path); err != nil {
		return notSaved(err)
	}
	return secret
}

func macHex(key []byte, msg string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}

// newID returns a fresh random session id.
func (s *browserSessions) newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (s *browserSessions) cookieValue(id string) string { return id + "." + macHex(s.cookieKey, id) }

// key is the origin-scoped secret for a session id. It cannot be computed from
// the cookie: it is keyed by keyKey, which never leaves the daemon.
func (s *browserSessions) key(id string) string { return macHex(s.keyKey, id) }

// cookieID returns the session id of a genuine tf_session cookie on r.
func (s *browserSessions) cookieID(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	id, mac, ok := strings.Cut(c.Value, ".")
	if !ok || id == "" {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(mac), []byte(macHex(s.cookieKey, id))) != 1 {
		return "", false
	}
	return id, true
}

// keyValid reports, in constant time, whether key is the session key of id.
func (s *browserSessions) keyValid(id, key string) bool {
	return subtle.ConstantTimeCompare([]byte(key), []byte(s.key(id))) == 1
}

// start hands a token-authenticated panel load its session: it sets the cookie
// (reusing the id of a genuine one, so other open tabs keep working) and
// returns the page with the session key filled in.
func (s *browserSessions) start(w http.ResponseWriter, r *http.Request, page []byte) []byte {
	id, ok := s.cookieID(r)
	if !ok {
		id = s.newID()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.cookieValue(id),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	filled := strings.Replace(sessionKeyMeta, `content=""`, `content="`+s.key(id)+`"`, 1)
	return bytes.Replace(page, []byte(sessionKeyMeta), []byte(filled), 1)
}

// presentedToken returns the token a request carries explicitly: Authorization,
// then X-Token, then ?token=. Cookies are deliberately not a source.
func presentedToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if got := trimBearer(h); got != "" {
			return got
		}
	}
	if got := r.Header.Get("X-Token"); got != "" {
		return got
	}
	return r.URL.Query().Get("token")
}
