package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Admin PIN handling: salted PBKDF2 at rest, random server-side session tokens
// instead of the PIN in the cookie, and an exponential lockout on failed
// attempts.

const (
	pinKDFName    = "pbkdf2-sha256"
	pinKDFIter    = 600_000 // OWASP guidance for PBKDF2-HMAC-SHA256
	minPINLen     = 6
	sessionTTL    = 8 * time.Hour
	maxSessions   = 32
	lockAfterFail = 5 // consecutive failures before the lockout starts
	maxLockout    = 15 * time.Minute
)

// hashPIN returns "pbkdf2-sha256$<iter>$<salt>$<key>" with a fresh random salt.
func hashPIN(pin string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic("crypto/rand: " + err.Error()) // no safe fallback
	}
	key, err := pbkdf2.Key(sha256.New, pin, salt, pinKDFIter, 32)
	if err != nil {
		panic("pbkdf2: " + err.Error())
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", pinKDFName, pinKDFIter, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// verifyPIN checks pin against a stored hash. legacy reports a match against the
// old unsalted single-round SHA-256 format, which the caller should upgrade.
func verifyPIN(pin, stored string) (ok, legacy bool) {
	if stored == "" {
		return false, false
	}
	parts := strings.Split(stored, "$")
	if len(parts) == 4 && parts[0] == pinKDFName {
		iter, err := strconv.Atoi(parts[1])
		if err != nil || iter < 1 || iter > 10_000_000 {
			return false, false
		}
		enc := base64.RawStdEncoding
		salt, err1 := enc.DecodeString(parts[2])
		want, err2 := enc.DecodeString(parts[3])
		if err1 != nil || err2 != nil || len(want) == 0 {
			return false, false
		}
		got, err := pbkdf2.Key(sha256.New, pin, salt, iter, len(want))
		if err != nil {
			return false, false
		}
		return subtle.ConstantTimeCompare(got, want) == 1, false
	}
	// legacy: hex(sha256(pin))
	sum := sha256.Sum256([]byte(pin))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(stored)) == 1 {
		return true, true
	}
	return false, false
}

// adminGate holds the in-memory admin sessions and the failed-attempt counter.
// The zero value is ready to use.
type adminGate struct {
	mu          sync.Mutex
	sessions    map[string]time.Time // token -> expiry
	fails       int
	lockedUntil time.Time
	verifyMu    sync.Mutex       // serialises PIN checks: PBKDF2 is costly, attempts are counted in order
	now         func() time.Time // test hook
}

func (g *adminGate) clock() time.Time {
	if g.now != nil {
		return g.now()
	}
	return time.Now()
}

// newSession mints a random session token valid for sessionTTL.
func (g *adminGate) newSession() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	tok := hex.EncodeToString(b)
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.clock()
	if g.sessions == nil {
		g.sessions = map[string]time.Time{}
	}
	for t, exp := range g.sessions {
		if now.After(exp) {
			delete(g.sessions, t)
		}
	}
	// bounded: drop the soonest-to-expire entry when full
	for len(g.sessions) >= maxSessions {
		var oldest string
		var oldestExp time.Time
		for t, exp := range g.sessions {
			if oldest == "" || exp.Before(oldestExp) {
				oldest, oldestExp = t, exp
			}
		}
		delete(g.sessions, oldest)
	}
	g.sessions[tok] = now.Add(sessionTTL)
	return tok
}

func (g *adminGate) validSession(tok string) bool {
	if tok == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.sessions[tok]
	if !ok {
		return false
	}
	if g.clock().After(exp) {
		delete(g.sessions, tok)
		return false
	}
	return true
}

// revokeAll drops every session (used when the PIN changes).
func (g *adminGate) revokeAll() {
	g.mu.Lock()
	g.sessions = nil
	g.mu.Unlock()
}

// retryAfter returns the remaining lockout (0 when attempts are allowed).
func (g *adminGate) retryAfter() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if d := g.lockedUntil.Sub(g.clock()); d > 0 {
		return d
	}
	return 0
}

func (g *adminGate) recordFailure() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fails++
	if g.fails < lockAfterFail {
		return
	}
	// 1s, 2s, 4s ... capped: every further failure doubles the wait
	shift := g.fails - lockAfterFail
	if shift > 10 {
		shift = 10
	}
	d := time.Second << shift
	if d > maxLockout {
		d = maxLockout
	}
	g.lockedUntil = g.clock().Add(d)
}

func (g *adminGate) recordSuccess() {
	g.mu.Lock()
	g.fails = 0
	g.lockedUntil = time.Time{}
	g.mu.Unlock()
}

// checkPIN verifies a PIN against the stored hash under the lockout. retry > 0
// means the attempt was refused without being evaluated.
func (a *Actions) checkPIN(pin string) (ok bool, retry time.Duration) {
	a.gate.verifyMu.Lock()
	defer a.gate.verifyMu.Unlock()
	if d := a.gate.retryAfter(); d > 0 {
		return false, d
	}
	s := a.loadSettings()
	match, legacy := verifyPIN(pin, s.AdminSecretHash)
	if !match {
		a.gate.recordFailure()
		return false, 0
	}
	a.gate.recordSuccess()
	if legacy {
		a.upgradePINHash(pin, s.AdminSecretHash)
	}
	return true, 0
}

// upgradePINHash replaces a legacy SHA-256 hash with a salted PBKDF2 one after a
// successful verification (only if the stored hash is still the one we checked).
func (a *Actions) upgradePINHash(pin, oldHash string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.loadSettings()
	if s.AdminSecretHash != oldHash {
		return
	}
	s.AdminSecretHash = hashPIN(pin)
	_ = a.saveSettings(s)
}

func validPINLength(pin string) bool { return utf8.RuneCountInString(pin) >= minPINLen }

func lockedResponse(w http.ResponseWriter, retry time.Duration) {
	secs := int(retry.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"ok": false, "error": "too many attempts", "retryAfter": secs,
	})
}

func setAdminCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name: "tf_admin", Value: tok, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
}
