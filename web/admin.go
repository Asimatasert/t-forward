package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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
	lockAfterFail = 5 // consecutive failures from one client before its lockout starts
	maxLockout    = 15 * time.Minute
)

// Ceiling across all clients: far above what one client can reach (its own
// backoff caps it at a few dozen guesses an hour), so it only trips when many
// addresses guess in concert. It locks everyone out, the operator too.
const (
	globalLockAfterFail = 50
	maxTrackedClients   = 1024
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

// clientFails is the failed-attempt state of one client address.
type clientFails struct {
	fails       int
	lockedUntil time.Time
	last        time.Time
}

// adminGate holds the in-memory admin sessions and the failed-attempt counters:
// one per client address (so a single client cannot lock the operator out) and
// a global ceiling. The zero value is ready to use.
type adminGate struct {
	mu          sync.Mutex
	sessions    map[string]time.Time // token -> expiry
	fails       int                  // global, across clients
	lockedUntil time.Time            // global
	clients     map[string]*clientFails
	keySecret   []byte           // derives each session's origin-scoped key; random per process
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

// sessionKey returns the origin-scoped key that must accompany a session's
// cookie. The tf_admin cookie is also sent to forwarded services on other ports
// of this host, so it must not pass the gate alone; the key is returned to the
// panel in the response body, kept in its origin-scoped storage and sent back in
// X-Admin-Key. It is an HMAC under a per-process secret, so it cannot be
// derived from the cookie.
func (g *adminGate) sessionKey(tok string) string {
	g.mu.Lock()
	if g.keySecret == nil {
		g.keySecret = make([]byte, 32)
		if _, err := rand.Read(g.keySecret); err != nil {
			panic("crypto/rand: " + err.Error())
		}
	}
	secret := g.keySecret
	g.mu.Unlock()
	return macHex(secret, tok)
}

// validSessionKey reports whether tok is a live session and key its key.
func (g *adminGate) validSessionKey(tok, key string) bool {
	if !g.validSession(tok) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(key), []byte(g.sessionKey(tok))) == 1
}

// revokeAll drops every session (used when the PIN changes).
func (g *adminGate) revokeAll() {
	g.mu.Lock()
	g.sessions = nil
	g.mu.Unlock()
}

// clientKey identifies the caller for throttling: the peer address of the TCP
// connection, never a forwarded-for header (any client could set those). IPv6
// peers are grouped by /64, the usual per-subscriber allocation. Behind a
// reverse proxy or a loopback bind every caller shares one key, which makes the
// per-client backoff behave like a single counter, never weaker than before.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return p.String()
		}
	}
	return ip.String()
}

// lockoutFor is the wait after the n-th consecutive failure when the lockout
// starts at failure `after`: 1s, 2s, 4s ... capped.
func lockoutFor(n, after int) time.Duration {
	if n < after {
		return 0
	}
	shift := n - after
	if shift > 10 {
		shift = 10
	}
	d := time.Second << shift
	if d > maxLockout {
		d = maxLockout
	}
	return d
}

// retryAfter returns the remaining lockout for client (0 when attempts are
// allowed): the longer of its own and the global one.
func (g *adminGate) retryAfter(client string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.clock()
	d := g.lockedUntil.Sub(now)
	if c := g.clients[client]; c != nil {
		if cd := c.lockedUntil.Sub(now); cd > d {
			d = cd
		}
	}
	if d > 0 {
		return d
	}
	return 0
}

func (g *adminGate) recordFailure(client string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.clock()
	g.fails++
	if d := lockoutFor(g.fails, globalLockAfterFail); d > 0 {
		g.lockedUntil = now.Add(d)
	}
	c := g.clients[client]
	if c == nil {
		g.evictClients(now)
		if g.clients == nil {
			g.clients = map[string]*clientFails{}
		}
		c = &clientFails{}
		g.clients[client] = c
	}
	c.fails++
	c.last = now
	if d := lockoutFor(c.fails, lockAfterFail); d > 0 {
		c.lockedUntil = now.Add(d)
	}
}

// evictClients keeps the table bounded: it drops idle entries and, when still
// full, the least recently active one. Caller holds g.mu.
func (g *adminGate) evictClients(now time.Time) {
	if len(g.clients) < maxTrackedClients {
		return
	}
	var oldest string
	var oldestAt time.Time
	for k, c := range g.clients {
		if now.After(c.lockedUntil) && now.Sub(c.last) > maxLockout {
			delete(g.clients, k)
			continue
		}
		if oldest == "" || c.last.Before(oldestAt) {
			oldest, oldestAt = k, c.last
		}
	}
	if len(g.clients) >= maxTrackedClients {
		delete(g.clients, oldest)
	}
}

func (g *adminGate) recordSuccess(client string) {
	g.mu.Lock()
	g.fails = 0
	g.lockedUntil = time.Time{}
	delete(g.clients, client)
	g.mu.Unlock()
}

// checkPIN verifies a PIN against the stored hash under the lockout of client
// (see clientKey) and the global one. retry > 0
// means the attempt was refused without being evaluated. A non-nil err means
// the stored hash could not be loaded: the attempt is refused and, not being a
// wrong PIN, does not count towards the lockout.
func (a *Actions) checkPIN(pin, client string) (ok bool, retry time.Duration, err error) {
	// refuse a locked-out client before it queues behind the PBKDF2 mutex
	if d := a.gate.retryAfter(client); d > 0 {
		return false, d, nil
	}
	a.gate.verifyMu.Lock()
	defer a.gate.verifyMu.Unlock()
	if d := a.gate.retryAfter(client); d > 0 {
		return false, d, nil
	}
	s, err := a.readSettings()
	if err != nil {
		return false, 0, err
	}
	match, legacy := verifyPIN(pin, s.AdminSecretHash)
	if !match {
		a.gate.recordFailure(client)
		return false, 0, nil
	}
	a.gate.recordSuccess(client)
	if legacy {
		a.upgradePINHash(pin, s.AdminSecretHash)
	}
	return true, 0, nil
}

// upgradePINHash replaces a legacy SHA-256 hash with a salted PBKDF2 one after a
// successful verification (only if the stored hash is still the one we checked).
func (a *Actions) upgradePINHash(pin, oldHash string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, err := a.readSettings()
	if err != nil || s.AdminSecretHash != oldHash {
		return // never save over a file that could not be loaded
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

// startAdminSession mints a session, sets its cookie and returns the key the
// caller must hand to the panel in the response body.
func (a *Actions) startAdminSession(w http.ResponseWriter) string {
	tok := a.gate.newSession()
	setAdminCookie(w, tok)
	return a.gate.sessionKey(tok)
}
