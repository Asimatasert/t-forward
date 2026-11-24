package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Extra coverage for the admin PIN / session / lockout code (admin.go) and the
// settings write path: malformed stored hashes, session bounds, lockout caps.

func TestAGVerifyPINRejectsMalformedHashes(t *testing.T) {
	valid := hashPIN("correct-pin")
	parts := strings.Split(valid, "$")
	if len(parts) != 4 {
		t.Fatalf("hashPIN format: %q", valid)
	}
	cases := []struct {
		name, stored string
	}{
		{"empty", ""},
		{"non-numeric iterations", "pbkdf2-sha256$abc$" + parts[2] + "$" + parts[3]},
		{"zero iterations", "pbkdf2-sha256$0$" + parts[2] + "$" + parts[3]},
		{"negative iterations", "pbkdf2-sha256$-5$" + parts[2] + "$" + parts[3]},
		{"iterations above the cap", "pbkdf2-sha256$10000001$" + parts[2] + "$" + parts[3]},
		{"salt is not base64", "pbkdf2-sha256$1000$!!!$" + parts[3]},
		{"key is not base64", "pbkdf2-sha256$1000$" + parts[2] + "$!!!"},
		{"empty key", "pbkdf2-sha256$1000$" + parts[2] + "$"},
		{"unknown kdf name", "scrypt$1000$" + parts[2] + "$" + parts[3]},
		{"too few fields", "pbkdf2-sha256$1000$" + parts[2]},
		{"too many fields", valid + "$extra"},
		{"truncated legacy hex", "abcdef"},
	}
	for _, c := range cases {
		if ok, legacy := verifyPIN("correct-pin", c.stored); ok || legacy {
			t.Errorf("%s: verifyPIN = (%v, %v), want (false, false)", c.name, ok, legacy)
		}
	}
	// the valid hash still verifies, a wrong PIN never does, and it is not "legacy"
	if ok, legacy := verifyPIN("correct-pin", valid); !ok || legacy {
		t.Errorf("valid hash: (%v, %v), want (true, false)", ok, legacy)
	}
	if ok, _ := verifyPIN("wrong-pin", valid); ok {
		t.Error("wrong PIN accepted")
	}
}

func TestAGLegacyHashMatchOnlyForExactSHA256Hex(t *testing.T) {
	sum := sha256.Sum256([]byte("123456"))
	legacy := hex.EncodeToString(sum[:])
	if ok, isLegacy := verifyPIN("123456", legacy); !ok || !isLegacy {
		t.Errorf("legacy hash: (%v, %v), want (true, true)", ok, isLegacy)
	}
	if ok, _ := verifyPIN("123456", strings.ToUpper(legacy)); ok {
		t.Error("an upper-cased legacy hash must not match (comparison is exact)")
	}
	if ok, _ := verifyPIN("654321", legacy); ok {
		t.Error("wrong PIN matched a legacy hash")
	}
}

func TestAGGateClockFallsBackToWallTime(t *testing.T) {
	var g adminGate // zero value: no test hook
	if d := time.Since(g.clock()); d < 0 || d > 5*time.Second {
		t.Errorf("clock() is %v away from now", d)
	}
}

func TestAGSessionsExpireAreBoundedAndEvictOldest(t *testing.T) {
	a, clock := newTestActions(t)
	g := &a.gate

	first := g.newSession()
	second := g.newSession()
	if first == second || len(first) != 64 {
		t.Fatalf("session tokens must be unique 32-byte hex: %q %q", first, second)
	}
	if !g.validSession(first) {
		t.Fatal("fresh session rejected")
	}
	if g.validSession("") || g.validSession("no-such-session") {
		t.Error("empty / unknown session accepted")
	}

	// after the TTL both are dead; minting a new one purges them from the map
	*clock = clock.Add(sessionTTL + time.Minute)
	if g.validSession(first) {
		t.Error("expired session accepted")
	}
	fresh := g.newSession()
	g.mu.Lock()
	n := len(g.sessions)
	_, stale := g.sessions[second]
	g.mu.Unlock()
	if n != 1 || stale {
		t.Errorf("expired sessions not purged: %d left, stale present=%v", n, stale)
	}

	// fill past the bound: the soonest-to-expire entry is dropped, never more than maxSessions
	toks := []string{fresh}
	for i := 0; i < maxSessions+4; i++ {
		*clock = clock.Add(time.Second) // strictly increasing expiry => a defined "oldest"
		toks = append(toks, g.newSession())
	}
	g.mu.Lock()
	n = len(g.sessions)
	g.mu.Unlock()
	if n != maxSessions {
		t.Fatalf("sessions = %d, want exactly maxSessions (%d)", n, maxSessions)
	}
	if g.validSession(toks[0]) {
		t.Error("the oldest session survived the eviction")
	}
	if !g.validSession(toks[len(toks)-1]) {
		t.Error("the newest session was evicted")
	}

	g.revokeAll()
	if g.validSession(toks[len(toks)-1]) {
		t.Error("revokeAll left a session valid")
	}
}

func TestAGLockoutStartsAtFifthFailureDoublesAndCaps(t *testing.T) {
	a, clock := newTestActions(t)
	g := &a.gate

	for i := 1; i < lockAfterFail; i++ {
		g.recordFailure()
		if d := g.retryAfter(); d != 0 {
			t.Fatalf("failure %d locked out for %v, want no lockout before %d", i, d, lockAfterFail)
		}
	}
	g.recordFailure() // 5th
	if d := g.retryAfter(); d != time.Second {
		t.Fatalf("5th failure lockout = %v, want 1s", d)
	}
	g.recordFailure() // 6th
	if d := g.retryAfter(); d != 2*time.Second {
		t.Fatalf("6th failure lockout = %v, want 2s", d)
	}
	for i := 0; i < 20; i++ { // far beyond the shift limit
		g.recordFailure()
	}
	if d := g.retryAfter(); d != maxLockout {
		t.Fatalf("lockout after many failures = %v, want the %v cap", d, maxLockout)
	}
	*clock = clock.Add(maxLockout + time.Second)
	if d := g.retryAfter(); d != 0 {
		t.Errorf("lockout still %v after it elapsed", d)
	}
	g.recordSuccess()
	g.recordFailure()
	if d := g.retryAfter(); d != 0 {
		t.Errorf("a success must reset the counter; got lockout %v", d)
	}
}

func TestAGCheckPINRefusesWhileLockedWithoutEvaluating(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "654321")
	for i := 0; i < lockAfterFail; i++ {
		if ok, retry := a.checkPIN("wrong-pin"); ok || retry != 0 {
			t.Fatalf("attempt %d = (%v, %v), want (false, 0)", i+1, ok, retry)
		}
	}
	// locked now: even the right PIN is refused, with the wait reported
	if ok, retry := a.checkPIN("654321"); ok || retry <= 0 {
		t.Fatalf("locked checkPIN = (%v, %v), want (false, >0)", ok, retry)
	}
}

func TestAGUpgradePINHashSkipsWhenHashChangedMeanwhile(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "654321")
	s := a.loadSettings()
	current := s.AdminSecretHash

	// the stored hash is no longer the one that was verified: leave it alone
	a.upgradePINHash("654321", "some-older-hash")
	if got := a.loadSettings().AdminSecretHash; got != current {
		t.Errorf("hash replaced although it changed in the meantime: %q", got)
	}
	// ... and when it is still the verified one, it is replaced by a fresh salted hash
	a.upgradePINHash("654321", current)
	if got := a.loadSettings().AdminSecretHash; got == current || !strings.HasPrefix(got, pinKDFName+"$") {
		t.Errorf("hash not re-salted: %q", got)
	}
}

func TestAGLockedResponseRoundsRetryUp(t *testing.T) {
	rec := httptest.NewRecorder()
	lockedResponse(rec, 1500*time.Millisecond)
	if rec.Code != 429 || rec.Header().Get("Retry-After") != strconv.Itoa(2) {
		t.Errorf("code=%d Retry-After=%q, want 429 and 2", rec.Code, rec.Header().Get("Retry-After"))
	}
	if !strings.Contains(rec.Body.String(), `"retryAfter":2`) {
		t.Errorf("body = %s", rec.Body.String())
	}
}

func TestAGSaveSettingsFailsWhenDirectoryIsMissing(t *testing.T) {
	root := t.TempDir()
	a := &Actions{docker: &Docker{confDir: filepath.Join(root, "missing", "conf.d")}}
	if err := a.saveSettings(Settings{}); err == nil {
		t.Fatal("saveSettings into a missing directory must report an error")
	}
	if _, err := os.Stat(filepath.Join(root, "missing")); err == nil {
		t.Error("saveSettings must not create the parent directory")
	}
}

func TestAGSaveSettingsLeavesNoTempFileAndKeepsMode(t *testing.T) {
	a, _ := newTestActions(t)
	if err := a.saveSettings(Settings{}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(a.settingsPath())
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".settings-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
	fi, err := os.Stat(a.settingsPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("settings.json mode = %v, want 0600 (it holds the PIN hash and the bot token)", fi.Mode().Perm())
	}
}
