package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newTestActions returns Actions backed by a temp config tree with a fake clock.
func newTestActions(t *testing.T) (*Actions, *time.Time) {
	t.Helper()
	root := t.TempDir()
	confDir := filepath.Join(root, "conf.d")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := &Actions{docker: &Docker{confDir: confDir}}
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a.gate.now = func() time.Time { return clock }
	return a, &clock
}

func postJSON(h http.HandlerFunc, path, body string, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func adminCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "tf_admin" {
			return c
		}
	}
	return nil
}

func setPIN(t *testing.T, a *Actions, pin string) {
	t.Helper()
	// first-run bootstrap: no PIN yet, so the POST is open
	rec := postJSON(a.handleSettings, "/settings", `{"adminPin":"`+pin+`"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("set pin: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPINHashIsSaltedAndVerifies(t *testing.T) {
	h1, h2 := hashPIN("correct horse"), hashPIN("correct horse")
	if h1 == h2 {
		t.Fatal("two hashes of the same PIN are identical: no salt")
	}
	if !strings.HasPrefix(h1, pinKDFName+"$") {
		t.Fatalf("unexpected hash format %q", h1)
	}
	if ok, legacy := verifyPIN("correct horse", h1); !ok || legacy {
		t.Fatalf("verify own hash: ok=%v legacy=%v", ok, legacy)
	}
	if ok, _ := verifyPIN("wrong", h1); ok {
		t.Fatal("wrong PIN verified")
	}
	if ok, _ := verifyPIN("anything", ""); ok {
		t.Fatal("empty stored hash must never verify")
	}
}

func TestLegacySHA256HashStillWorksAndIsUpgraded(t *testing.T) {
	a, _ := newTestActions(t)
	// PIN "123456" stored the way v0.8.0 did: hex(sha256(pin))
	const legacyHash = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
	if err := a.saveSettings(Settings{AdminSecretHash: legacyHash}); err != nil {
		t.Fatal(err)
	}
	rec := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"123456"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy PIN rejected: %d", rec.Code)
	}
	got := a.loadSettings().AdminSecretHash
	if got == legacyHash || !strings.HasPrefix(got, pinKDFName+"$") {
		t.Fatalf("hash not upgraded: %q", got)
	}
	if rec := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"123456"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("PIN rejected after upgrade: %d", rec.Code)
	}
}

func TestCookieCarriesSessionNotPIN(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "s3cret-pin")
	rec := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"s3cret-pin"}`, nil)
	c := adminCookie(rec)
	if rec.Code != http.StatusOK || c == nil {
		t.Fatalf("unlock failed: %d", rec.Code)
	}
	if strings.Contains(c.Value, "s3cret-pin") || len(c.Value) < 32 {
		t.Fatalf("cookie must be an opaque session token, got %q", c.Value)
	}
	// the session passes the gate...
	req := httptest.NewRequest(http.MethodPost, "/conf/x", nil)
	req.AddCookie(c)
	if !a.requirePrivileged(httptest.NewRecorder(), req) {
		t.Fatal("valid session rejected")
	}
	// ...but the PIN itself in the cookie (the old behaviour) does not
	req = httptest.NewRequest(http.MethodPost, "/conf/x", nil)
	req.AddCookie(&http.Cookie{Name: "tf_admin", Value: "s3cret-pin"})
	if a.requirePrivileged(httptest.NewRecorder(), req) {
		t.Fatal("PIN accepted as cookie value")
	}
}

func TestSessionExpiresAndPINChangeRevokes(t *testing.T) {
	a, clock := newTestActions(t)
	setPIN(t, a, "first-pin")
	c := adminCookie(postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"first-pin"}`, nil))
	check := func() bool {
		req := httptest.NewRequest(http.MethodPost, "/conf/x", nil)
		req.AddCookie(c)
		return a.requirePrivileged(httptest.NewRecorder(), req)
	}
	if !check() {
		t.Fatal("fresh session rejected")
	}
	// rotating the PIN (authorised by the session) revokes old sessions
	rec := postJSON(a.handleSettings, "/settings", `{"adminPin":"second-pin"}`, nil, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate pin: %d %s", rec.Code, rec.Body.String())
	}
	if check() {
		t.Fatal("old session survived a PIN change")
	}
	fresh := adminCookie(rec)
	if fresh == nil {
		t.Fatal("PIN change should hand the caller a new session")
	}
	// expiry
	*clock = clock.Add(sessionTTL + time.Minute)
	c = fresh
	if check() {
		t.Fatal("expired session accepted")
	}
}

func TestUnlockLockout(t *testing.T) {
	a, clock := newTestActions(t)
	setPIN(t, a, "right-pin")
	for i := 0; i < lockAfterFail; i++ {
		rec := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"nope-`+strconv.Itoa(i)+`"}`, nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("attempt %d: want 403, got %d", i, rec.Code)
		}
	}
	// locked: even the correct PIN is refused without being evaluated
	rec := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"right-pin"}`, nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("want 429 + Retry-After while locked, got %d", rec.Code)
	}
	if adminCookie(rec) != nil {
		t.Fatal("no session may be issued while locked")
	}
	// the API path (PIN in X-Admin-Token) is behind the same lockout
	rec = postJSON(func(w http.ResponseWriter, r *http.Request) {
		if a.requirePrivileged(w, r) {
			w.WriteHeader(http.StatusOK)
		}
	}, "/conf/x", `{}`, map[string]string{"X-Admin-Token": "right-pin"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("header PIN during lockout: want 429, got %d", rec.Code)
	}
	// after the wait the correct PIN works and resets the counter
	*clock = clock.Add(2 * time.Second)
	if rec := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"right-pin"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("correct PIN after lockout: %d", rec.Code)
	}
	if a.gate.fails != 0 {
		t.Fatal("success should reset the failure counter")
	}
}

func TestStaleCookieDoesNotTriggerLockout(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "right-pin")
	for i := 0; i < 3*lockAfterFail; i++ {
		req := httptest.NewRequest(http.MethodPost, "/conf/x", nil)
		req.AddCookie(&http.Cookie{Name: "tf_admin", Value: "stale-session-from-before-restart"})
		rec := httptest.NewRecorder()
		if a.requirePrivileged(rec, req) {
			t.Fatal("stale session accepted")
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("want plain 403, got %d", rec.Code)
		}
	}
	if rec := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"right-pin"}`, nil); rec.Code != http.StatusOK {
		t.Fatalf("legit unlock blocked by cookie noise: %d", rec.Code)
	}
}

func TestShortPINRejected(t *testing.T) {
	a, _ := newTestActions(t)
	rec := postJSON(a.handleSettings, "/settings", `{"adminPin":"12345"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("5-char PIN: want 400, got %d", rec.Code)
	}
	if a.loadSettings().AdminSecretHash != "" {
		t.Fatal("a rejected PIN must not be stored")
	}
}
