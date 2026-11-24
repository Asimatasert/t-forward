package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A session token replayed as X-Admin-Token, or a value too short to be a PIN,
// is refused but is not a guess: it must not feed the lockout.
func TestNonPINHeaderValuesDoNotCountTowardsLockout(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "right-pin")
	live := a.gate.newSession()
	for _, v := range []string{live, "short", "12345"} {
		for i := 0; i < 3*lockAfterFail; i++ {
			req := httptest.NewRequest(http.MethodPost, "/conf/x", nil)
			req.Header.Set("X-Admin-Token", v)
			rec := httptest.NewRecorder()
			if a.requirePrivileged(rec, req) {
				t.Fatalf("%q accepted", v)
			}
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%q: status %d, want 403", v, rec.Code)
			}
		}
	}
	if a.gate.fails != 0 {
		t.Fatalf("gate.fails = %d, want 0", a.gate.fails)
	}
	req := httptest.NewRequest(http.MethodPost, "/conf/x", nil)
	req.Header.Set("X-Admin-Token", "right-pin")
	if !a.requirePrivileged(httptest.NewRecorder(), req) {
		t.Fatal("the real PIN was refused")
	}
}

// A well-shaped wrong PIN in the header still counts.
func TestWrongPINInHeaderStillCounts(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "right-pin")
	req := httptest.NewRequest(http.MethodPost, "/conf/x", nil)
	req.Header.Set("X-Admin-Token", "wrong-pin")
	a.requirePrivileged(httptest.NewRecorder(), req)
	if a.gate.fails != 1 {
		t.Fatalf("gate.fails = %d, want 1", a.gate.fails)
	}
}
