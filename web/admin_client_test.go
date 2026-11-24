package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// unlockFrom POSTs /admin/unlock as a client connecting from addr.
func unlockFrom(a *Actions, addr, pin string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/unlock", strings.NewReader(`{"pin":"`+pin+`"}`))
	req.RemoteAddr = addr
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	a.handleAdminUnlock(rec, req)
	return rec
}

// One client's wrong guesses must not lock the real operator out.
func TestUnlockLockoutIsPerClient(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "right-pin")
	const attacker, operator = "198.51.100.7:40000", "203.0.113.9:51000"
	for i := 0; i < 3*lockAfterFail; i++ {
		// forwarded-for headers are not trusted: spoofing one changes nothing
		unlockFrom(a, attacker, "guess", map[string]string{"X-Forwarded-For": "203.0.113.9"})
	}
	if rec := unlockFrom(a, attacker, "right-pin", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the guessing client: status %d, want 429", rec.Code)
	}
	if rec := unlockFrom(a, operator, "right-pin", nil); rec.Code != http.StatusOK {
		t.Fatalf("another client was locked out by the first one: status %d %s", rec.Code, rec.Body.String())
	}
	// same address, other source port: still the same client
	if rec := unlockFrom(a, "198.51.100.7:40001", "right-pin", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a new source port reset the backoff: status %d", rec.Code)
	}
}
