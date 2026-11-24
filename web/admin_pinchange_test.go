package main

import (
	"net/http"
	"testing"
)

// Changing an existing PIN needs the current one on top of the admin gate.
func TestPINChangeRequiresCurrentPIN(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "first-pin")
	unlock := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"first-pin"}`, nil)
	c, hdr := adminCookie(unlock), map[string]string{"X-Admin-Key": adminKey(unlock)}
	if c == nil || hdr["X-Admin-Key"] == "" {
		t.Fatal("unlock failed")
	}
	stillFirst := func(t *testing.T) {
		t.Helper()
		if ok, _ := verifyPIN("first-pin", a.loadSettings().AdminSecretHash); !ok {
			t.Fatal("the PIN was replaced by a request without the current PIN")
		}
	}
	for name, body := range map[string]string{
		"no current PIN":    `{"adminPin":"second-pin"}`,
		"empty current PIN": `{"adminPin":"second-pin","currentPin":""}`,
		"wrong current PIN": `{"adminPin":"second-pin","currentPin":"not-the-pin"}`,
	} {
		rec := postJSON(a.handleSettings, "/settings", body, hdr, c)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (%s)", name, rec.Code, rec.Body.String())
		}
		if m := jsonBody(t, rec); m["needPin"] == true {
			t.Errorf("%s: a wrong current PIN must not read as a locked session: %v", name, m)
		}
		if adminCookie(rec) != nil {
			t.Errorf("%s: no session may be issued", name)
		}
		stillFirst(t)
	}
	// other settings still save with a live session alone
	if rec := postJSON(a.handleSettings, "/settings", `{"telegramChatId":"42"}`, hdr, c); rec.Code != http.StatusOK {
		t.Errorf("non-PIN save: status %d", rec.Code)
	}
	// the right current PIN rotates it
	rec := postJSON(a.handleSettings, "/settings", `{"adminPin":"second-pin","currentPin":"first-pin"}`, hdr, c)
	if rec.Code != http.StatusOK || adminKey(rec) == "" {
		t.Fatalf("rotate: status %d %s", rec.Code, rec.Body.String())
	}
	if ok, _ := verifyPIN("second-pin", a.loadSettings().AdminSecretHash); !ok {
		t.Error("PIN not rotated")
	}
}

// Wrong current PINs count towards the lockout, like wrong unlock attempts.
func TestPINChangeWrongCurrentPINCountsTowardsLockout(t *testing.T) {
	a, _ := newTestActions(t)
	setPIN(t, a, "first-pin")
	unlock := postJSON(a.handleAdminUnlock, "/admin/unlock", `{"pin":"first-pin"}`, nil)
	c, hdr := adminCookie(unlock), map[string]string{"X-Admin-Key": adminKey(unlock)}
	for i := 0; i < lockAfterFail; i++ {
		postJSON(a.handleSettings, "/settings", `{"adminPin":"second-pin","currentPin":"guess"}`, hdr, c)
	}
	rec := postJSON(a.handleSettings, "/settings", `{"adminPin":"second-pin","currentPin":"first-pin"}`, hdr, c)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status %d, want 429 once locked", rec.Code)
	}
	if ok, _ := verifyPIN("first-pin", a.loadSettings().AdminSecretHash); !ok {
		t.Error("PIN replaced while locked")
	}
}

// Setting the first PIN stays open and needs no current PIN.
func TestFirstPINNeedsNoCurrentPIN(t *testing.T) {
	a, _ := newTestActions(t)
	rec := postJSON(a.handleSettings, "/settings", `{"adminPin":"first-pin"}`, nil)
	if rec.Code != http.StatusOK || adminCookie(rec) == nil {
		t.Fatalf("first PIN: status %d %s", rec.Code, rec.Body.String())
	}
}
