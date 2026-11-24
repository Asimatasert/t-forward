package main

import (
	"regexp"
	"testing"
)

// A signed-out tab must not keep polling /state and /evlog every few seconds
// (the event stream already backs off on 401/403). Both pollers have to check
// the shared hold first and record a 401/403 answer. The behaviour itself is
// exercised in a real browser; this guards the wiring against regressions.
func TestPanelPollersBackOffWhenSignedOut(t *testing.T) {
	src := tEscPanel(t)
	for _, fn := range []string{"pullState", "pullEvlog"} {
		re := regexp.MustCompile(`(?s)async function ` + fn + `\(\) \{\s*if \(Date\.now\(\) < authHoldUntil\) return;.*?authHold\(r\)`)
		if !re.MatchString(src) {
			t.Errorf("%s() must return while authHoldUntil is in the future and call authHold(r) on the response", fn)
		}
	}
	if !regexp.MustCompile(`(?s)function authHold\(r\) \{.*?r\.status === 401 \|\| r\.status === 403.*?authHoldUntil = Date\.now\(\) \+ AUTH_HOLD_MS`).MatchString(src) {
		t.Error("authHold() must start a hold on 401/403")
	}
}
