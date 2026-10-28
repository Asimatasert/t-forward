package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// ------------------------------------------------------------------ helpers

// tgReq is one request captured by the fake Telegram Bot API.
type tgReq struct {
	Path    string
	Method  string
	CT      string
	Payload map[string]string
}

// fakeTelegram points telegramAPI at an httptest server for the test. Every
// request is recorded on the returned channel (buffered; tests drain it).
// status/body are what the fake answers with.
func fakeTelegram(t *testing.T, status int, body string) <-chan tgReq {
	t.Helper()
	ch := make(chan tgReq, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var p map[string]string
		_ = json.Unmarshal(raw, &p)
		ch <- tgReq{Path: r.URL.Path, Method: r.Method, CT: r.Header.Get("Content-Type"), Payload: p}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	old := telegramAPI
	telegramAPI = srv.URL
	t.Cleanup(func() {
		telegramAPI = old
		srv.Close()
	})
	return ch
}

func recvTG(t *testing.T, ch <-chan tgReq) tgReq {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("no request reached the fake Telegram API")
		return tgReq{}
	}
}

// expectNoTG fails if a request shows up shortly after the (synchronous part
// of the) call under test. The notify goroutine is spawned before the call
// returns, so a short grace period is enough for a negative check.
func expectNoTG(t *testing.T, ch <-chan tgReq) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("unexpected Telegram request: %+v", r)
	case <-time.After(150 * time.Millisecond):
	}
}

// writeSettings persists s beside the env's conf.d via the production saver.
func (e *actEnv) writeSettings(t *testing.T, s Settings) {
	t.Helper()
	if err := e.a.saveSettings(s); err != nil {
		t.Fatalf("saveSettings: %v", err)
	}
}

// ------------------------------------------------------- scrubTelegramErr

func TestNotifyScrubTelegramErr(t *testing.T) {
	const token = "123456:AAH-secret"

	t.Run("url.Error is unwrapped so the request URL never shows", func(t *testing.T) {
		inner := errors.New("dial tcp: connection refused")
		err := scrubTelegramErr(&url.Error{Op: "Post", URL: "https://api.telegram.org/bot" + token + "/sendMessage", Err: inner}, token)
		if got, want := err.Error(), "telegram request failed: dial tcp: connection refused"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("token inside a plain error is masked", func(t *testing.T) {
		err := scrubTelegramErr(fmt.Errorf("boom while using %s twice: %s", token, token), token)
		if strings.Contains(err.Error(), token) {
			t.Errorf("token leaked: %v", err)
		}
		if got, want := err.Error(), "telegram request failed: boom while using *** twice: ***"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("token inside a wrapped url.Error's cause is masked", func(t *testing.T) {
		ue := &url.Error{Op: "Post", URL: "x", Err: errors.New("bad host for bot" + token)}
		err := scrubTelegramErr(fmt.Errorf("wrapped: %w", ue), token)
		if strings.Contains(err.Error(), token) {
			t.Errorf("token leaked: %v", err)
		}
	})

	t.Run("empty token does not mangle the message", func(t *testing.T) {
		err := scrubTelegramErr(errors.New("plain"), "")
		if got := err.Error(); got != "telegram request failed: plain" {
			t.Errorf("got %q", got)
		}
	})
}

// ----------------------------------------------------------- sendTelegram

func TestNotifySendTelegramNotConfigured(t *testing.T) {
	ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
	for _, c := range []struct{ token, chat string }{{"", ""}, {"tok", ""}, {"", "42"}} {
		err := sendTelegram(c.token, c.chat, "", "hi")
		if err == nil || err.Error() != "telegram not configured" {
			t.Errorf("sendTelegram(%q,%q) = %v, want 'telegram not configured'", c.token, c.chat, err)
		}
	}
	expectNoTG(t, ch)
}

func TestNotifySendTelegramRequestShape(t *testing.T) {
	t.Run("posts JSON to /bot<token>/sendMessage without a thread", func(t *testing.T) {
		ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
		if err := sendTelegram("123:abc", "-1001", "", "hello ✅"); err != nil {
			t.Fatalf("sendTelegram: %v", err)
		}
		r := recvTG(t, ch)
		if r.Method != http.MethodPost || r.Path != "/bot123:abc/sendMessage" {
			t.Errorf("request = %s %s", r.Method, r.Path)
		}
		if r.CT != "application/json" {
			t.Errorf("content-type = %q", r.CT)
		}
		if r.Payload["chat_id"] != "-1001" || r.Payload["text"] != "hello ✅" {
			t.Errorf("payload = %v", r.Payload)
		}
		if _, has := r.Payload["message_thread_id"]; has {
			t.Errorf("empty thread id must be omitted, payload = %v", r.Payload)
		}
	})

	t.Run("thread id is sent as message_thread_id", func(t *testing.T) {
		ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
		if err := sendTelegram("tok", "@chan", "77", "x"); err != nil {
			t.Fatalf("sendTelegram: %v", err)
		}
		r := recvTG(t, ch)
		if r.Payload["message_thread_id"] != "77" || r.Payload["chat_id"] != "@chan" {
			t.Errorf("payload = %v", r.Payload)
		}
	})
}

func TestNotifySendTelegramAPIErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{"description is surfaced", http.StatusBadRequest, `{"ok":false,"description":"Bad Request: chat not found"}`, "telegram: Bad Request: chat not found"},
		{"no description falls back to the status", http.StatusForbidden, `{"ok":false}`, "telegram api: 403 Forbidden"},
		{"non-JSON body falls back to the status", http.StatusBadGateway, `<html>oops</html>`, "telegram api: 502 Bad Gateway"},
		{"empty body falls back to the status", http.StatusInternalServerError, ``, "telegram api: 500 Internal Server Error"},
		{"any non-200 is an error, even 201", http.StatusCreated, `{"ok":true}`, "telegram api: 201 Created"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeTelegram(t, tc.status, tc.body)
			err := sendTelegram("tok", "42", "", "x")
			if err == nil || err.Error() != tc.want {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNotifySendTelegramTransportErrorScrubsToken(t *testing.T) {
	old := telegramAPI
	t.Cleanup(func() { telegramAPI = old })
	telegramAPI = "http://127.0.0.1:1" // closed port
	const token = "999:TOPSECRET"
	err := sendTelegram(token, "42", "", "x")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "TOPSECRET") || !strings.HasPrefix(err.Error(), "telegram request failed: ") {
		t.Errorf("err = %v", err)
	}
}

// -------------------------------------------------------------- notifyState

func TestNotifyStateSkips(t *testing.T) {
	allOn := Settings{
		Telegram: TelegramConf{BotToken: "tok", ChatID: "42"},
		Notify:   NotifyConf{Down: true, Up: true, Warn: true, Reach: true},
	}

	t.Run("no settings file", func(t *testing.T) {
		e := newActEnv(t)
		ch := fakeTelegram(t, http.StatusOK, `{}`)
		e.d.notifyState("down", "prod", "msg")
		expectNoTG(t, ch)
	})

	t.Run("event disabled", func(t *testing.T) {
		e := newActEnv(t)
		s := allOn
		s.Notify.Up = false
		e.writeSettings(t, s)
		ch := fakeTelegram(t, http.StatusOK, `{}`)
		e.d.notifyState("up", "prod", "msg")
		expectNoTG(t, ch)
	})

	t.Run("unknown event kind is never enabled", func(t *testing.T) {
		e := newActEnv(t)
		e.writeSettings(t, allOn)
		ch := fakeTelegram(t, http.StatusOK, `{}`)
		e.d.notifyState("bogus", "prod", "msg")
		e.d.notifyState("", "prod", "msg")
		expectNoTG(t, ch)
	})

	t.Run("missing token", func(t *testing.T) {
		e := newActEnv(t)
		s := allOn
		s.Telegram.BotToken = ""
		e.writeSettings(t, s)
		ch := fakeTelegram(t, http.StatusOK, `{}`)
		e.d.notifyState("down", "prod", "msg")
		expectNoTG(t, ch)
	})

	t.Run("missing chat id", func(t *testing.T) {
		e := newActEnv(t)
		s := allOn
		s.Telegram.ChatID = ""
		e.writeSettings(t, s)
		ch := fakeTelegram(t, http.StatusOK, `{}`)
		e.d.notifyState("down", "prod", "msg")
		expectNoTG(t, ch)
	})
}

func TestNotifyStateSendsToEventTopic(t *testing.T) {
	e := newActEnv(t)
	e.writeSettings(t, Settings{
		Telegram: TelegramConf{
			BotToken: "tok", ChatID: "42",
			Topics: map[string]string{"down": "11", "warn": "33"},
		},
		Notify: NotifyConf{Down: true, Up: true, Warn: true, Reach: true},
	})
	ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)

	for _, tc := range []struct{ kind, topic string }{
		{"down", "11"},
		{"warn", "33"},
		{"up", ""},    // no topic configured -> General
		{"reach", ""}, // ditto
	} {
		e.d.notifyState(tc.kind, "prod", "msg-"+tc.kind)
		r := recvTG(t, ch)
		if r.Path != "/bottok/sendMessage" || r.Payload["chat_id"] != "42" {
			t.Errorf("%s: request = %+v", tc.kind, r)
		}
		if r.Payload["text"] != "msg-"+tc.kind {
			t.Errorf("%s: text = %q", tc.kind, r.Payload["text"])
		}
		if got := r.Payload["message_thread_id"]; got != tc.topic {
			t.Errorf("%s: message_thread_id = %q, want %q", tc.kind, got, tc.topic)
		}
	}
}

func TestNotifyStateFailureGoesToEventStream(t *testing.T) {
	e := newActEnv(t)
	const token = "555:LEAKME"
	e.writeSettings(t, Settings{
		Telegram: TelegramConf{BotToken: token, ChatID: "42"},
		Notify:   NotifyConf{Down: true},
	})
	fakeTelegram(t, http.StatusBadRequest, `{"ok":false,"description":"chat not found"}`)
	c := e.hub.register()

	e.d.notifyState("down", "prod", "tunnel prod is down")

	deadline := time.After(5 * time.Second)
	for {
		for _, ev := range drainEvents(c) {
			msg, _ := ev["msg"].(string)
			if !strings.HasPrefix(msg, "telegram notify failed: ") {
				continue
			}
			if ev["level"] != "error" || ev["tun"] != "prod" {
				t.Errorf("event = %v, want level=error tun=prod", ev)
			}
			if !strings.Contains(msg, "chat not found") {
				t.Errorf("msg = %q, want the API description", msg)
			}
			if strings.Contains(msg, token) {
				t.Errorf("token leaked into the event stream: %q", msg)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("no 'telegram notify failed' event was broadcast")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNotifyStateReadsSettingsFreshEachCall(t *testing.T) {
	e := newActEnv(t)
	ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
	e.d.notifyState("down", "prod", "before")
	expectNoTG(t, ch)

	e.writeSettings(t, Settings{
		Telegram: TelegramConf{BotToken: "tok", ChatID: "42"},
		Notify:   NotifyConf{Down: true},
	})
	e.d.notifyState("down", "prod", "after")
	if r := recvTG(t, ch); r.Payload["text"] != "after" {
		t.Errorf("payload = %v", r.Payload)
	}
}

// --------------------------------------------------------- handleNotifyTest

func TestNotifyHandleNotifyTest(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		e := newActEnv(t)
		ch := fakeTelegram(t, http.StatusOK, `{}`)
		for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
			if rec := doReq(e.a.handleNotifyTest, m, "/notify/test", `{}`); rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s: status = %d, want 405", m, rec.Code)
			}
		}
		expectNoTG(t, ch)
	})

	t.Run("nothing configured", func(t *testing.T) {
		e := newActEnv(t)
		ch := fakeTelegram(t, http.StatusOK, `{}`)
		rec := doReq(e.a.handleNotifyTest, http.MethodPost, "/notify/test", `{}`)
		m := jsonBody(t, rec)
		if rec.Code != http.StatusOK || m["ok"] != false || m["error"] != "telegram not configured" {
			t.Errorf("status %d response %v", rec.Code, m)
		}
		expectNoTG(t, ch)
	})

	t.Run("request values are used without saving", func(t *testing.T) {
		e := newActEnv(t)
		ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
		body := `{"telegramToken":"reqtok","telegramChatId":"-100","topicId":"9","event":"down"}`
		m := jsonBody(t, doReq(e.a.handleNotifyTest, http.MethodPost, "/notify/test", body))
		if m["ok"] != true {
			t.Fatalf("response = %v", m)
		}
		r := recvTG(t, ch)
		if r.Path != "/botreqtok/sendMessage" || r.Payload["chat_id"] != "-100" || r.Payload["message_thread_id"] != "9" {
			t.Errorf("request = %+v", r)
		}
		if want := "✅ t-forward test notification (down)"; r.Payload["text"] != want {
			t.Errorf("text = %q, want %q", r.Payload["text"], want)
		}
		if _, err := os.Stat(settingsPathFor(e.d.confDir)); !os.IsNotExist(err) {
			t.Errorf("handleNotifyTest wrote settings.json (stat err = %v)", err)
		}
	})

	t.Run("falls back to persisted token, chat and the event's topic", func(t *testing.T) {
		e := newActEnv(t)
		e.writeSettings(t, Settings{Telegram: TelegramConf{
			BotToken: "savedtok", ChatID: "777", Topics: map[string]string{"warn": "55"},
		}})
		ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
		m := jsonBody(t, doReq(e.a.handleNotifyTest, http.MethodPost, "/notify/test", `{"event":"warn"}`))
		if m["ok"] != true {
			t.Fatalf("response = %v", m)
		}
		r := recvTG(t, ch)
		if r.Path != "/botsavedtok/sendMessage" || r.Payload["chat_id"] != "777" || r.Payload["message_thread_id"] != "55" {
			t.Errorf("request = %+v", r)
		}
		if !strings.HasSuffix(r.Payload["text"], "(warn)") {
			t.Errorf("text = %q", r.Payload["text"])
		}
	})

	t.Run("request topicId beats the saved topic; request token beats saved", func(t *testing.T) {
		e := newActEnv(t)
		e.writeSettings(t, Settings{Telegram: TelegramConf{
			BotToken: "savedtok", ChatID: "777", Topics: map[string]string{"up": "55"},
		}})
		ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
		doReq(e.a.handleNotifyTest, http.MethodPost, "/notify/test", `{"event":"up","topicId":"66","telegramToken":"newtok"}`)
		r := recvTG(t, ch)
		if r.Path != "/botnewtok/sendMessage" || r.Payload["message_thread_id"] != "66" || r.Payload["chat_id"] != "777" {
			t.Errorf("request = %+v", r)
		}
	})

	t.Run("no event means the general label and no saved topic", func(t *testing.T) {
		e := newActEnv(t)
		e.writeSettings(t, Settings{Telegram: TelegramConf{
			BotToken: "tok", ChatID: "1", Topics: map[string]string{"down": "11"},
		}})
		ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
		doReq(e.a.handleNotifyTest, http.MethodPost, "/notify/test", `{}`)
		r := recvTG(t, ch)
		if _, has := r.Payload["message_thread_id"]; has {
			t.Errorf("payload = %v, want no thread", r.Payload)
		}
		if !strings.HasSuffix(r.Payload["text"], "(general)") {
			t.Errorf("text = %q", r.Payload["text"])
		}
	})

	t.Run("Telegram API error is reported in the body, HTTP 200", func(t *testing.T) {
		e := newActEnv(t)
		fakeTelegram(t, http.StatusUnauthorized, `{"ok":false,"description":"Unauthorized"}`)
		rec := doReq(e.a.handleNotifyTest, http.MethodPost, "/notify/test", `{"telegramToken":"t","telegramChatId":"1"}`)
		m := jsonBody(t, rec)
		if rec.Code != http.StatusOK || m["ok"] != false || m["error"] != "telegram: Unauthorized" {
			t.Errorf("status %d response %v", rec.Code, m)
		}
	})

	t.Run("transport error does not leak the token", func(t *testing.T) {
		e := newActEnv(t)
		old := telegramAPI
		t.Cleanup(func() { telegramAPI = old })
		telegramAPI = "http://127.0.0.1:1"
		rec := doReq(e.a.handleNotifyTest, http.MethodPost, "/notify/test", `{"telegramToken":"9:SECRETTOK","telegramChatId":"1"}`)
		if strings.Contains(rec.Body.String(), "SECRETTOK") {
			t.Errorf("token leaked in response: %s", rec.Body.String())
		}
		if m := jsonBody(t, rec); m["ok"] != false {
			t.Errorf("response = %v", m)
		}
	})
}

// The route is registered as acts.privileged(acts.handleNotifyTest): once an
// admin PIN exists, an unauthenticated POST must be refused before Telegram is
// ever contacted.
func TestNotifyTestEndpointIsPrivileged(t *testing.T) {
	e := newActEnv(t)
	setPIN(t, e.a, "correct-pin")
	ch := fakeTelegram(t, http.StatusOK, `{"ok":true}`)
	h := e.a.privileged(e.a.handleNotifyTest)

	rec := doReq(h, http.MethodPost, "/notify/test", `{"telegramToken":"t","telegramChatId":"1"}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if m := jsonBody(t, rec); m["needPin"] != true {
		t.Errorf("response = %v, want needPin", m)
	}
	expectNoTG(t, ch)

	// with a valid session the same request goes through
	unlock := postJSON(e.a.handleAdminUnlock, "/admin/unlock", `{"pin":"correct-pin"}`, nil)
	c := adminCookie(unlock)
	if c == nil {
		t.Fatalf("unlock did not set a cookie: %d %s", unlock.Code, unlock.Body.String())
	}
	req := httptest.NewRequest(http.MethodPost, "/notify/test", strings.NewReader(`{"telegramToken":"t","telegramChatId":"1"}`))
	req.AddCookie(c)
	ok := httptest.NewRecorder()
	h(ok, req)
	if m := jsonBody(t, ok); m["ok"] != true {
		t.Errorf("authenticated response = %v", m)
	}
	recvTG(t, ch)
}
