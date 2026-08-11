package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// sendTelegram posts text to the given chat (optionally into one forum topic)
// via the Telegram Bot API. chatID accepts anything the API does: a numeric
// user/group id, a channel id (-100…), or a public channel's @username, as
// long as the bot is a member (channels: an admin) there. An empty threadID
// posts to the chat's General topic (or a non-forum chat).
func sendTelegram(token, chatID, threadID, text string) error {
	if token == "" || chatID == "" {
		return fmt.Errorf("telegram not configured")
	}
	payload := map[string]string{"chat_id": chatID, "text": text}
	if threadID != "" {
		payload["message_thread_id"] = threadID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(
		"https://api.telegram.org/bot"+token+"/sendMessage",
		"application/json", bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Description string `json:"description"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		if apiErr.Description != "" {
			return fmt.Errorf("telegram: %s", apiErr.Description)
		}
		return fmt.Errorf("telegram api: %s", resp.Status)
	}
	return nil
}

// handleNotifyTest: POST (privileged) — sends a test Telegram message for one
// notify event, using the request's token/chatId/topicId if given (so unsaved
// settings-modal edits can be tried before Save), falling back to the
// persisted settings + that event's configured topic otherwise. Nothing is
// written to disk here.
func (a *Actions) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := decodeBody(r)
	s := a.loadSettings()
	token, chatID := body["telegramToken"], body["telegramChatId"]
	if token == "" {
		token = s.Telegram.BotToken
	}
	if chatID == "" {
		chatID = s.Telegram.ChatID
	}
	event := body["event"]
	threadID := body["topicId"]
	if threadID == "" && event != "" {
		threadID = s.Telegram.Topics[event]
	}
	label := event
	if label == "" {
		label = "general"
	}
	if err := sendTelegram(token, chatID, threadID, fmt.Sprintf("✅ t-forward test notification (%s)", label)); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
