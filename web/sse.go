package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
)

// Hub is a minimal server-sent-events fan-out. Clients register with two
// delivery paths: a lossy buffered channel for high-frequency 'stat'/'event'
// frames (dropped under back-pressure) and a coalesce-latest 'state' slot that
// is guaranteed to deliver the most recent snapshot (overwritten, never
// silently lost). Broadcast never blocks the caller.
type Hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}

	// SnapshotFn returns the event type and payload sent to a client the
	// moment it connects (a full 'state' snapshot).
	SnapshotFn func() (string, any)

	// Recent 'event' frames, kept so browsers whose SSE stream is buffered by
	// an intermediary proxy can poll GET /evlog?since=SEQ instead and still
	// render the console.
	evMu   sync.Mutex
	evSeq  int64
	evRing []evEntry
}

// evEntry is one recorded console event with its monotonically-increasing id.
type evEntry struct {
	Seq int64 `json:"seq"`
	Ev  any   `json:"ev"`
}

// evCap bounds the ring; old entries fall off (a late poller just misses them,
// same as a lossy SSE drop).
const evCap = 250

// client holds the two delivery paths for one connected browser.
//
//   - lossy carries stat/event frames; a full buffer drops the frame.
//   - state is a coalesce-latest slot (capacity 1): a newer 'state' snapshot
//     always replaces an undelivered older one, so a stalled client can miss
//     intermediate snapshots but never ends up stale on the current one.
type client struct {
	lossy chan []byte
	state chan []byte
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*client]struct{})}
}

// frame renders one SSE frame: "event: <type>\ndata: <json>\n\n".
func frame(eventType string, payload any) []byte {
	data, err := json.Marshal(payload)
	if err != nil {
		data = []byte("null")
	}
	return []byte(fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, data))
}

// pushState delivers a 'state' frame with coalesce-latest semantics: if a prior
// snapshot is still queued it is discarded in favour of this newer one, so the
// slot always holds the freshest state and delivery is never skipped.
func pushState(ch chan []byte, f []byte) {
	for {
		select {
		case ch <- f:
			return
		default:
			// Slot full with a stale snapshot: drain it and retry so the
			// latest state wins. Guard the drain with a default in case the
			// reader emptied it concurrently.
			select {
			case <-ch:
			default:
			}
		}
	}
}

// Broadcast marshals payload and fans it out to all clients. It never blocks the
// hub. 'state' frames take the guaranteed coalesce-latest path; all other
// frames take the lossy path and may be dropped for a slow client.
func (h *Hub) Broadcast(eventType string, payload any) {
	if eventType == "event" {
		h.evMu.Lock()
		h.evSeq++
		// Stamp the seq into the SSE payload too, so a client that receives an
		// event live can advance its /evlog cursor and never re-render it as a
		// duplicate when it later falls back to polling.
		if m, ok := payload.(map[string]any); ok {
			m["seq"] = h.evSeq
		}
		h.evRing = append(h.evRing, evEntry{Seq: h.evSeq, Ev: payload})
		if len(h.evRing) > evCap {
			h.evRing = h.evRing[len(h.evRing)-evCap:]
		}
		h.evMu.Unlock()
	}
	f := frame(eventType, payload)
	reliable := eventType == "state"
	h.mu.Lock()
	for c := range h.clients {
		if reliable {
			pushState(c.state, f)
			continue
		}
		select {
		case c.lossy <- f:
		default:
			// slow client: drop this stat/event frame rather than block the hub
		}
	}
	h.mu.Unlock()
}

func (h *Hub) register() *client {
	c := &client{
		lossy: make(chan []byte, 64),
		state: make(chan []byte, 1),
	}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	return c
}

func (h *Hub) unregister(c *client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// ServeEvLog answers the polling fallback for the console: the recorded events
// newer than ?since=SEQ plus the current sequence, as plain JSON.
func (h *Hub) ServeEvLog(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	h.evMu.Lock()
	out := make([]evEntry, 0, 16)
	for _, e := range h.evRing {
		if e.Seq > since {
			out = append(out, e)
		}
	}
	seq := h.evSeq
	h.evMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"seq": seq, "events": out})
}

// ServeHTTP streams events to a single client until its request context is
// cancelled. It sends a state snapshot on connect, then relays broadcasts,
// always preferring pending 'state' frames so transitions are never masked by a
// backlog of stat/event frames.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	c := h.register()
	defer h.unregister(c)

	// initial full-state snapshot
	if h.SnapshotFn != nil {
		et, payload := h.SnapshotFn()
		if _, err := w.Write(frame(et, payload)); err != nil {
			return
		}
		flusher.Flush()
	}

	ctx := r.Context()
	for {
		// Prioritise the reliable 'state' path: if a snapshot is pending, send
		// it before servicing lossy frames so a stat/event backlog cannot delay
		// a state transition.
		select {
		case <-ctx.Done():
			return
		case f := <-c.state:
			if _, err := w.Write(f); err != nil {
				return
			}
			flusher.Flush()
			continue
		default:
		}

		select {
		case <-ctx.Done():
			return
		case f := <-c.state:
			if _, err := w.Write(f); err != nil {
				return
			}
			flusher.Flush()
		case f := <-c.lossy:
			if _, err := w.Write(f); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}
