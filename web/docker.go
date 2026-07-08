package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const label = "t-forward"

// Forward is one published port relay.
type Forward struct {
	Local   string `json:"local"`
	Remote  string `json:"remote"`
	Service string `json:"service"`        // ssh/http/postgres… (auto from port, or @override)
	User    string `json:"user,omitempty"` // optional service user (e.g. @ssh:root)
	Note    string `json:"note,omitempty"` // optional per-forward note
}

// well-known service names by port; used to auto-label forwards. A forward may
// override this with an "@name" suffix in FORWARDS (e.g. 9281:host:80@http).
var services = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	110: "pop3", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
	587: "smtp", 993: "imaps", 995: "pop3s", 1080: "socks", 1433: "mssql",
	1521: "oracle", 2049: "nfs", 3000: "http-dev", 3306: "mysql", 3389: "rdp",
	5432: "postgres", 5601: "kibana", 5672: "amqp", 5900: "vnc", 6379: "redis",
	8000: "http-alt", 8080: "http", 8443: "https", 8888: "http-alt",
	9000: "http-alt", 9100: "jetdirect", 9200: "elastic", 11211: "memcached",
	15672: "rabbitmq", 27017: "mongodb",
}

func serviceForPort(port string) string {
	if p, err := strconv.Atoi(port); err == nil {
		return services[p]
	}
	return ""
}

// Tunnel is the read-only view of a configured and/or running tunnel.
type Tunnel struct {
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Desc     string    `json:"desc"`
	State    string    `json:"state"`
	Tags     []string  `json:"tags"`
	Forwards []Forward `json:"forwards"`
	Socks    string    `json:"socks"`
	Restart  bool      `json:"restart"`
	Totp     bool      `json:"totp"`
	// connection descriptors (from conf) used by the panel's "via" column
	Proto   string `json:"proto"`
	Server  string `json:"server"`
	SSHHost string `json:"sshHost"`
	User    string `json:"user"`
	// ordered ProxyJump hops (from ssh.jump) the ssh tunnel chains through
	SSHJump []string `json:"sshJump,omitempty"`
	// optional user name per remote host, e.g. {"10.0.0.5":"Production DB"}
	HostNotes map[string]string `json:"hostNotes"`
	// optional per-host tags (from each host's tags list)
	HostTags map[string][]string `json:"hostTags"`
	// optional user label/tags per VPN subnet (CIDR), from the subnets list.
	// The live CIDR itself is discovered at runtime (netinfo SSE); these decorate
	// the virtual subnet node the panel draws for it.
	SubnetNotes map[string]string   `json:"subnetNotes,omitempty"`
	SubnetTags  map[string][]string `json:"subnetTags,omitempty"`

	// live fields — also streamed over SSE (stat/hosts/netinfo/clients), but
	// included in /state too so the panel works by polling alone when the SSE
	// stream is blocked (e.g. by an SSE-buffering HTTP proxy).
	TxRate      int64             `json:"txRate,omitempty"`
	RxRate      int64             `json:"rxRate,omitempty"`
	HostUp      map[string]bool   `json:"hostUp,omitempty"`
	TunIP       string            `json:"tunIP,omitempty"`
	TunSubnet   string            `json:"tunSubnet,omitempty"`
	HostSubnets map[string]string `json:"hostSubnets,omitempty"`
	Clients     []Client          `json:"clients,omitempty"`
}

// liveData is the per-tunnel data the background loops compute; cached so State()
// can fold it into /state (SSE-independent).
type liveData struct {
	txRate, rxRate   int64
	hostUp           map[string]bool
	tunIP, tunSubnet string
	hostSubnets      map[string]string
	clients          []Client
}

// Docker collects all the live readers backed by the docker/CLI.
type Docker struct {
	hub      *Hub
	confDir  string // <config-dir>/conf.d
	stateDir string // <config-dir>/.auth
	tfPath   string // t-forward CLI, for auto-supplying TOTP codes
	// allowTotpCmd gates auto-execution of a tunnel's totp_command (sh -c). Off by
	// default: it is arbitrary command execution as the daemon user, so it must be
	// switched on explicitly (-allow-totp-command / TF_ALLOW_TOTP_COMMAND).
	allowTotpCmd bool

	mu      sync.Mutex
	tailers map[string]*tailer   // container name -> active tailer
	lastNet map[string]netSample // container name -> last stats sample
	armed   map[string]bool      // tunnel id -> TOTP_COMMAND already fired this wait
	// parsed-conf cache: State() runs every couple of seconds and would otherwise
	// fork yq for every conf each time. Keyed by tunnel name, invalidated on the
	// file's mtime/size changing.
	confCache map[string]confCacheEntry

	// latest live data per tunnel id (rates/reachability/netinfo/clients), so
	// State() can include it without relying on the SSE stream.
	live map[string]*liveData
}

// updateLive mutates (creating if needed) the cached live data for a tunnel id.
func (d *Docker) updateLive(id string, fn func(*liveData)) {
	d.mu.Lock()
	ld := d.live[id]
	if ld == nil {
		ld = &liveData{}
		d.live[id] = ld
	}
	fn(ld)
	d.mu.Unlock()
}

type confCacheEntry struct {
	mtime time.Time
	size  int64
	tun   Tunnel
}

type tailer struct {
	cancel context.CancelFunc
	done   chan struct{} // closed when tailLogs returns (child has exited)
}

type netSample struct {
	rx, tx float64
	at     time.Time
}

func NewDocker(hub *Hub, configDir, tfPath string) *Docker {
	return &Docker{
		hub:       hub,
		confDir:   filepath.Join(configDir, "conf.d"),
		stateDir:  filepath.Join(configDir, ".auth"),
		tfPath:    tfPath,
		tailers:   make(map[string]*tailer),
		lastNet:   make(map[string]netSample),
		armed:     make(map[string]bool),
		confCache: make(map[string]confCacheEntry),
		live:      make(map[string]*liveData),
	}
}

func splitTags(s string) []string {
	f := strings.Fields(s)
	if f == nil {
		return []string{}
	}
	return f
}

// ---------------------------------------------------------------- docker ps

type dockerPS struct {
	Names  string `json:"Names"`
	State  string `json:"State"`
	Labels string `json:"Labels"`
	Ports  string `json:"Ports"`
}

func parseLabels(s string) map[string]string {
	m := make(map[string]string)
	for _, kv := range strings.Split(s, ",") {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			continue
		}
		m[kv[:eq]] = kv[eq+1:]
	}
	return m
}

// dockerPorts maps a container's internal port -> published "ip:port"
// (e.g. "10001" -> "127.0.0.1:8023") from `docker port <name>`.
func dockerPorts(container string) map[string]string {
	out := map[string]string{}
	b, err := exec.Command("docker", "port", container).Output()
	if err != nil {
		return out
	}
	// lines like: 10001/tcp -> 127.0.0.1:8023
	for _, ln := range strings.Split(string(b), "\n") {
		arrow := strings.Index(ln, "->")
		if arrow < 0 {
			continue
		}
		left := strings.TrimSpace(ln[:arrow])    // "10001/tcp"
		right := strings.TrimSpace(ln[arrow+2:]) // "127.0.0.1:8023"
		internal := left
		if s := strings.IndexByte(left, '/'); s >= 0 {
			internal = left[:s]
		}
		if internal != "" && right != "" {
			out[internal] = right
		}
	}
	return out
}

// State merges running/created containers (docker ps -a) with configured but
// down tunnels (conf.d scan).
func (d *Docker) State() []Tunnel {
	byID := make(map[string]*Tunnel)

	out, err := exec.Command("docker", "ps", "-a",
		"--filter", "label="+label,
		"--format", "{{json .}}").Output()
	if err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(out)))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var ps dockerPS
			if json.Unmarshal([]byte(line), &ps) != nil {
				continue
			}
			labels := parseLabels(ps.Labels)
			id := labels[label+".name"]
			if id == "" {
				id = strings.TrimPrefix(ps.Names, "tf-")
			}
			// start from conf data (desc/forwards/socks/…), then overlay live
			t := d.tunnelFromConf(id)
			t.ID = id
			if typ := labels[label+".type"]; typ != "" {
				t.Type = typ
			}
			if tags := labels[label+".tags"]; tags != "" {
				t.Tags = splitTags(tags)
			}
			t.State = mapState(ps.State)
			if t.State == "on" && d.isWaiting(id) {
				t.State = "waiting"
			}
			// resolve the REAL published host port for each forward (fixes "any"
			// dynamic ports, so copy strings use the actual port). Forwards are
			// assigned internal ports 10001, 10002, … in order by the CLI.
			if t.State == "on" || t.State == "waiting" {
				if pub := dockerPorts(ps.Names); len(pub) > 0 {
					for i := range t.Forwards {
						if hp := pub[strconv.Itoa(10001+i)]; hp != "" {
							t.Forwards[i].Local = hp
						}
					}
				}
			}
			cp := t
			byID[id] = &cp
		}
	}

	// configured-but-down tunnels
	entries, _ := os.ReadDir(d.confDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		if _, ok := byID[name]; ok {
			continue
		}
		t := d.tunnelFromConf(name)
		byID[name] = &t
	}

	// fold in the latest live data (rates/reachability/netinfo/clients) so a
	// polling-only panel (SSE blocked) still gets everything
	res := make([]Tunnel, 0, len(byID))
	for _, t := range byID {
		if t.State == "on" {
			d.mu.Lock()
			if ld := d.live[t.ID]; ld != nil {
				t.TxRate, t.RxRate = ld.txRate, ld.rxRate
				t.HostUp, t.TunIP, t.TunSubnet = ld.hostUp, ld.tunIP, ld.tunSubnet
				t.HostSubnets, t.Clients = ld.hostSubnets, ld.clients
			}
			d.mu.Unlock()
		}
		res = append(res, *t)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].ID < res[j].ID })
	return res
}

func mapState(dockerState string) string {
	switch strings.ToLower(dockerState) {
	case "running":
		return "on"
	case "exited", "dead":
		return "failed"
	case "created", "restarting", "paused":
		return dockerState
	default:
		if dockerState == "" {
			return "off"
		}
		return dockerState
	}
}

// isWaiting reports whether the tunnel's auth dir has awaiting_code but no ready.
func (d *Docker) isWaiting(id string) bool {
	dir := filepath.Join(d.stateDir, "auth-"+slugify(id))
	if _, err := os.Stat(filepath.Join(dir, "awaiting_code")); err != nil {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
		return false
	}
	return true
}

// slugify mirrors the CLI: lowercase, non-alnum runs -> single '-', trim '-'.
func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
		} else if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

// broadcastState pushes a fresh full snapshot.
func (d *Docker) broadcastState() {
	d.hub.Broadcast("state", d.State())
}

// ---------------------------------------------------------------- stats loop

type dockerStat struct {
	Name  string `json:"Name"`
	NetIO string `json:"NetIO"`
}

// StateLoop re-broadcasts the full tunnel state on a slow heartbeat so any
// connected panel self-heals within a few seconds even if it missed a docker
// event (e.g. its SSE connection dropped during a daemon restart). EventsLoop
// still pushes state immediately on container start/die; this is the backstop.
func (d *Docker) StateLoop(ctx context.Context) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.hub.Broadcast("state", d.State())
		}
	}
}

// StatsLoop samples per-container network IO once a second and broadcasts
// byte/s rates as 'stat' events.
func (d *Docker) StatsLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		d.sampleStats(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (d *Docker) sampleStats(ctx context.Context) {
	ids, names := d.runningContainers(ctx)
	if len(ids) == 0 {
		return
	}
	args := append([]string{"stats", "--no-stream", "--format", "{{json .}}"}, ids...)
	out, err := exec.CommandContext(ctx, "docker", args...).Output()
	if err != nil {
		return
	}
	now := time.Now()
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var st dockerStat
		if json.Unmarshal([]byte(line), &st) != nil {
			continue
		}
		rx, tx, ok := parseNetIO(st.NetIO)
		if !ok {
			continue
		}
		d.mu.Lock()
		prev, had := d.lastNet[st.Name]
		d.lastNet[st.Name] = netSample{rx: rx, tx: tx, at: now}
		d.mu.Unlock()
		if !had {
			continue
		}
		dt := now.Sub(prev.at).Seconds()
		if dt <= 0 {
			continue
		}
		txRate := (tx - prev.tx) / dt
		rxRate := (rx - prev.rx) / dt
		if txRate < 0 {
			txRate = 0
		}
		if rxRate < 0 {
			rxRate = 0
		}
		id := names[st.Name]
		if id == "" {
			id = strings.TrimPrefix(st.Name, "tf-")
		}
		d.updateLive(id, func(ld *liveData) { ld.txRate, ld.rxRate = int64(txRate), int64(rxRate) })
		d.hub.Broadcast("stat", map[string]any{
			"id":     id,
			"txRate": int64(txRate),
			"rxRate": int64(rxRate),
		})
	}
}

// runningContainers returns container IDs and a name->tunnelID map.
func (d *Docker) runningContainers(ctx context.Context) ([]string, map[string]string) {
	out, err := exec.CommandContext(ctx, "docker", "ps",
		"--filter", "label="+label,
		"--format", "{{json .}}").Output()
	names := make(map[string]string)
	if err != nil {
		return nil, names
	}
	var ids []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ps dockerPS
		if json.Unmarshal([]byte(line), &ps) != nil {
			continue
		}
		ids = append(ids, ps.Names)
		id := parseLabels(ps.Labels)[label+".name"]
		if id == "" {
			id = strings.TrimPrefix(ps.Names, "tf-")
		}
		names[ps.Names] = id
	}
	return ids, names
}

// parseNetIO parses docker's "RX / TX" NetIO field into bytes.
func parseNetIO(s string) (rx, tx float64, ok bool) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, 0, false
	}
	r, ok1 := parseBytes(strings.TrimSpace(parts[0]))
	t, ok2 := parseBytes(strings.TrimSpace(parts[1]))
	return r, t, ok1 && ok2
}

// parseBytes turns "1.2kB", "3.4MB", "512B" (docker SI units) into bytes.
func parseBytes(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	i := 0
	for i < len(s) && (s[i] == '.' || (s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	num, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, false
	}
	unit := strings.TrimSpace(s[i:])
	mult := 1.0
	switch unit {
	case "B", "":
		mult = 1
	case "kB", "KB", "kiB", "KiB":
		mult = 1000
	case "MB", "MiB":
		mult = 1000 * 1000
	case "GB", "GiB":
		mult = 1000 * 1000 * 1000
	case "TB", "TiB":
		mult = 1000 * 1000 * 1000 * 1000
	default:
		mult = 1
	}
	return num * mult, true
}

// ---------------------------------------------------------------- log events

// classify mirrors the CLI's tag_events keyword rules.
func classify(line string) string {
	l := line
	switch {
	// benign openconnect/vpnc noise inside the container — not real errors,
	// so they must not be flagged as such (they contain "Failed"/"Cannot")
	case contains(l,
		"/dev/vhost-net",
		"route/flush",
		"Read-only file system",
		"Cannot open"):
		return "log"
	case contains(l, "accepting connection", "N accept", " connection from", "connect to"):
		return "conn"
	case contains(l, "tunnel is up", "READY", "reconnect", "established", "exited"):
		return "tunnel"
	case contains(l, "password sent", "verification code", "awaiting", "waiting for"):
		return "auth"
	case contains(l, "ERROR", "Error", "failed", "Failed"):
		return "error"
	default:
		return "log"
	}
}

func contains(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// tailLogs follows one container's logs and broadcasts classified events.
func (d *Docker) tailLogs(ctx context.Context, containerName, tun string) {
	cmd := exec.CommandContext(ctx, "docker", "logs", "-f",
		"--since=0s", "--timestamps", containerName)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	cmd.Stderr = cmd.Stdout // some engines log to stderr; ignore split errors
	if err := cmd.Start(); err != nil {
		return
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		raw := strings.TrimRight(sc.Text(), "\r")
		if raw == "" {
			continue
		}
		ts, msg := splitTimestamp(raw)
		d.hub.Broadcast("event", map[string]any{
			"ts":    ts,
			"level": classify(msg),
			"tun":   tun,
			"msg":   msg,
		})
	}
	// The scanner may have stopped early (e.g. bufio.ErrTooLong on a line larger
	// than the token limit) while `docker logs -f` keeps writing. If we stop
	// reading, the child blocks once the OS pipe buffer fills and cmd.Wait()
	// would hang forever, pinning both the goroutine and the docker process.
	// Drain the rest of the pipe so the child can make progress / exit. When the
	// context is cancelled (container died / shutdown) CommandContext kills the
	// child, unblocking the copy.
	_, _ = io.Copy(io.Discard, stdout)
	_ = cmd.Wait()
}

// splitTimestamp separates docker's leading RFC3339 timestamp from the message.
func splitTimestamp(line string) (ts, msg string) {
	if sp := strings.IndexByte(line, ' '); sp > 0 {
		head := line[:sp]
		if strings.Contains(head, "T") && (strings.Contains(head, ":")) {
			return head, strings.TrimSpace(line[sp+1:])
		}
	}
	return time.Now().Format(time.RFC3339), line
}

func (d *Docker) startTailer(ctx context.Context, containerName, tun string) {
	d.mu.Lock()
	if old, ok := d.tailers[containerName]; ok {
		// An entry exists, but presence alone is not liveness: a tailer whose
		// `docker logs -f` child has already exited (e.g. a docker daemon
		// restart dropped every stream) may still be registered because its
		// goroutine has not yet reached the map delete below. Treat such a
		// stale, exited tailer as absent and replace it; only a still-live
		// tailer suppresses a new one.
		select {
		case <-old.done:
			delete(d.tailers, containerName)
		default:
			d.mu.Unlock()
			return
		}
	}
	tctx, cancel := context.WithCancel(ctx)
	t := &tailer{cancel: cancel, done: make(chan struct{})}
	d.tailers[containerName] = t
	d.mu.Unlock()
	go func() {
		d.tailLogs(tctx, containerName, tun)
		// Signal liveness before touching the map so a concurrent startTailer
		// observing this closed channel can safely replace us.
		close(t.done)
		d.mu.Lock()
		// only remove if we are still the registered tailer (avoid clobbering
		// a fresh tailer that replaced us after a container restart)
		if cur, ok := d.tailers[containerName]; ok && cur == t {
			delete(d.tailers, containerName)
		}
		d.mu.Unlock()
		cancel()
	}()
}

func (d *Docker) stopTailer(containerName string) {
	d.mu.Lock()
	if t, ok := d.tailers[containerName]; ok {
		t.cancel()
		delete(d.tailers, containerName)
	}
	delete(d.lastNet, containerName)
	d.mu.Unlock()
}

// ---------------------------------------------------------------- events loop

type dockerEvent struct {
	Action string `json:"Action"`
	Actor  struct {
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// EventsLoop watches docker events, attaching/detaching log tailers as
// containers start and die, and re-broadcasting full state on any change.
func (d *Docker) EventsLoop(ctx context.Context) {
	d.broadcastState()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// (Re)attach tailers to already-running containers on every connect to
		// `docker events`. On a docker daemon restart every `docker logs -f`
		// drops and self-removes its tailer, but surviving containers emit no
		// new 'start' event, so watchEvents alone would never re-tail them.
		// startTailer is idempotent (map-keyed dedup) so re-attaching is safe.
		ids, names := d.runningContainers(ctx)
		for _, cname := range ids {
			d.startTailer(ctx, cname, names[cname])
		}
		d.watchEvents(ctx)
		// docker events exited (engine restart?); back off and retry
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

func (d *Docker) watchEvents(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "docker", "events",
		"--filter", "label="+label,
		"--format", "{{json .}}")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}
	if err := cmd.Start(); err != nil {
		return
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev dockerEvent
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		cname := ev.Actor.Attributes["name"]
		tun := ev.Actor.Attributes[label+".name"]
		if tun == "" {
			tun = strings.TrimPrefix(cname, "tf-")
		}
		switch ev.Action {
		case "start":
			if cname != "" {
				d.startTailer(ctx, cname, tun)
			}
			d.broadcastState()
		case "die", "kill", "stop":
			if cname != "" {
				d.stopTailer(cname)
			}
			d.broadcastState()
		case "create", "destroy":
			d.broadcastState()
		}
	}
	_ = cmd.Wait()
}

// ---------------------------------------------------------------- waiting loop

// WaitingLoop polls auth dirs for tunnels blocking on a verification code.
func (d *Docker) WaitingLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
		entries, err := os.ReadDir(d.stateDir)
		if err != nil {
			continue
		}
		// Build slug -> canonical tunnel ID map from the current state so we can
		// resolve auth dir names (which carry the slugified id) back to the real
		// tunnel id that /state uses. slugify is lossy (lowercase, non-alnum ->
		// '-') and has no inverse, so a lookup is the only correct mapping.
		var slugToID map[string]string
		var stateByID map[string]string
		waitingNow := make(map[string]bool)
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "auth-") {
				continue
			}
			dir := filepath.Join(d.stateDir, e.Name())
			if _, err := os.Stat(filepath.Join(dir, "awaiting_code")); err != nil {
				continue
			}
			if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
				continue
			}
			if slugToID == nil {
				slugToID = make(map[string]string)
				stateByID = make(map[string]string)
				for _, t := range d.State() {
					slugToID[slugify(t.ID)] = t.ID
					stateByID[t.ID] = t.State
				}
			}
			dirSlug := strings.TrimPrefix(e.Name(), "auth-")
			tun, ok := slugToID[dirSlug]
			if !ok {
				// No matching tunnel in state; fall back to the slug so the event
				// is at least emitted rather than silently dropped.
				tun = dirSlug
			}
			// Only treat this as a live wait when the container is actually
			// running and blocking on a code. State()=="waiting" already means
			// the container is up (State=="on") AND awaiting_code is present, so
			// it rejects stale markers left behind by an aborted/exited container
			// (which would otherwise burn a real verification code via
			// maybeAutoCode's TOTP_COMMAND). A stale marker with no live container
			// maps to "failed"/"off"/missing here and is skipped.
			if !ok || stateByID[tun] != "waiting" {
				continue
			}
			waitingNow[tun] = true
			d.hub.Broadcast("waiting", map[string]any{"tun": tun})
			d.maybeAutoCode(ctx, tun)
		}
		// forget arming state for tunnels that are no longer waiting so a later
		// reconnect re-fires TOTP_COMMAND
		d.mu.Lock()
		for id := range d.armed {
			if !waitingNow[id] {
				delete(d.armed, id)
			}
		}
		d.mu.Unlock()
	}
}

// maybeAutoCode fires a tunnel's TOTP_COMMAND (if any) exactly once per wait,
// extracts a code from its stdout, and hands it to `t-forward code`. This is
// the no-secret automation hook: the command can read the code from anywhere
// (a webhook cache, an SMS bridge, a mail fetch) and just print it.
func (d *Docker) maybeAutoCode(ctx context.Context, tun string) {
	d.mu.Lock()
	if d.armed[tun] {
		d.mu.Unlock()
		return
	}
	d.armed[tun] = true
	d.mu.Unlock()

	c, err := readConfYAML(confPath(d.confDir, tun))
	if err != nil || c == nil || strings.TrimSpace(c.TotpCommand) == "" {
		return
	}
	// totp_command is arbitrary shell run as the daemon user; never auto-execute it
	// unless the operator explicitly opted in when starting the daemon.
	if !d.allowTotpCmd {
		d.hub.Broadcast("event", map[string]any{
			"ts": "", "level": "error", "tun": tun,
			"msg": "totp_command is set but auto-exec is disabled; start the daemon with -allow-totp-command to enable it",
		})
		return
	}
	cmdStr := c.TotpCommand
	go func() {
		cctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		d.hub.Broadcast("event", map[string]any{
			"ts": "", "level": "auth", "tun": tun, "msg": "TOTP_COMMAND: fetching verification code",
		})
		out, err := exec.CommandContext(cctx, "sh", "-c", cmdStr).Output()
		if err != nil {
			d.hub.Broadcast("event", map[string]any{
				"ts": "", "level": "error", "tun": tun, "msg": "TOTP_COMMAND failed: " + err.Error(),
			})
			return
		}
		code := extractCode(string(out))
		if code == "" {
			d.hub.Broadcast("event", map[string]any{
				"ts": "", "level": "error", "tun": tun, "msg": "TOTP_COMMAND produced no code",
			})
			return
		}
		if err := exec.CommandContext(cctx, d.tfPath, "code", tun, code).Run(); err != nil {
			d.hub.Broadcast("event", map[string]any{
				"ts": "", "level": "error", "tun": tun, "msg": "delivering TOTP code failed: " + err.Error(),
			})
			return
		}
		d.hub.Broadcast("event", map[string]any{
			"ts": "", "level": "auth", "tun": tun, "msg": "TOTP code delivered automatically",
		})
	}()
}

// extractCode pulls the first 4-8 digit run from arbitrary command output.
func extractCode(s string) string {
	return codeExtractRe.FindString(s)
}

var codeExtractRe = regexp.MustCompile(`[0-9]{4,8}`)

// ---------------------------------------------------------------- clients loop

// Client is a peer connected to one of a tunnel's published forward ports,
// observed on the HOST side (docker NAT hides it from inside the container).
type Client struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`           // the forward's local port it hit
	MAC  string `json:"mac,omitempty"`  // LAN peers only (same subnet, via ARP)
	Proc string `json:"proc,omitempty"` // local (127.0.0.1) peers: connecting process
}

// docker/OrbStack port-proxy process names — their sockets are the ACCEPT side
// of a published port, so their remote endpoint is the real client.
func isProxyProc(cmd string) bool {
	switch {
	case strings.HasPrefix(cmd, "OrbStack"),
		strings.HasPrefix(cmd, "com.docker"),
		strings.HasPrefix(cmd, "docker-pr"), // docker-proxy
		strings.HasPrefix(cmd, "vpnkit"),
		strings.HasPrefix(cmd, "Docker"):
		return true
	}
	return false
}

// ClientsLoop watches, on the host, who is connected to each tunnel's published
// forward ports and broadcasts a 'clients' event per tunnel; new peers are also
// surfaced as 'conn' events ("who reached YOU").
func (d *Docker) ClientsLoop(ctx context.Context) {
	seen := map[string]bool{} // tun|ip|port already logged this session
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		// port -> tunnel id, only for running tunnels with forwards
		portTun := map[int]string{}
		hasPorts := false
		for _, tn := range d.State() {
			if tn.State != "on" {
				continue
			}
			for _, f := range tn.Forwards {
				if p := portOf(f.Local); p > 0 {
					portTun[p] = tn.ID
					hasPorts = true
				}
			}
		}
		if !hasPorts {
			continue
		}

		conns := hostConns() // established TCP peers per local port
		arp := arpTable()    // ip -> mac (best effort)

		byTun := map[string][]Client{}
		for port, tun := range portTun {
			for _, c := range conns[port] {
				if c.IP != "127.0.0.1" && c.IP != "::1" {
					c.MAC = arp[c.IP]
				}
				byTun[tun] = append(byTun[tun], c)
			}
		}

		for tun, cs := range byTun {
			cs := cs
			d.updateLive(tun, func(ld *liveData) { ld.clients = cs })
			d.hub.Broadcast("clients", map[string]any{"tun": tun, "clients": cs})
			for _, c := range cs {
				key := tun + "|" + c.IP + "|" + strconv.Itoa(c.Port)
				if seen[key] {
					continue
				}
				seen[key] = true
				who := c.IP
				if c.Proc != "" {
					who += " (" + c.Proc + ")"
				} else if c.MAC != "" {
					who += " [" + c.MAC + "]"
				}
				d.hub.Broadcast("event", map[string]any{
					"ts": "", "level": "conn", "tun": tun,
					"msg": "client " + who + " -> localhost:" + strconv.Itoa(c.Port),
				})
			}
		}
		// forget peers that are gone so a later reconnection re-logs
		for k := range seen {
			parts := strings.SplitN(k, "|", 3)
			if len(parts) != 3 {
				continue
			}
			present := false
			if p, err := strconv.Atoi(parts[2]); err == nil {
				for _, c := range conns[p] {
					if c.IP == parts[1] {
						present = true
						break
					}
				}
			}
			if !present {
				delete(seen, k)
			}
		}
	}
}

func portOf(hostPort string) int {
	// "127.0.0.1:8023" -> 8023 ; "127.0.0.1:auto" (dynamic) -> 0 (skip)
	i := strings.LastIndexByte(hostPort, ':')
	if i < 0 {
		return 0
	}
	p, err := strconv.Atoi(hostPort[i+1:])
	if err != nil {
		return 0
	}
	return p
}

// hostConns returns, per local (listening) port, the peers connected to it.
func hostConns() map[int][]Client {
	out := map[int][]Client{}
	b, err := exec.Command("lsof", "-nP", "-sTCP:ESTABLISHED", "-iTCP").Output()
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 9 || f[0] == "COMMAND" {
			continue
		}
		cmd := f[0]
		name := f[8] // "local->remote"
		arrow := strings.Index(name, "->")
		if arrow < 0 {
			continue
		}
		lIP, lPort := splitHostPort(name[:arrow])
		rIP, _ := splitHostPort(name[arrow+2:])
		if lPort == 0 {
			continue
		}
		if isProxyProc(cmd) {
			// accept side: local port is the published forward, remote is the client
			out[lPort] = append(out[lPort], Client{IP: rIP, Port: lPort})
		} else {
			// a local process connecting TO a forward: remote port is the forward
			_, rPort := splitHostPort(name[arrow+2:])
			if rPort > 0 && (rIP == "127.0.0.1" || rIP == "::1") {
				out[rPort] = append(out[rPort], Client{IP: lIP, Port: rPort, Proc: cmd})
			}
		}
	}
	// dedupe per port by IP (prefer entries carrying a Proc/MAC label)
	for port, cs := range out {
		best := map[string]Client{}
		for _, c := range cs {
			if ex, ok := best[c.IP]; !ok || (ex.Proc == "" && c.Proc != "") {
				best[c.IP] = c
			}
		}
		merged := make([]Client, 0, len(best))
		for _, c := range best {
			merged = append(merged, c)
		}
		sort.Slice(merged, func(i, j int) bool { return merged[i].IP < merged[j].IP })
		out[port] = merged
	}
	return out
}

func splitHostPort(s string) (string, int) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, 0
	}
	p, _ := strconv.Atoi(s[i+1:])
	return s[:i], p
}

// arpTable maps IP -> MAC from the host ARP cache (LAN peers only).
func arpTable() map[string]string {
	out := map[string]string{}
	b, err := exec.Command("arp", "-an").Output()
	if err != nil {
		return out
	}
	// lines like: ? (10.0.0.5) at aa:bb:cc:dd:ee:ff on en0 ...
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[2] != "at" {
			continue
		}
		ip := strings.Trim(f[1], "()")
		mac := f[3]
		if mac == "(incomplete)" || !strings.Contains(mac, ":") {
			continue
		}
		out[ip] = mac
	}
	return out
}

// ---------------------------------------------------------------- host ping loop

// HostPingLoop learns the reachability of each tunnel's target hosts by pinging
// them from INSIDE the container (the only place the VPN's network is reachable)
// and broadcasts a 'hosts' event {tun, up:{ip:bool}} for the panel to color the
// target nodes.
func (d *Docker) HostPingLoop(ctx context.Context) {
	first := time.NewTimer(3 * time.Second)
	tick := time.NewTicker(12 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-tick.C:
		}
		for _, tn := range d.State() {
			if tn.State != "on" {
				continue
			}
			cname := "tf-" + slugify(tn.ID)
			// probe reachability by a TCP connect to one of each host's forwarded
			// ports (a real "can I reach the service" signal — ICMP ping is often
			// blocked even when the ports are open)
			// Collect ALL forwarded ports per host (not just the first): a host is
			// "reachable" if ANY of its ports answers. Probing only the first port
			// gave a false UNREACHABLE when that port is firewalled by the VPN
			// gateway but another (e.g. :80) is open.
			hostPorts := map[string][]string{}
			var order []string
			for _, f := range tn.Forwards {
				ip, port := f.Remote, ""
				if i := strings.IndexByte(ip, ':'); i >= 0 {
					ip, port = ip[:i], ip[i+1:]
				}
				if ip == "" {
					continue
				}
				if _, seen := hostPorts[ip]; !seen {
					order = append(order, ip)
				}
				hostPorts[ip] = append(hostPorts[ip], port)
			}
			up := map[string]bool{}
			for _, ip := range order {
				reachable := false
				for _, port := range hostPorts[ip] {
					if reachInContainer(ctx, cname, ip, port) {
						reachable = true
						break // first port that answers -> host is reachable
					}
				}
				up[ip] = reachable
			}
			if len(up) > 0 {
				upC := up
				d.updateLive(tn.ID, func(ld *liveData) { ld.hostUp = upC })
				d.hub.Broadcast("hosts", map[string]any{"tun": tn.ID, "up": up})
			}
			// our IP on the VPN (tun0) and which target hosts share our subnet
			// (same subnet -> they can talk to us / each other directly)
			tunIP, nets := tunnelNet(ctx, cname)
			if tunIP != "" {
				hostSubnets := map[string]string{}
				for ip := range up {
					hostSubnets[ip] = subnetOf(ip, nets)
				}
				sub := subnetOf(tunIP, nets)
				d.updateLive(tn.ID, func(ld *liveData) { ld.tunIP, ld.tunSubnet, ld.hostSubnets = tunIP, sub, hostSubnets })
				d.hub.Broadcast("netinfo", map[string]any{
					"tun": tn.ID, "ip": tunIP, "subnet": sub, "hostSubnets": hostSubnets,
				})
			}
		}
	}
}

// reachInContainer reports whether ip:port accepts a TCP connection from inside
// the tunnel's container (bash /dev/tcp; bash ships in the image). A blank port
// falls back to an ICMP ping.
func reachInContainer(ctx context.Context, cname, ip, port string) bool {
	// ip/port originate from the config file and are interpolated into a bash
	// -c string inside the container; validate them strictly so a crafted host IP
	// or remote port can never smuggle shell metacharacters into that command.
	if net.ParseIP(ip) == nil {
		return false
	}
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if port == "" {
		return exec.CommandContext(c, "docker", "exec", cname, "ping", "-c", "1", "-W", "1", ip).Run() == nil
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return false
	}
	return exec.CommandContext(c, "docker", "exec", cname,
		"timeout", "2", "bash", "-c", "exec 3<>/dev/tcp/"+ip+"/"+port).Run() == nil
}

// tunnelNet returns the container's tun0 address and the subnets routed over it
// (the VPN-pushed networks).
func tunnelNet(ctx context.Context, cname string) (string, []*net.IPNet) {
	c, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	tunIP := ""
	if out, err := exec.CommandContext(c, "docker", "exec", cname, "ip", "-4", "-o", "addr", "show", "tun0").Output(); err == nil {
		for _, f := range strings.Fields(string(out)) {
			if strings.Contains(f, ".") && strings.Contains(f, "/") {
				if ip, _, e := net.ParseCIDR(f); e == nil {
					tunIP = ip.String()
					break
				}
			}
		}
	}
	var nets []*net.IPNet
	if out, err := exec.CommandContext(c, "docker", "exec", cname, "ip", "-4", "route", "show", "dev", "tun0").Output(); err == nil {
		for _, ln := range strings.Split(string(out), "\n") {
			fields := strings.Fields(ln)
			if len(fields) == 0 || fields[0] == "default" {
				continue
			}
			cidr := fields[0]
			// skip host routes (/32 and bare IPs) — we want the pushed networks
			// that define a real subnet (e.g. 10.0.0.0/16)
			if !strings.Contains(cidr, "/") || strings.HasSuffix(cidr, "/32") {
				continue
			}
			if _, n, e := net.ParseCIDR(cidr); e == nil {
				nets = append(nets, n)
			}
		}
	}
	return tunIP, nets
}

// subnetOf returns the most specific VPN subnet containing ip (or "").
func subnetOf(ip string, nets []*net.IPNet) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	best, bestOnes := "", -1
	for _, n := range nets {
		if n.Contains(parsed) {
			if ones, _ := n.Mask.Size(); ones > bestOnes {
				bestOnes, best = ones, n.String()
			}
		}
	}
	return best
}
