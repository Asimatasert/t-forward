package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scanner discovers devices + open ports reachable from the host's own network
// interfaces (via nmap), on a config-driven interval, and caches the result
// (in memory, a JSON file, and optionally Redis). It powers the panel's second
// "discovery" canvas — separate from the tunnel map.

// common ports scanned when the config doesn't override them
var defaultScanPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
	3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
}

type scanConf struct {
	Enabled    bool        `json:"enabled"`
	Interval   int         `json:"interval"` // seconds between scans (0 -> default)
	Ports      []int       `json:"ports"`
	AllPorts   bool        `json:"all_ports"` // scan every port (nmap -p-) instead of a set
	TopPorts   int         `json:"top_ports"` // scan nmap's N most common ports
	Interfaces []scanIface `json:"interfaces"`
	Redis      string      `json:"redis"`   // optional host:port for redis-cli caching
	Persist    *bool       `json:"persist"` // write the JSON cache file (default true)
}

// scanIface is an interface to scan, written as a bare name ("en0") or an object
// {name, cidr} to override the auto-derived subnet.
type scanIface struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

func (s *scanIface) UnmarshalJSON(b []byte) error {
	b = trimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		s.Name = str
		return nil
	}
	type raw scanIface
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*s = scanIface(r)
	return nil
}

func trimSpace(b []byte) []byte { return []byte(strings.TrimSpace(string(b))) }

// ---- discovery result (broadcast to the panel) ----

type scanPort struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
}

type scanDevice struct {
	IP    string     `json:"ip"`
	Host  string     `json:"host,omitempty"`
	MAC   string     `json:"mac,omitempty"`
	Name  string     `json:"name,omitempty"` // user label (from devices.yaml)
	Tags  []string   `json:"tags,omitempty"` // user tags (from devices.yaml)
	Ports []scanPort `json:"ports"`
}

// deviceID is the stable annotation key: the MAC when known (survives DHCP IP
// changes), else "ip:<ip>".
func deviceID(mac, ip string) string {
	if mac != "" {
		return strings.ToLower(mac)
	}
	return "ip:" + ip
}

type scanIfaceResult struct {
	Name    string       `json:"name"`
	IP      string       `json:"ip"`
	CIDR    string       `json:"cidr"`
	Devices []scanDevice `json:"devices"`
}

type scanSnapshot struct {
	At         int64             `json:"at"` // unix seconds of the last completed scan
	Scanning   bool              `json:"scanning"`
	Interfaces []scanIfaceResult `json:"interfaces"`
}

type Scanner struct {
	hub       *Hub
	configDir string
	cachePath string

	mu       sync.Mutex
	latest   scanSnapshot
	scanning bool
	baseCtx  context.Context // daemon-lifetime ctx, for scans triggered off a request
}

func NewScanner(hub *Hub, configDir string) *Scanner {
	s := &Scanner{
		hub:       hub,
		configDir: configDir,
		cachePath: filepath.Join(configDir, ".scan-cache.json"),
	}
	s.loadCache()
	return s
}

func (s *Scanner) confPath() string    { return filepath.Join(s.configDir, "scan.yaml") }
func (s *Scanner) devicesPath() string { return filepath.Join(s.configDir, "devices.yaml") }

// readAnnos loads the per-device user labels/tags keyed by device id.
func (s *Scanner) readAnnos() map[string]deviceAnno {
	out := map[string]deviceAnno{}
	if _, err := os.Stat(s.devicesPath()); err != nil {
		return out
	}
	b, err := exec.Command("yq", "-o=json", ".", s.devicesPath()).Output()
	if err != nil {
		return out
	}
	var doc struct {
		Devices []struct {
			ID   string   `json:"id"`
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		} `json:"devices"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return out
	}
	for _, d := range doc.Devices {
		if d.ID != "" {
			out[strings.ToLower(d.ID)] = deviceAnno{Name: d.Name, Tags: d.Tags}
		}
	}
	return out
}

type deviceAnno struct {
	Name string
	Tags []string
}

// cloneSnapshot deep-copies the interface + device slices so the result can be
// mutated (e.g. annotated) without touching the shared backing of s.latest,
// which other goroutines may be reading/marshalling concurrently.
func cloneSnapshot(in scanSnapshot) scanSnapshot {
	out := in
	out.Interfaces = make([]scanIfaceResult, len(in.Interfaces))
	for i, ifc := range in.Interfaces {
		out.Interfaces[i] = ifc
		out.Interfaces[i].Devices = append([]scanDevice(nil), ifc.Devices...)
	}
	return out
}

// annotate stamps each device with its stored name/tags (by MAC, then by IP).
// snap MUST be a private copy (see cloneSnapshot) — it mutates device elements.
func annotate(snap *scanSnapshot, annos map[string]deviceAnno) {
	if len(annos) == 0 {
		return
	}
	for i := range snap.Interfaces {
		for j := range snap.Interfaces[i].Devices {
			d := &snap.Interfaces[i].Devices[j]
			a, ok := annos[deviceID(d.MAC, d.IP)]
			if !ok {
				a, ok = annos["ip:"+d.IP]
			}
			if ok {
				d.Name, d.Tags = a.Name, a.Tags
			}
		}
	}
}

// reannotate re-applies device labels to the current snapshot and rebroadcasts
// (called after an edit so it shows without waiting for a rescan). The yq read
// is done before the lock; the snapshot is deep-copied under the lock and only
// the private copy is mutated, so this never races with concurrent readers.
func (s *Scanner) reannotate() {
	annos := s.readAnnos()
	s.mu.Lock()
	snap := cloneSnapshot(s.latest)
	annotate(&snap, annos)
	s.latest = snap
	s.mu.Unlock()
	s.hub.Broadcast("scan", snap)
}

// readConf loads scan.yaml (via yq, like the tunnel confs). Missing file -> a
// disabled config, not an error.
func (s *Scanner) readConf() scanConf {
	c := scanConf{}
	if _, err := os.Stat(s.confPath()); err != nil {
		return c
	}
	out, err := exec.Command("yq", "-o=json", ".", s.confPath()).Output()
	if err != nil {
		return c
	}
	_ = json.Unmarshal(out, &c)
	return c
}

func (s *Scanner) Snapshot() scanSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest
}

// Loop scans on the configured interval; it also scans once at startup if
// enabled. A zero/absent interval defaults to 5 minutes.
func (s *Scanner) Loop(ctx context.Context) {
	s.mu.Lock()
	s.baseCtx = ctx
	s.mu.Unlock()
	first := time.NewTimer(2 * time.Second)
	defer first.Stop()
	var tick *time.Ticker
	rearm := func(sec int) {
		if sec <= 0 {
			sec = 300
		}
		if tick != nil {
			tick.Stop()
		}
		tick = time.NewTicker(time.Duration(sec) * time.Second)
	}
	rearm(s.readConf().Interval)
	defer func() {
		if tick != nil {
			tick.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-tick.C:
		}
		conf := s.readConf()
		rearm(conf.Interval)
		if conf.Enabled {
			s.scan(ctx, conf, "")
		}
	}
}

// Rescan runs a scan now (manual-refresh endpoint). `only` scans just that one
// interface (empty = all). It runs on the daemon-lifetime context, NOT the
// caller's — an HTTP request context is cancelled the instant the handler
// returns, which would kill the scan (and its nmap child) a few ms in. No-op if
// disabled.
func (s *Scanner) Rescan(only string) {
	conf := s.readConf()
	if !conf.Enabled {
		return
	}
	s.mu.Lock()
	ctx := s.baseCtx
	s.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}
	go s.scan(ctx, conf, only)
}

func (s *Scanner) scan(ctx context.Context, conf scanConf, only string) {
	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		return
	}
	s.scanning = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.scanning = false
		s.mu.Unlock()
		s.broadcastScanning(false)
	}()

	// port spec: every port (-p-), an explicit set, nmap's top-N, or the default
	var portSpec []string
	switch {
	case conf.AllPorts:
		portSpec = []string{"-p-"}
	case len(conf.Ports) > 0:
		portSpec = []string{"-p", joinInts(conf.Ports)}
	case conf.TopPorts > 0:
		portSpec = []string{"--top-ports", strconv.Itoa(conf.TopPorts)}
	default:
		portSpec = []string{"-p", joinInts(defaultScanPorts)}
	}
	// root scan (ARP discovery + SYN) is far faster and yields MACs; fall back to
	// an unprivileged connect-scan if we can't sudo nmap
	useSudo := canSudoNmap()

	// Seed the result set from the previous snapshot, keyed by interface name, so
	// a rescan updates each adapter IN PLACE — the others keep their devices
	// instead of blanking while we work through them.
	s.mu.Lock()
	prev := map[string]scanIfaceResult{}
	for _, r := range s.latest.Interfaces {
		prev[r.Name] = r
	}
	s.mu.Unlock()

	results := make([]scanIfaceResult, 0, len(conf.Interfaces))
	idx := map[string]int{}
	for _, ifc := range conf.Interfaces {
		if ifc.Name == "" && ifc.CIDR == "" {
			continue
		}
		r := prev[ifc.Name]
		r.Name = ifc.Name
		idx[ifc.Name] = len(results)
		results = append(results, r)
	}

	annos := s.readAnnos()
	publish := func(scanning bool) {
		// deep-copy `results` into a private snapshot before annotating, so
		// mutating device fields can't race with readers of the last s.latest
		snap := cloneSnapshot(scanSnapshot{At: time.Now().Unix(), Scanning: scanning, Interfaces: results})
		annotate(&snap, annos)
		s.mu.Lock()
		s.latest = snap
		s.mu.Unlock()
		if !scanning {
			s.persist(conf, snap)
		}
		s.hub.Broadcast("scan", snap)
	}
	publish(true) // show the seeded (previous) state immediately, marked scanning

	for _, ifc := range conf.Interfaces {
		i, ok := idx[ifc.Name]
		if !ok {
			continue
		}
		if only != "" && ifc.Name != only {
			continue // targeted rescan: leave the other adapters untouched
		}
		ip, cidr := ifaceIPCIDR(ifc.Name)
		if ifc.CIDR != "" {
			cidr = ifc.CIDR // explicit override
		}
		cidr = widenHostCIDR(ip, cidr) // a /32 (tun/tailscale) -> its /24
		if cidr == "" {
			results[i] = scanIfaceResult{Name: ifc.Name, IP: ip, CIDR: "", Devices: nil}
			publish(true)
			continue
		}
		s.event("scanning " + ifc.Name + " " + cidr + "…")
		devices := nmapScan(ctx, cidr, portSpec, useSudo)
		// don't list ourselves as a discovered device
		filtered := devices[:0]
		nopen := 0
		for _, d := range devices {
			if d.IP != ip {
				filtered = append(filtered, d)
				nopen += len(d.Ports)
			}
		}
		s.event(fmt.Sprintf("%s: %d devices, %d open ports", ifc.Name, len(filtered), nopen))
		results[i] = scanIfaceResult{Name: ifc.Name, IP: ip, CIDR: cidr, Devices: filtered}
		publish(true) // this adapter refreshed in place; others unchanged
	}

	publish(false) // done
}

func (s *Scanner) broadcastScanning(on bool) {
	s.mu.Lock()
	s.latest.Scanning = on
	snap := s.latest
	s.mu.Unlock()
	s.hub.Broadcast("scan", snap)
}

// ---- nmap ----

// nmapScan runs nmap over a CIDR and returns hosts with >=1 open port. With root
// (sudo) it uses ARP discovery + a SYN scan (-sS, fast, resolves MACs); without
// it falls back to an unprivileged connect-scan (-sT). Greppable output. No -Pn:
// nmap does host discovery first so it only port-scans live hosts.
func nmapScan(ctx context.Context, cidr string, portSpec []string, useSudo bool) []scanDevice {
	c, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	var bin string
	var args []string
	if useSudo {
		bin, args = "sudo", []string{"-n", "nmap", "-sS"}
	} else {
		bin, args = "nmap", []string{"-sT"}
	}
	args = append(args, "-n", "--open")
	args = append(args, portSpec...)
	args = append(args, "-T4", "--host-timeout", "90s", "-oG", "-", cidr)
	out, err := exec.CommandContext(c, bin, args...).Output()
	if err != nil && len(out) == 0 {
		return nil
	}
	return parseNmapGreppable(string(out))
}

// canSudoNmap reports whether nmap can be run as root non-interactively (a
// NOPASSWD sudoers entry), enabling the faster/richer root scan.
func canSudoNmap() bool {
	return exec.Command("sudo", "-n", "nmap", "--version").Run() == nil
}

// widenHostCIDR turns a host route (/32, e.g. a tun/tailscale address) into the
// /24 around it so there's something to sweep; other CIDRs pass through.
func widenHostCIDR(ip, cidr string) string {
	if cidr == "" || !strings.HasSuffix(cidr, "/32") {
		return cidr
	}
	p := net.ParseIP(ip)
	if p == nil || p.To4() == nil {
		return ""
	}
	m := net.CIDRMask(24, 32)
	return (&net.IPNet{IP: p.To4().Mask(m), Mask: m}).String()
}

// event emits a LAN-side network event to the panel's console.
func (s *Scanner) event(msg string) {
	s.hub.Broadcast("event", map[string]any{
		"ts":    time.Now().Format(time.RFC3339),
		"level": "scan",
		"tun":   "LAN",
		"msg":   msg,
	})
}

// parseNmapGreppable extracts hosts + open ports from nmap -oG output lines like:
//
//	Host: 192.168.1.1 (router.lan)\tPorts: 80/open/tcp//http///, 443/open/tcp//https///
func parseNmapGreppable(text string) []scanDevice {
	var devs []scanDevice
	for _, ln := range strings.Split(text, "\n") {
		if !strings.HasPrefix(ln, "Host: ") {
			continue
		}
		pi := strings.Index(ln, "Ports:")
		if pi < 0 {
			continue // a "Status: Up" line with no open ports
		}
		head := strings.TrimSpace(ln[len("Host: "):pi])
		ip := head
		host := ""
		if sp := strings.IndexByte(head, ' '); sp >= 0 {
			ip = head[:sp]
			if h := strings.TrimSpace(head[sp+1:]); len(h) > 2 && h[0] == '(' {
				host = strings.Trim(h, "()")
			}
		}
		portsField := ln[pi+len("Ports:"):]
		if tab := strings.IndexByte(portsField, '\t'); tab >= 0 {
			portsField = portsField[:tab]
		}
		var ports []scanPort
		for _, ent := range strings.Split(portsField, ",") {
			f := strings.Split(strings.TrimSpace(ent), "/")
			if len(f) < 5 || f[1] != "open" {
				continue
			}
			p, err := strconv.Atoi(f[0])
			if err != nil {
				continue
			}
			ports = append(ports, scanPort{Port: p, Service: f[4]})
		}
		if len(ports) == 0 {
			continue
		}
		devs = append(devs, scanDevice{IP: ip, Host: host, MAC: arpMAC(ip), Ports: ports})
	}
	return devs
}

// arpMAC best-effort resolves a LAN IP's MAC from the host arp cache (no root).
func arpMAC(ip string) string {
	out, err := exec.Command("arp", "-n", ip).Output()
	if err != nil {
		return ""
	}
	for _, f := range strings.Fields(string(out)) {
		if strings.Count(f, ":") == 5 {
			return f
		}
	}
	return ""
}

// ---- interface -> CIDR (uses the OS interface table; no ifconfig parsing) ----

func ifaceIPCIDR(name string) (string, string) {
	if name == "" {
		return "", ""
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return "", ""
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return "", ""
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil {
			continue
		}
		_, network, err := net.ParseCIDR(n.String())
		if err != nil {
			continue
		}
		return n.IP.String(), network.String()
	}
	return "", ""
}

// ---- cache persistence (file + optional redis) ----

func (s *Scanner) persist(conf scanConf, snap scanSnapshot) {
	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	if conf.Persist == nil || *conf.Persist {
		tmp := s.cachePath + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, s.cachePath)
		}
	}
	if conf.Redis != "" {
		host, port := redisHostPort(conf.Redis)
		_ = exec.Command("redis-cli", "-h", host, "-p", port,
			"SET", "tforward:scan", string(b)).Run()
	}
}

func (s *Scanner) loadCache() {
	b, err := os.ReadFile(s.cachePath)
	if err != nil {
		return
	}
	var snap scanSnapshot
	if json.Unmarshal(b, &snap) == nil {
		snap.Scanning = false
		s.latest = snap
	}
}

func redisHostPort(hp string) (string, string) {
	if i := strings.LastIndexByte(hp, ':'); i >= 0 {
		return hp[:i], hp[i+1:]
	}
	return hp, "6379"
}

// validIfaceName accepts only interface-name-shaped strings (alnum plus . _ - :),
// so a crafted value can't smuggle argv/path characters into the tunnel name.
func validIfaceName(s string) bool {
	if s == "" || len(s) > 24 {
		return false
	}
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' || r == ':'
		if !ok {
			return false
		}
	}
	return true
}

func joinInts(xs []int) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = strconv.Itoa(x)
	}
	return strings.Join(parts, ",")
}

// ---- HTTP handlers (wired in main.go) ----

// handleScan: GET /scan -> the latest discovery snapshot.
func (a *Actions) handleScan(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.scanner.Snapshot())
}

// handleScanRescan: POST /scan/rescan {iface?} -> rescan all, or just one adapter.
func (a *Actions) handleScanRescan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	only := strings.TrimSpace(decodeBody(r)["iface"])
	if only != "" && !validIfaceName(only) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid iface"})
		return
	}
	a.scanner.Rescan(only)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleScanForward: POST /scan/forward {ip,port} -> spin up a local relay to a
// discovered device:port on an auto-picked localhost port (any).
func (a *Actions) handleScanForward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := decodeBody(r)
	ip := strings.TrimSpace(body["ip"])
	port := strings.TrimSpace(body["port"])
	iface := strings.TrimSpace(body["iface"])
	if ipv4 := net.ParseIP(ip); ipv4 == nil || ipv4.To4() == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid ip"})
		return
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid port"})
		return
	}
	if iface != "" && !validIfaceName(iface) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid iface"})
		return
	}
	// name is derived from validated iface/ip/port only (never from free text),
	// so it is always a safe argv token / filename. It carries the adapter name
	// so you can tell which interface a forward came from.
	name := "scan-"
	if iface != "" {
		name += iface + "-"
	}
	name += strings.ReplaceAll(ip, ".", "-") + "-" + port

	// Write a first-class local-relay conf so the forward shows up fully in the
	// panel (real published port, service label) and survives a restart, then
	// bring it up by name. ip/port are already strictly validated.
	svc := ""
	if s := serviceForPort(port); s != "" {
		svc = ", service: " + s
	}
	yaml := "name: " + name + "\ntype: local\ntags: [scan]\n" +
		"hosts:\n  - ip: " + ip + "\n    forwards:\n" +
		"      - { remote: " + port + ", local: any" + svc + " }\n"
	confFile := confPath(a.docker.confDir, name)
	if err := os.WriteFile(confFile, []byte(yaml), 0o600); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "write conf: " + err.Error()})
		return
	}
	err := a.runTF(r.Context(), name, "up", name, "--no-prompt")
	a.docker.broadcastState()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})
}

// handleScanDevice: POST /scan/device {id, name?, tags?} — upsert a device label
// / tags in devices.yaml (keyed by MAC or "ip:<ip>"), via yq. Values reach yq
// only through env/strenv, so a crafted value can't inject yq syntax.
func (a *Actions) handleScanDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ID   string    `json:"id"`
		Name *string   `json:"name"`
		Tags *[]string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json"})
		return
	}
	id := strings.ToLower(strings.TrimSpace(body.ID))
	if !validDeviceID(id) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid device id"})
		return
	}
	path := a.scanner.devicesPath()
	if _, err := os.Stat(path); err != nil {
		if err := os.WriteFile(path, []byte("devices: []\n"), 0o600); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	upsert := func(field string, e env) error {
		expr := `{"id": strenv(ID), ` + field + `} as $new |` +
			`((.devices // []) | map(select(.id == strenv(ID))) | .[0] // {}) as $cur |` +
			`.devices = ((.devices // []) | map(select(.id != strenv(ID)))) + [$cur * $new]`
		return yqEdit(path, expr, e)
	}
	if body.Name != nil {
		if err := upsert(`"name": strenv(VAL)`, env{"ID": id, "VAL": *body.Name}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	if body.Tags != nil {
		if err := upsert(`"tags": (strenv(J)|fromjson)`, env{"ID": id, "J": jsonArr(*body.Tags)}); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
			return
		}
	}
	a.scanner.reannotate()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// validDeviceID accepts a MAC or "ip:<ipv4>" shape (hex, dots, colons, the "ip:"
// prefix) — enough to key annotations, and strenv makes injection impossible.
func validDeviceID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		ok := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') ||
			r == ':' || r == '.'
		if !ok {
			return false
		}
	}
	return true
}
