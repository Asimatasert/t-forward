package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Coverage tests for the scan.go pieces that need a filesystem, a Hub or an
// HTTP request but no real nmap / network: config + annotation readers (yq is
// replaced by a PATH stub), cache persistence, event broadcasting and the
// /scan/* handlers.

// scvStub puts an executable shell script called name first on PATH for the
// test. Skipped where no POSIX sh exists.
func scvStub(t *testing.T, name, script string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs need a POSIX sh")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// scvYQ stubs yq: `yq -o=json . <file>` prints out and exits with code; any
// `yq -i ...` edit appends its argv (plus ID/VAL/J env) to the returned log
// and exits with editExit.
func scvYQ(t *testing.T, out string, code, editExit int) (editLog string) {
	t.Helper()
	dir := t.TempDir()
	editLog = filepath.Join(dir, "edits.log")
	outFile := filepath.Join(dir, "out.json")
	if err := os.WriteFile(outFile, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `if [ "$1" = "-i" ]; then
  echo "$* ID=$ID VAL=$VAL J=$J" >> ` + editLog + `
  [ "` + itoa(editExit) + `" = 0 ] || { echo "edit failed" >&2; exit ` + itoa(editExit) + `; }
  exit 0
fi
cat ` + outFile + `
exit ` + itoa(code) + "\n"
	scvStub(t, "yq", script)
	return editLog
}

func scvScanner(t *testing.T) (*Scanner, *Hub, string) {
	t.Helper()
	dir := t.TempDir()
	hub := NewHub()
	return NewScanner(hub, dir), hub, dir
}

// scvFrames returns every pending frame (lossy then state) on the client.
func scvFrames(c *client) []string {
	var out []string
	for {
		select {
		case f := <-c.lossy:
			out = append(out, string(f))
		case f := <-c.state:
			out = append(out, string(f))
		default:
			return out
		}
	}
}

// ------------------------------------------------------------ JSON config

func TestScanIfaceUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    scanIface
		wantErr bool
	}{
		{"bare name", `"en0"`, scanIface{Name: "en0"}, false},
		{"bare name with surrounding space", " \t\"eth1\"\n", scanIface{Name: "eth1"}, false},
		{"object", `{"name":"eth0","cidr":"10.0.0.0/24"}`, scanIface{Name: "eth0", CIDR: "10.0.0.0/24"}, false},
		{"object without cidr", `{"name":"wlan0"}`, scanIface{Name: "wlan0"}, false},
		{"empty object", `{}`, scanIface{}, false},
		{"broken string", `"abc`, scanIface{}, true},
		{"broken object", `{"name":`, scanIface{}, true},
		{"wrong type inside object", `{"name":5}`, scanIface{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got scanIface
			err := json.Unmarshal([]byte(tc.in), &got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestScanConfMixedInterfaces(t *testing.T) {
	var c scanConf
	in := `{"enabled":true,"interval":60,"ports":[22,80],"interfaces":["en0",{"name":"tun0","cidr":"10.9.0.0/24"}]}`
	if err := json.Unmarshal([]byte(in), &c); err != nil {
		t.Fatal(err)
	}
	want := []scanIface{{Name: "en0"}, {Name: "tun0", CIDR: "10.9.0.0/24"}}
	if !c.Enabled || c.Interval != 60 || !reflect.DeepEqual(c.Interfaces, want) || !reflect.DeepEqual(c.Ports, []int{22, 80}) {
		t.Errorf("unexpected conf: %+v", c)
	}
}

func TestTrimSpace(t *testing.T) {
	tests := map[string]string{"": "", "  ": "", " a b ": "a b", "\n\t{}\r\n": "{}"}
	for in, want := range tests {
		if got := string(trimSpace([]byte(in))); got != want {
			t.Errorf("trimSpace(%q) = %q, want %q", in, got, want)
		}
	}
}

// ------------------------------------------------------- constructor + cache

func TestNewScannerPaths(t *testing.T) {
	s, _, dir := scvScanner(t)
	if s.cachePath != filepath.Join(dir, ".scan-cache.json") {
		t.Errorf("cachePath = %q", s.cachePath)
	}
	if s.confPath() != filepath.Join(dir, "scan.yaml") {
		t.Errorf("confPath = %q", s.confPath())
	}
	if s.devicesPath() != filepath.Join(dir, "devices.yaml") {
		t.Errorf("devicesPath = %q", s.devicesPath())
	}
	if got := s.Snapshot(); got.At != 0 || got.Scanning || len(got.Interfaces) != 0 {
		t.Errorf("fresh scanner snapshot should be empty, got %+v", got)
	}
}

func TestNewScannerLoadsCache(t *testing.T) {
	dir := t.TempDir()
	cached := scanSnapshot{At: 1234, Scanning: true, Interfaces: []scanIfaceResult{
		{Name: "eth0", IP: "10.0.0.2", CIDR: "10.0.0.0/24", Devices: []scanDevice{{IP: "10.0.0.5", Ports: []scanPort{{Port: 22, Service: "ssh"}}}}},
	}}
	b, _ := json.Marshal(cached)
	if err := os.WriteFile(filepath.Join(dir, ".scan-cache.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(NewHub(), dir)
	got := s.Snapshot()
	if got.At != 1234 || len(got.Interfaces) != 1 || got.Interfaces[0].Devices[0].IP != "10.0.0.5" {
		t.Errorf("cache not loaded: %+v", got)
	}
	if got.Scanning {
		t.Error("a stale scanning=true in the cache must be cleared on load")
	}
}

func TestLoadCacheIgnoresCorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".scan-cache.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewScanner(NewHub(), dir)
	if got := s.Snapshot(); got.At != 0 || len(got.Interfaces) != 0 {
		t.Errorf("corrupt cache must leave the snapshot empty, got %+v", got)
	}
}

func TestPersistWritesCacheRoundTrip(t *testing.T) {
	yes, no := true, false
	snap := scanSnapshot{At: 99, Interfaces: []scanIfaceResult{{Name: "eth0", Devices: []scanDevice{{IP: "1.2.3.4", Ports: []scanPort{{Port: 80}}}}}}}

	for name, persist := range map[string]*bool{"default": nil, "explicit true": &yes} {
		t.Run(name, func(t *testing.T) {
			s, _, dir := scvScanner(t)
			s.persist(scanConf{Persist: persist}, snap)
			again := NewScanner(NewHub(), dir)
			if got := again.Snapshot(); got.At != 99 || got.Interfaces[0].Devices[0].IP != "1.2.3.4" {
				t.Errorf("round trip lost data: %+v", got)
			}
			left, _ := filepath.Glob(filepath.Join(dir, ".scan-cache-*.tmp"))
			if len(left) != 0 {
				t.Errorf("temp files left behind: %v", left)
			}
		})
	}

	t.Run("persist false writes nothing", func(t *testing.T) {
		s, _, dir := scvScanner(t)
		s.persist(scanConf{Persist: &no}, snap)
		if _, err := os.Stat(filepath.Join(dir, ".scan-cache.json")); !os.IsNotExist(err) {
			t.Errorf("cache file should not exist, stat err = %v", err)
		}
	})

	t.Run("unwritable dir is tolerated", func(t *testing.T) {
		s, _, dir := scvScanner(t)
		s.cachePath = filepath.Join(dir, "missing-subdir", ".scan-cache.json")
		s.persist(scanConf{}, snap) // CreateTemp fails -> silently skipped
		if _, err := os.Stat(s.cachePath); !os.IsNotExist(err) {
			t.Errorf("nothing should have been written, stat err = %v", err)
		}
	})
}

func TestPersistPushesToRedis(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "redis.log")
	scvStub(t, "redis-cli", `echo "$*" >> `+logFile+"\n")
	s, _, _ := scvScanner(t)
	no := false
	s.persist(scanConf{Persist: &no, Redis: "cache.lan:6400"}, scanSnapshot{At: 7})
	b, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("redis-cli was not called: %v", err)
	}
	got := string(b)
	for _, want := range []string{"-h cache.lan", "-p 6400", "SET tforward:scan", `"at":7`} {
		if !strings.Contains(got, want) {
			t.Errorf("redis-cli argv %q missing %q", got, want)
		}
	}
}

// ------------------------------------------------------------- yq readers

func TestReadAnnos(t *testing.T) {
	t.Run("missing devices file", func(t *testing.T) {
		scvYQ(t, `{}`, 0, 0)
		s, _, _ := scvScanner(t)
		if got := s.readAnnos(); len(got) != 0 {
			t.Errorf("want empty, got %v", got)
		}
	})

	write := func(s *Scanner) {
		if err := os.WriteFile(s.devicesPath(), []byte("devices: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("parses, lower-cases ids and skips empty ids", func(t *testing.T) {
		scvYQ(t, `{"devices":[
			{"id":"AA:BB:CC:DD:EE:FF","name":"NAS","tags":["lan","storage"]},
			{"id":"ip:10.0.0.9","name":"printer"},
			{"id":"","name":"orphan"}]}`, 0, 0)
		s, _, _ := scvScanner(t)
		write(s)
		got := s.readAnnos()
		want := map[string]deviceAnno{
			"aa:bb:cc:dd:ee:ff": {Name: "NAS", Tags: []string{"lan", "storage"}},
			"ip:10.0.0.9":       {Name: "printer"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %#v, want %#v", got, want)
		}
	})

	t.Run("yq failure yields empty", func(t *testing.T) {
		scvYQ(t, ``, 1, 0)
		s, _, _ := scvScanner(t)
		write(s)
		if got := s.readAnnos(); len(got) != 0 {
			t.Errorf("want empty, got %v", got)
		}
	})

	t.Run("invalid json yields empty", func(t *testing.T) {
		scvYQ(t, `not json`, 0, 0)
		s, _, _ := scvScanner(t)
		write(s)
		if got := s.readAnnos(); len(got) != 0 {
			t.Errorf("want empty, got %v", got)
		}
	})
}

func TestScannerReadConf(t *testing.T) {
	write := func(s *Scanner) {
		if err := os.WriteFile(s.confPath(), []byte("enabled: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("missing file is a disabled config", func(t *testing.T) {
		scvYQ(t, `{"enabled":true}`, 0, 0)
		s, _, _ := scvScanner(t)
		if c := s.readConf(); c.Enabled {
			t.Errorf("want disabled, got %+v", c)
		}
	})

	t.Run("parses", func(t *testing.T) {
		scvYQ(t, `{"enabled":true,"interval":120,"top_ports":100,"interfaces":["eth0"],"redis":"r:1"}`, 0, 0)
		s, _, _ := scvScanner(t)
		write(s)
		c := s.readConf()
		if !c.Enabled || c.Interval != 120 || c.TopPorts != 100 || c.Redis != "r:1" || len(c.Interfaces) != 1 || c.Interfaces[0].Name != "eth0" {
			t.Errorf("unexpected conf %+v", c)
		}
	})

	t.Run("yq failure is a disabled config", func(t *testing.T) {
		scvYQ(t, `{"enabled":true}`, 2, 0)
		s, _, _ := scvScanner(t)
		write(s)
		if c := s.readConf(); c.Enabled {
			t.Errorf("want disabled, got %+v", c)
		}
	})

	t.Run("garbage output is a disabled config", func(t *testing.T) {
		scvYQ(t, `<<<`, 0, 0)
		s, _, _ := scvScanner(t)
		write(s)
		if c := s.readConf(); c.Enabled || c.Interval != 0 {
			t.Errorf("want zero conf, got %+v", c)
		}
	})
}

// ------------------------------------------------- annotate + broadcast

func TestReannotateAppliesLabelsAndBroadcasts(t *testing.T) {
	scvYQ(t, `{"devices":[{"id":"aa:bb:cc:dd:ee:ff","name":"NAS","tags":["lan"]}]}`, 0, 0)
	s, hub, _ := scvScanner(t)
	if err := os.WriteFile(s.devicesPath(), []byte("devices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.latest = scanSnapshot{At: 5, Interfaces: []scanIfaceResult{{Name: "eth0", Devices: []scanDevice{
		{IP: "10.0.0.5", MAC: "AA:BB:CC:DD:EE:FF"},
		{IP: "10.0.0.6"},
	}}}}
	c := hub.register()
	s.reannotate()

	got := s.Snapshot()
	d := got.Interfaces[0].Devices
	if d[0].Name != "NAS" || !reflect.DeepEqual(d[0].Tags, []string{"lan"}) {
		t.Errorf("labelled device = %+v", d[0])
	}
	if d[1].Name != "" || d[1].Tags != nil {
		t.Errorf("unlabelled device must stay clean: %+v", d[1])
	}
	frames := scvFrames(c)
	if len(frames) != 1 || !strings.HasPrefix(frames[0], "event: scan\n") || !strings.Contains(frames[0], `"name":"NAS"`) {
		t.Errorf("want one annotated scan frame, got %q", frames)
	}
}

func TestBroadcastScanningTogglesFlag(t *testing.T) {
	s, hub, _ := scvScanner(t)
	c := hub.register()

	s.broadcastScanning(true)
	if !s.Snapshot().Scanning {
		t.Error("scanning flag not set")
	}
	s.broadcastScanning(false)
	if s.Snapshot().Scanning {
		t.Error("scanning flag not cleared")
	}
	frames := scvFrames(c)
	if len(frames) != 2 || !strings.Contains(frames[0], `"scanning":true`) || !strings.Contains(frames[1], `"scanning":false`) {
		t.Errorf("unexpected frames %q", frames)
	}
}

func TestScannerEventEmitsLANConsoleLine(t *testing.T) {
	s, hub, _ := scvScanner(t)
	c := hub.register()
	s.event("scanning eth0 10.0.0.0/24…")
	evs := drainEvents(c)
	if len(evs) != 1 {
		t.Fatalf("want 1 event, got %v", evs)
	}
	ev := evs[0]
	if ev["level"] != "scan" || ev["tun"] != "LAN" || ev["msg"] != "scanning eth0 10.0.0.0/24…" {
		t.Errorf("unexpected event %v", ev)
	}
	if _, err := time.Parse(time.RFC3339, ev["ts"].(string)); err != nil {
		t.Errorf("ts is not RFC3339: %v", err)
	}
}

// ------------------------------------------------------- OS lookups

func TestIfaceIPCIDR(t *testing.T) {
	if ip, cidr := ifaceIPCIDR(""); ip != "" || cidr != "" {
		t.Errorf("empty name = %q %q", ip, cidr)
	}
	if ip, cidr := ifaceIPCIDR("definitely-not-a-nic0"); ip != "" || cidr != "" {
		t.Errorf("unknown iface = %q %q", ip, cidr)
	}

	// Pick any interface that really has an IPv4 address and cross-check.
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			_, want, _ := net.ParseCIDR(n.String())
			ip, cidr := ifaceIPCIDR(ifc.Name)
			if ip != n.IP.String() || cidr != want.String() {
				t.Errorf("ifaceIPCIDR(%s) = %q %q, want %q %q", ifc.Name, ip, cidr, n.IP, want)
			}
			return
		}
	}
	t.Skip("no interface with an IPv4 address on this host")
}

func TestArpMAC(t *testing.T) {
	t.Run("finds the MAC column", func(t *testing.T) {
		scvStub(t, "arp", `echo "Address HWtype HWaddress Flags Mask Iface"
echo "$2 ether aa:bb:cc:dd:ee:ff C eth0"
`)
		if got := arpMAC("10.0.0.7"); got != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("no entry", func(t *testing.T) {
		scvStub(t, "arp", `echo "10.0.0.7 (10.0.0.7) -- no entry"`+"\n")
		if got := arpMAC("10.0.0.7"); got != "" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("arp fails", func(t *testing.T) {
		scvStub(t, "arp", "exit 1\n")
		if got := arpMAC("10.0.0.7"); got != "" {
			t.Errorf("got %q", got)
		}
	})
}

func TestParseNmapGreppableResolvesMAC(t *testing.T) {
	scvStub(t, "arp", `echo "$2 ether 00:11:22:33:44:55 C eth0"`+"\n")
	devs := parseNmapGreppable("Host: 10.1.1.1 (gw.lan)\tPorts: 80/open/tcp//http///\n")
	if len(devs) != 1 || devs[0].MAC != "00:11:22:33:44:55" || devs[0].Host != "gw.lan" {
		t.Errorf("unexpected devices %+v", devs)
	}
}

// ------------------------------------------------- scan() without nmap

// An interface whose CIDR is not a real CIDR (e.g. an option-looking value from
// scan.yaml) must never reach nmap: the adapter is reported with no devices.
func TestScanSkipsInvalidCIDRWithoutRunningNmap(t *testing.T) {
	scvStub(t, "sudo", "exit 1\n")
	scvStub(t, "nmap", "echo nmap-must-not-run >&2; exit 99\n")
	s, hub, dir := scvScanner(t)
	c := hub.register()

	s.latest = scanSnapshot{Interfaces: []scanIfaceResult{
		{Name: "eth9", Devices: []scanDevice{{IP: "1.1.1.1"}}},
		{Name: "keep0", Devices: []scanDevice{{IP: "2.2.2.2"}}},
	}}
	conf := scanConf{
		AllPorts: true,
		Interfaces: []scanIface{
			{Name: "eth9", CIDR: "--script=evil"},
			{Name: "keep0", CIDR: "10.0.0.0/24"},
			{}, // nameless + cidr-less entries are dropped
		},
	}
	// targeted rescan of eth9 only: keep0 must be left untouched
	s.scan(context.Background(), conf, "eth9")

	got := s.Snapshot()
	if got.Scanning {
		t.Error("scanning flag must be cleared when scan returns")
	}
	if len(got.Interfaces) != 2 {
		t.Fatalf("want 2 adapters, got %+v", got.Interfaces)
	}
	if r := got.Interfaces[0]; r.Name != "eth9" || r.CIDR != "" || len(r.Devices) != 0 {
		t.Errorf("eth9 must be blanked: %+v", r)
	}
	if r := got.Interfaces[1]; r.Name != "keep0" || len(r.Devices) != 1 || r.Devices[0].IP != "2.2.2.2" {
		t.Errorf("keep0 must be unchanged: %+v", r)
	}
	if got.At == 0 {
		t.Error("completed scan must stamp At")
	}
	if len(drainEvents(c)) != 0 {
		t.Error("no 'scanning …' console event expected when nothing is scanned")
	}
	if _, err := os.Stat(filepath.Join(dir, ".scan-cache.json")); err != nil {
		t.Errorf("finished scan must persist the cache: %v", err)
	}
}

func TestScanPortSpecVariantsAndReentryGuard(t *testing.T) {
	scvStub(t, "sudo", "exit 1\n")
	for name, conf := range map[string]scanConf{
		"explicit ports": {Ports: []int{22, 80}},
		"top ports":      {TopPorts: 50},
		"defaults":       {},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := scvScanner(t)
			s.scan(context.Background(), conf, "")
			if s.Snapshot().Scanning {
				t.Error("scanning flag stuck")
			}
		})
	}

	t.Run("a second scan while one runs is a no-op", func(t *testing.T) {
		s, hub, _ := scvScanner(t)
		c := hub.register()
		s.mu.Lock()
		s.scanning = true
		s.mu.Unlock()
		s.scan(context.Background(), scanConf{}, "")
		if frames := scvFrames(c); len(frames) != 0 {
			t.Errorf("re-entrant scan must not publish, got %q", frames)
		}
		s.mu.Lock()
		still := s.scanning
		s.mu.Unlock()
		if !still {
			t.Error("the running scan's flag must be left alone")
		}
	})
}

func TestRescan(t *testing.T) {
	t.Run("disabled config is a no-op", func(t *testing.T) {
		s, hub, _ := scvScanner(t)
		c := hub.register()
		s.Rescan("")
		time.Sleep(50 * time.Millisecond)
		if frames := scvFrames(c); len(frames) != 0 {
			t.Errorf("disabled rescan must not scan, got %q", frames)
		}
	})

	t.Run("enabled config scans in the background", func(t *testing.T) {
		scvStub(t, "sudo", "exit 1\n")
		scvYQ(t, `{"enabled":true}`, 0, 0)
		s, hub, _ := scvScanner(t)
		if err := os.WriteFile(s.confPath(), []byte("enabled: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c := hub.register()
		s.Rescan("")
		deadline := time.After(5 * time.Second)
		for {
			if s.Snapshot().At != 0 {
				break
			}
			select {
			case <-deadline:
				t.Fatal("background scan never finished")
			case <-time.After(10 * time.Millisecond):
			}
		}
		if len(scvFrames(c)) == 0 {
			t.Error("scan frames expected")
		}
	})
}

// ------------------------------------------------------------ handlers

func scvActions(t *testing.T) (*actEnv, *Scanner) {
	t.Helper()
	e := newActEnv(t)
	e.a.scanner = NewScanner(e.hub, e.root)
	if err := os.MkdirAll(e.d.confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return e, e.a.scanner
}

func TestHandleScanReturnsSnapshot(t *testing.T) {
	e, s := scvActions(t)
	s.latest = scanSnapshot{At: 42, Interfaces: []scanIfaceResult{{Name: "eth0"}}}
	rec := doReq(e.a.handleScan, http.MethodGet, "/scan", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	m := jsonBody(t, rec)
	if m["at"] != float64(42) || len(m["interfaces"].([]any)) != 1 {
		t.Errorf("unexpected body %v", m)
	}
}

func TestHandleScanRescan(t *testing.T) {
	e, _ := scvActions(t)

	if rec := doReq(e.a.handleScanRescan, http.MethodGet, "/scan/rescan", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code %d", rec.Code)
	}
	rec := doReq(e.a.handleScanRescan, http.MethodPost, "/scan/rescan", `{"iface":"eth0; rm -rf /"}`)
	if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid iface" {
		t.Errorf("bad iface: %d %s", rec.Code, rec.Body.String())
	}
	for _, body := range []string{``, `{}`, `{"iface":" eth0 "}`} {
		rec := doReq(e.a.handleScanRescan, http.MethodPost, "/scan/rescan", body)
		if rec.Code != http.StatusOK || jsonBody(t, rec)["ok"] != true {
			t.Errorf("body %q: %d %s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleScanForwardValidation(t *testing.T) {
	e, _ := scvActions(t)
	h := e.a.handleScanForward

	if rec := doReq(h, http.MethodGet, "/scan/forward", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code %d", rec.Code)
	}
	tests := []struct{ name, body, wantErr string }{
		{"missing ip", `{"port":"22"}`, "invalid ip"},
		{"hostname instead of ip", `{"ip":"router.lan","port":"22"}`, "invalid ip"},
		{"ipv6", `{"ip":"::1","port":"22"}`, "invalid ip"},
		{"port not numeric", `{"ip":"10.0.0.5","port":"ssh"}`, "invalid port"},
		{"port zero", `{"ip":"10.0.0.5","port":"0"}`, "invalid port"},
		{"port too big", `{"ip":"10.0.0.5","port":"65536"}`, "invalid port"},
		{"bad iface", `{"ip":"10.0.0.5","port":"22","iface":"a b"}`, "invalid iface"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := doReq(h, http.MethodPost, "/scan/forward", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code %d, body %s", rec.Code, rec.Body.String())
			}
			if got := jsonBody(t, rec)["error"]; got != tc.wantErr {
				t.Errorf("error = %v, want %q", got, tc.wantErr)
			}
		})
	}
	entries, _ := os.ReadDir(e.d.confDir)
	if len(entries) != 0 {
		t.Errorf("rejected requests must not write confs, found %d files", len(entries))
	}
}

func TestHandleScanForwardWritesConfAndBringsItUp(t *testing.T) {
	e, _ := scvActions(t)
	logFile := e.useStubCLI(t, 0)

	rec := doReq(e.a.handleScanForward, http.MethodPost, "/scan/forward", `{"ip":"10.0.0.5","port":"22","iface":"eth0"}`)
	m := jsonBody(t, rec)
	if rec.Code != http.StatusOK || m["ok"] != true || m["name"] != "scan-eth0-10-0-0-5-22" {
		t.Fatalf("unexpected response %d %v", rec.Code, m)
	}
	b, err := os.ReadFile(confPath(e.d.confDir, "scan-eth0-10-0-0-5-22"))
	if err != nil {
		t.Fatalf("conf not written: %v", err)
	}
	conf := string(b)
	for _, want := range []string{
		"name: scan-eth0-10-0-0-5-22\n",
		"type: local\n",
		"tags: [scan]\n",
		"  - ip: 10.0.0.5\n",
		"{ remote: 22, local: any, service: ssh }",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("conf missing %q:\n%s", want, conf)
		}
	}
	if got := calls(t, logFile); !reflect.DeepEqual(got, []string{"up scan-eth0-10-0-0-5-22 --no-prompt"}) {
		t.Errorf("CLI calls = %q", got)
	}
}

func TestHandleScanForwardNameWithoutIfaceAndUnknownService(t *testing.T) {
	e, _ := scvActions(t)
	e.useStubCLI(t, 0)

	rec := doReq(e.a.handleScanForward, http.MethodPost, "/scan/forward", `{"ip":" 192.168.1.20 ","port":" 61234 "}`)
	m := jsonBody(t, rec)
	if m["ok"] != true || m["name"] != "scan-192-168-1-20-61234" {
		t.Fatalf("unexpected response %v", m)
	}
	b, err := os.ReadFile(confPath(e.d.confDir, "scan-192-168-1-20-61234"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "service:") {
		t.Errorf("a port without a well-known service must not get a service label:\n%s", b)
	}
}

func TestHandleScanForwardRefusesExistingConf(t *testing.T) {
	e, _ := scvActions(t)
	logFile := e.useStubCLI(t, 0)
	path := confPath(e.d.confDir, "scan-10-0-0-5-80")
	if err := os.WriteFile(path, []byte("name: mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := doReq(e.a.handleScanForward, http.MethodPost, "/scan/forward", `{"ip":"10.0.0.5","port":"80"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("code %d, body %s", rec.Code, rec.Body.String())
	}
	if b, _ := os.ReadFile(path); string(b) != "name: mine\n" {
		t.Errorf("existing conf was clobbered: %q", b)
	}
	if got := calls(t, logFile); len(got) != 0 {
		t.Errorf("CLI must not run, got %q", got)
	}
}

func TestHandleScanForwardRollsBackConfWhenUpFails(t *testing.T) {
	e, _ := scvActions(t)
	logFile := e.useStubCLI(t, 1)

	rec := doReq(e.a.handleScanForward, http.MethodPost, "/scan/forward", `{"ip":"10.0.0.5","port":"443"}`)
	m := jsonBody(t, rec)
	if rec.Code != http.StatusOK || m["ok"] != false || m["error"] == "" {
		t.Fatalf("unexpected response %d %v", rec.Code, m)
	}
	if _, err := os.Stat(confPath(e.d.confDir, "scan-10-0-0-5-443")); !os.IsNotExist(err) {
		t.Errorf("failed up must remove the conf, stat err = %v", err)
	}
	if got := calls(t, logFile); len(got) != 1 {
		t.Errorf("CLI calls = %q", got)
	}
}

func TestHandleScanForwardConfWriteError(t *testing.T) {
	e, _ := scvActions(t)
	e.d.confDir = filepath.Join(e.root, "no-such-dir") // WriteFile fails
	rec := doReq(e.a.handleScanForward, http.MethodPost, "/scan/forward", `{"ip":"10.0.0.5","port":"80"}`)
	m := jsonBody(t, rec)
	if rec.Code != http.StatusInternalServerError || m["ok"] != false || !strings.HasPrefix(m["error"].(string), "write conf: ") {
		t.Errorf("unexpected response %d %v", rec.Code, m)
	}
}

func TestHandleScanDevice(t *testing.T) {
	t.Run("method", func(t *testing.T) {
		e, _ := scvActions(t)
		if rec := doReq(e.a.handleScanDevice, http.MethodGet, "/scan/device", ""); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("code %d", rec.Code)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		e, _ := scvActions(t)
		rec := doReq(e.a.handleScanDevice, http.MethodPost, "/scan/device", `{`)
		if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "bad json" {
			t.Errorf("%d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("invalid ids", func(t *testing.T) {
		e, s := scvActions(t)
		for _, id := range []string{``, `nonsense`, `ip:::1`, `aa:bb:cc:dd:ee`, `zz:bb:cc:dd:ee:ff`} {
			rec := doReq(e.a.handleScanDevice, http.MethodPost, "/scan/device", `{"id":"`+id+`","name":"x"}`)
			if rec.Code != http.StatusBadRequest || jsonBody(t, rec)["error"] != "invalid device id" {
				t.Errorf("id %q: %d %s", id, rec.Code, rec.Body.String())
			}
		}
		if _, err := os.Stat(s.devicesPath()); !os.IsNotExist(err) {
			t.Error("rejected ids must not create devices.yaml")
		}
	})

	t.Run("name and tags are upserted through strenv", func(t *testing.T) {
		editLog := scvYQ(t, `{"devices":[{"id":"aa:bb:cc:dd:ee:ff","name":"Fridge","tags":["iot"]}]}`, 0, 0)
		e, s := scvActions(t)
		s.latest = scanSnapshot{Interfaces: []scanIfaceResult{{Name: "eth0", Devices: []scanDevice{{IP: "10.0.0.5", MAC: "aa:bb:cc:dd:ee:ff"}}}}}
		c := e.hub.register()

		body := `{"id":" AA:BB:CC:DD:EE:FF ","name":"Fridge $(touch /tmp/pwn)","tags":["iot","kitchen"]}`
		rec := doReq(e.a.handleScanDevice, http.MethodPost, "/scan/device", body)
		if rec.Code != http.StatusOK || jsonBody(t, rec)["ok"] != true {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		b, err := os.ReadFile(s.devicesPath())
		if err != nil || string(b) != "devices: []\n" {
			t.Errorf("devices.yaml should be seeded: %q %v", b, err)
		}
		logged, _ := os.ReadFile(editLog)
		lines := strings.Split(strings.TrimSpace(string(logged)), "\n")
		if len(lines) != 2 {
			t.Fatalf("want 2 yq edits (name, tags), got %q", lines)
		}
		if !strings.Contains(lines[0], "ID=aa:bb:cc:dd:ee:ff") || !strings.Contains(lines[0], "VAL=Fridge $(touch /tmp/pwn)") {
			t.Errorf("name edit env wrong: %s", lines[0])
		}
		if !strings.Contains(lines[1], `J=["iot","kitchen"]`) || !strings.Contains(lines[1], "fromjson") {
			t.Errorf("tags edit wrong: %s", lines[1])
		}
		// reannotate rebroadcast the labelled snapshot
		if got := s.Snapshot().Interfaces[0].Devices[0]; got.Name != "Fridge" {
			t.Errorf("snapshot not re-annotated: %+v", got)
		}
		if frames := scvFrames(c); len(frames) == 0 || !strings.HasPrefix(frames[len(frames)-1], "event: scan\n") {
			t.Errorf("expected a scan frame, got %q", frames)
		}
	})

	t.Run("only tags", func(t *testing.T) {
		editLog := scvYQ(t, `{}`, 0, 0)
		e, _ := scvActions(t)
		rec := doReq(e.a.handleScanDevice, http.MethodPost, "/scan/device", `{"id":"ip:10.0.0.5","tags":[]}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		logged, _ := os.ReadFile(editLog)
		if lines := strings.Split(strings.TrimSpace(string(logged)), "\n"); len(lines) != 1 || !strings.Contains(lines[0], "J=[]") {
			t.Errorf("want one tags edit with an empty list, got %q", lines)
		}
	})

	t.Run("name edit failure", func(t *testing.T) {
		scvYQ(t, `{}`, 0, 3)
		e, _ := scvActions(t)
		rec := doReq(e.a.handleScanDevice, http.MethodPost, "/scan/device", `{"id":"ip:10.0.0.5","name":"x"}`)
		m := jsonBody(t, rec)
		if rec.Code != http.StatusInternalServerError || m["ok"] != false || !strings.HasPrefix(m["error"].(string), "yq: ") {
			t.Errorf("%d %v", rec.Code, m)
		}
	})

	t.Run("tags edit failure", func(t *testing.T) {
		scvYQ(t, `{}`, 0, 3)
		e, _ := scvActions(t)
		rec := doReq(e.a.handleScanDevice, http.MethodPost, "/scan/device", `{"id":"ip:10.0.0.5","tags":["a"]}`)
		m := jsonBody(t, rec)
		if rec.Code != http.StatusInternalServerError || m["ok"] != false {
			t.Errorf("%d %v", rec.Code, m)
		}
	})

	t.Run("devices.yaml cannot be created", func(t *testing.T) {
		scvYQ(t, `{}`, 0, 0)
		e, _ := scvActions(t)
		e.a.scanner = NewScanner(e.hub, filepath.Join(e.root, "gone")) // dir does not exist
		rec := doReq(e.a.handleScanDevice, http.MethodPost, "/scan/device", `{"id":"ip:10.0.0.5","name":"x"}`)
		if rec.Code != http.StatusInternalServerError || jsonBody(t, rec)["ok"] != false {
			t.Errorf("%d %s", rec.Code, rec.Body.String())
		}
	})
}
