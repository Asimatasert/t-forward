package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Config files are YAML, read with `yq -o=json` and unmarshalled with the
// stdlib JSON decoder — so the daemon needs the `yq` binary (already required by
// the CLI) but no Go YAML dependency, and it never executes the file as bash.

// scalar is a YAML scalar that may arrive as a number or a string (e.g. a port
// written 8080 or "any"). It keeps the raw textual form.
type scalar struct{ s string }

func (v *scalar) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		v.s = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		v.s = s
		return nil
	}
	v.s = string(b) // number/bool as written
	return nil
}
func (v scalar) String() string { return v.s }

// jumpHop is one ssh ProxyJump hop, written either as a bare string ("host") or
// an object ({host, user, port}).
type jumpHop struct {
	Host string `json:"host"`
	User string `json:"user"`
	Port int    `json:"port"`
}

func (h *jumpHop) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		h.Host = s
		return nil
	}
	type raw jumpHop
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*h = jumpHop(r)
	return nil
}

// token renders a hop as "[user@]host[:port]" for display / the SSH_JUMP env.
func (h jumpHop) token() string {
	s := h.Host
	if h.User != "" {
		s = h.User + "@" + s
	}
	if h.Port != 0 && h.Port != 22 {
		s = s + ":" + strconv.Itoa(h.Port)
	}
	return s
}

// confYAML mirrors the on-disk YAML schema. See examples/ for the shape.
type confYAML struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Tags        []string `json:"tags"`
	Socks       scalar   `json:"socks"`
	Restart     bool     `json:"restart"`
	TotpCommand string   `json:"totp_command"`

	VPN *struct {
		Server     string `json:"server"`
		Protocol   string `json:"protocol"`
		User       string `json:"user"`
		Password   string `json:"password"`
		Servercert string `json:"servercert"`
		Authgroup  string `json:"authgroup"`
		Totp       bool   `json:"totp"`
		TotpSecret string `json:"totp_secret"`
	} `json:"vpn"`

	SSH *struct {
		Host string    `json:"host"`
		User string    `json:"user"`
		Port int       `json:"port"`
		Key  string    `json:"key"`
		Jump []jumpHop `json:"jump"`
	} `json:"ssh"`

	Hosts []struct {
		IP       string   `json:"ip"`
		Name     string   `json:"name"`
		Tags     []string `json:"tags"`
		Forwards []struct {
			Remote  scalar `json:"remote"`
			Local   scalar `json:"local"`
			Service string `json:"service"`
			User    string `json:"user"`
			Note    string `json:"note"`
		} `json:"forwards"`
	} `json:"hosts"`

	Subnets []struct {
		CIDR  string   `json:"cidr"`
		Label string   `json:"label"`
		Tags  []string `json:"tags"`
	} `json:"subnets"`
}

// confPath is the on-disk path for a tunnel's config file.
func confPath(dir, name string) string { return filepath.Join(dir, name+".yaml") }

// readConfYAML runs the YAML file through yq into JSON and unmarshals it.
func readConfYAML(path string) (*confYAML, error) {
	out, err := exec.Command("yq", "-o=json", ".", path).Output()
	if err != nil {
		return nil, err
	}
	var c confYAML
	if err := json.Unmarshal(out, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// tunnelFromConf builds a Tunnel from a conf file (state defaults to "off").
// Results are cached by the file's mtime+size so the frequent State() calls
// don't re-fork yq for unchanged configs. The Forwards slice is cloned on the
// way out because callers overwrite it (resolving real published ports).
func (d *Docker) tunnelFromConf(name string) Tunnel {
	path := confPath(d.confDir, name)
	var fi os.FileInfo
	if s, err := os.Stat(path); err == nil {
		fi = s
		d.mu.Lock()
		e, ok := d.confCache[name]
		d.mu.Unlock()
		if ok && e.mtime.Equal(fi.ModTime()) && e.size == fi.Size() {
			return cloneForwards(e.tun)
		}
	}

	c, err := readConfYAML(path)
	if err != nil || c == nil {
		return Tunnel{ID: name, Type: "vpn", State: "off", Tags: []string{}, Forwards: []Forward{}}
	}

	typ := c.Type
	if typ == "" {
		typ = "vpn"
	}

	socks := c.Socks.String()
	if socks != "" && !strings.Contains(socks, ":") {
		socks = "127.0.0.1:" + socks
	}

	forwards := []Forward{}
	notes := map[string]string{}
	hostTags := map[string][]string{}
	for _, h := range c.Hosts {
		ip := strings.TrimSpace(h.IP)
		if ip == "" {
			continue
		}
		if h.Name != "" {
			notes[ip] = h.Name
		}
		if len(h.Tags) > 0 {
			hostTags[ip] = h.Tags
		}
		for _, f := range h.Forwards {
			rport := f.Remote.String()
			if rport == "" {
				continue
			}
			local := localSpec(f.Local.String())
			svc := f.Service
			if svc == "" {
				svc = serviceForPort(rport)
			}
			forwards = append(forwards, Forward{
				Local: local, Remote: ip + ":" + rport,
				Service: svc, User: f.User, Note: f.Note,
			})
		}
	}

	subnetNotes := map[string]string{}
	subnetTags := map[string][]string{}
	for _, s := range c.Subnets {
		if s.CIDR == "" {
			continue
		}
		if s.Label != "" {
			subnetNotes[s.CIDR] = s.Label
		}
		if len(s.Tags) > 0 {
			subnetTags[s.CIDR] = s.Tags
		}
	}

	t := Tunnel{
		ID:          name,
		Type:        typ,
		Desc:        c.Name,
		State:       "off",
		Tags:        orEmpty(c.Tags),
		Forwards:    forwards,
		Socks:       socks,
		Restart:     c.Restart,
		HostNotes:   notes,
		HostTags:    hostTags,
		SubnetNotes: subnetNotes,
		SubnetTags:  subnetTags,
	}
	if c.VPN != nil {
		t.Totp = c.VPN.Totp
		t.Proto = c.VPN.Protocol
		t.Server = c.VPN.Server
		t.User = c.VPN.User
	}
	if c.SSH != nil {
		t.SSHHost = c.SSH.Host
		if t.User == "" {
			t.User = c.SSH.User
		}
		for _, hop := range c.SSH.Jump {
			if tok := hop.token(); tok != "" {
				t.SSHJump = append(t.SSHJump, tok)
			}
		}
	}

	if fi != nil {
		d.mu.Lock()
		d.confCache[name] = confCacheEntry{mtime: fi.ModTime(), size: fi.Size(), tun: t}
		d.mu.Unlock()
	}
	return cloneForwards(t)
}

// cloneForwards returns t with an independent copy of its Forwards slice, so a
// caller that overwrites forward fields can't mutate a cached Tunnel.
func cloneForwards(t Tunnel) Tunnel {
	if t.Forwards != nil {
		t.Forwards = append([]Forward(nil), t.Forwards...)
	}
	return t
}

// publishBind is the address forwards publish on when a forward doesn't set its
// own BIND:PORT — mirrors the CLI's T_FORWARD_BIND so a configured (down) tunnel
// displays the same bind it will actually use once up.
var publishBind = func() string {
	if b := os.Getenv("T_FORWARD_BIND"); b != "" {
		return b
	}
	return "127.0.0.1"
}()

// localSpec normalises a forward's local side: "any"/"" -> auto port, a bare
// port -> <bind>:port, a bind:port stays as written.
func localSpec(lspec string) string {
	switch {
	case lspec == "any" || lspec == "":
		return publishBind + ":auto"
	case strings.Contains(lspec, ":"):
		return lspec
	default:
		return publishBind + ":" + lspec
	}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
