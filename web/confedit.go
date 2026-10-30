package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// confEdit is the whitelist of things the web UI may change in a conf file.
// Sensitive keys (the vpn/ssh password, psk, servercert, totp_secret, ssh key)
// are NEVER in scope — the edits below only ever touch these specific paths.
type confEdit struct {
	Name     *string             `json:"name"`     // tunnel display name -> .name
	Tags     *[]string           `json:"tags"`     // tunnel tags -> .tags
	Hosts    map[string]hostEdit `json:"hosts"`    // ip -> host name/tags
	Forwards map[string]string   `json:"forwards"` // "ip:rport" -> forward note
	Subnets  map[string]hostEdit `json:"subnets"`  // CIDR -> subnet label/tags
}

type hostEdit struct {
	Note *string   `json:"note"`
	Tags *[]string `json:"tags"`
}

// handleConf applies whitelisted edits to a YAML conf via `yq -i`. Every value
// reaches yq through an environment variable read with strenv()/fromjson, so a
// crafted value can never inject yq syntax; the expressions themselves are
// constant and only ever address the whitelisted paths.
func (a *Actions) handleConf(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "POST only"})
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/conf/")
	if !validName(name) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad name"})
		return
	}
	path := confPath(a.docker.confDir, name)
	if _, err := os.Stat(path); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "no such tunnel"})
		return
	}
	var e confEdit
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&e); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "bad json"})
		return
	}
	if err := validateEdit(e); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if err := applyEdits(path, e); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	a.docker.broadcastState()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// validateEdit is a light sanity pass. Injection is already impossible (values
// go through strenv), so this only rejects shapes that would be nonsensical:
// multi-line scalars, tags with whitespace, and non-CIDR / non-numeric keys.
func validateEdit(e confEdit) error {
	oneLine := func(s string) bool { return !strings.ContainsAny(s, "\n\r") }
	tagOK := func(t string) bool { return oneLine(t) && !strings.ContainsAny(t, " \t") }
	if e.Name != nil && !oneLine(*e.Name) {
		return errStr("name must be one line")
	}
	if e.Tags != nil {
		for _, t := range *e.Tags {
			if !tagOK(t) {
				return errStr("tag has an illegal character")
			}
		}
	}
	for _, h := range e.Hosts {
		if h.Note != nil && !oneLine(*h.Note) {
			return errStr("host note must be one line")
		}
		if h.Tags != nil {
			for _, t := range *h.Tags {
				if !tagOK(t) {
					return errStr("host tag has an illegal character")
				}
			}
		}
	}
	for k, v := range e.Forwards {
		ip, rport, ok := strings.Cut(k, ":")
		if !ok || ip == "" || !validPort(rport) {
			return errStr("forward key must be ip:port")
		}
		if !oneLine(v) {
			return errStr("forward note must be one line")
		}
	}
	for cidr, h := range e.Subnets {
		if !validCIDRKey(cidr) {
			return errStr("subnet key is not a CIDR")
		}
		if h.Note != nil && !oneLine(*h.Note) {
			return errStr("subnet label must be one line")
		}
		if h.Tags != nil {
			for _, t := range *h.Tags {
				if !tagOK(t) {
					return errStr("subnet tag has an illegal character")
				}
			}
		}
	}
	return nil
}

// applyEdits runs one focused `yq -i` per provided field. A failure aborts and
// reports; earlier successful edits stay (yq writes atomically per call).
func applyEdits(path string, e confEdit) error {
	if e.Name != nil {
		if err := yqEdit(path, `.name = strenv(VAL)`, env{"VAL": *e.Name}); err != nil {
			return err
		}
	}
	if e.Tags != nil {
		if err := yqEdit(path, `.tags = (strenv(J)|fromjson)`, env{"J": jsonArr(*e.Tags)}); err != nil {
			return err
		}
	}
	for ip, h := range e.Hosts {
		if h.Note != nil {
			if err := yqEdit(path,
				`(.hosts[] | select(.ip == strenv(IP)) | .name) = strenv(VAL)`,
				env{"IP": ip, "VAL": *h.Note}); err != nil {
				return err
			}
		}
		if h.Tags != nil {
			if err := yqEdit(path,
				`(.hosts[] | select(.ip == strenv(IP)) | .tags) = (strenv(J)|fromjson)`,
				env{"IP": ip, "J": jsonArr(*h.Tags)}); err != nil {
				return err
			}
		}
	}
	for key, note := range e.Forwards {
		ip, rport, _ := strings.Cut(key, ":")
		if err := yqEdit(path,
			`(.hosts[] | select(.ip == strenv(IP)) | .forwards[] | select(.remote == (strenv(RP)|fromjson)) | .note) = strenv(VAL)`,
			env{"IP": ip, "RP": rport, "VAL": note}); err != nil {
			return err
		}
	}
	for cidr, h := range e.Subnets {
		if h.Note != nil {
			if err := subnetUpsert(path, cidr, `"label": strenv(VAL)`, env{"C": cidr, "VAL": *h.Note}); err != nil {
				return err
			}
		}
		if h.Tags != nil {
			if err := subnetUpsert(path, cidr, `"tags": (strenv(J)|fromjson)`, env{"C": cidr, "J": jsonArr(*h.Tags)}); err != nil {
				return err
			}
		}
	}
	return nil
}

// subnetUpsert sets one field on the subnets[] entry with the given CIDR,
// creating the entry if absent and preserving the entry's other fields. Reorders
// the edited entry to the end of the list (cosmetic; the list is small).
func subnetUpsert(path, cidr, field string, e env) error {
	expr := `{"cidr": strenv(C), ` + field + `} as $new |` +
		`((.subnets // []) | map(select(.cidr == strenv(C))) | .[0] // {}) as $cur |` +
		`.subnets = ((.subnets // []) | map(select(.cidr != strenv(C)))) + [$cur * $new]`
	return yqEdit(path, expr, e)
}

type env map[string]string

// yqEdit runs `yq -i <expr> <path>` with the given extra environment.
func yqEdit(path, expr string, extra env) error {
	cmd := exec.Command("yq", "-i", expr, path)
	cmd.Env = os.Environ()
	for k, v := range extra {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("yq: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func jsonArr(s []string) string {
	if s == nil {
		s = []string{}
	}
	b, _ := json.Marshal(s)
	return string(b)
}

// isNumeric reports whether s is a non-empty run of ASCII digits that fits an
// int. A sign (strconv.Atoi accepts "-1" and "+80") is not a digit.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	_, err := strconv.Atoi(s)
	return err == nil
}

// validPort accepts a forward remote port as written in the conf: ASCII digits
// only, no leading zero (the yq lookup parses it as a JSON number), 1-65535.
func validPort(s string) bool {
	if !isNumeric(s) || s[0] == '0' {
		return false
	}
	n, _ := strconv.Atoi(s)
	return n >= 1 && n <= 65535
}

// validCIDRKey accepts only real IPv4 CIDRs: digits, dots and one slash, and
// the key must parse with net.ParseCIDR as an IPv4 network (which also rejects
// leading-zero octets and prefixes such as "/099", and IPv6 forms).
func validCIDRKey(s string) bool {
	if s == "" || strings.Count(s, "/") != 1 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9') && r != '.' && r != '/' {
			return false
		}
	}
	_, ipn, err := net.ParseCIDR(s)
	return err == nil && ipn.IP.To4() != nil
}

type errStr string

func (e errStr) Error() string { return string(e) }
