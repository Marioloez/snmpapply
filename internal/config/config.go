// Package config loads the device inventory (JSON) and credentials (.env),
// then resolves each device into a ready-to-use Target.
//
// The inventory is a JSON array whose elements are usually just host strings —
// credentials, user and community all come from .env, since the binary runs on
// the site's own probe. An element may also be an object for the rare case that
// needs a per-device override (explicit vendor, different community, etc.).
package config

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Device is one inventory entry.
type Device struct {
	Host        string `json:"host"`
	Vendor      string `json:"vendor"`       // optional: skip autodetect
	Community   string `json:"community"`    // optional override (else SNMP_COMMUNITY)
	PasswordEnv string `json:"password_env"` // optional: env var holding this device's password
	Port        int    `json:"port"`         // optional (else 22)
}

// UnmarshalJSON accepts either a bare host string ("192.0.2.9") or a full
// object, so the common inventory is just a list of IPs.
func (d *Device) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "\"") {
		var host string
		if err := json.Unmarshal(b, &host); err != nil {
			return err
		}
		*d = Device{Host: host}
		return nil
	}
	type alias Device // avoid recursing into this method
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*d = Device(a)
	return nil
}

// Inventory is the parsed inventory file: a flat list of devices.
type Inventory struct {
	Devices []Device
}

// Target is a fully resolved device ready to be processed.
type Target struct {
	Host      string
	Vendor    string // canonical lowercase, or "" for autodetect
	User      string
	Password  string
	Community string
	Port      int
}

// LoadInventory reads and parses an inventory JSON file (a JSON array).
func LoadInventory(path string) (*Inventory, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("leer inventario: %w", err)
	}
	var devices []Device
	if err := json.Unmarshal(b, &devices); err != nil {
		return nil, fmt.Errorf("parsear inventario %s (debe ser una lista JSON de IPs): %w", path, err)
	}
	return &Inventory{Devices: devices}, nil
}

// LoadDotenv parses a .env file into a map. Missing file => empty map, no error.
func LoadDotenv(path string) map[string]string {
	m := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := unquote(strings.TrimSpace(line[eq+1:]))
		m[key] = val
	}
	return m
}

// Getenv returns a lookup function where the real process environment wins,
// falling back to values parsed from a .env file.
func Getenv(dotenv map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			return v
		}
		return dotenv[k]
	}
}

// Resolve fills each device from .env (SSH_USER, SSH_PASSWORD, SNMP_COMMUNITY,
// SSH_PORT) plus any per-device overrides. It returns usable targets and a slice
// of errors for skipped devices, so one bad entry never aborts the batch.
//
// A password is always required; the community is required only when
// requireCommunity is set (dry-run scans don't apply it).
func (inv *Inventory) Resolve(get func(string) string, requireCommunity bool) ([]Target, []error) {
	defUser := get("SSH_USER")
	defComm := get("SNMP_COMMUNITY")
	defPass := get("SSH_PASSWORD")
	defPort := atoiDefault(get("SSH_PORT"), 22)

	var targets []Target
	var errs []error
	for i, d := range inv.Devices {
		if strings.TrimSpace(d.Host) == "" {
			errs = append(errs, fmt.Errorf("dispositivo[%d]: falta host", i))
			continue
		}
		t := Target{
			Host:      d.Host,
			Vendor:    strings.ToLower(strings.TrimSpace(d.Vendor)),
			User:      defUser,
			Community: firstNonEmpty(d.Community, defComm),
			Port:      firstInt(d.Port, defPort),
		}
		if d.PasswordEnv != "" {
			t.Password = get(d.PasswordEnv)
		} else {
			t.Password = defPass
		}
		if requireCommunity && t.Community == "" {
			errs = append(errs, fmt.Errorf("dispositivo %s: sin comunidad (define SNMP_COMMUNITY en .env)", d.Host))
			continue
		}
		if t.Password == "" {
			errs = append(errs, fmt.Errorf("dispositivo %s: sin contraseña (define SSH_PASSWORD en .env)", d.Host))
			continue
		}
		targets = append(targets, t)
	}
	return targets, errs
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstInt(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return def
}
