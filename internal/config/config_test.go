package config

import (
	"encoding/json"
	"testing"
)

func TestResolveFromEnvAndOverrides(t *testing.T) {
	inv := &Inventory{Devices: []Device{
		{Host: "10.0.0.1"},                           // everything from .env
		{Host: "10.0.0.2", Vendor: "Ruckus"},         // vendor normalized
		{Host: "10.0.0.3", PasswordEnv: "PASS_SITE"}, // per-device password
		{Host: ""},                                   // invalid host -> error
	}}

	env := map[string]string{
		"SSH_USER":       "testuser",
		"SSH_PASSWORD":   "defaultpass",
		"SNMP_COMMUNITY": "public",
		"PASS_SITE":      "sitepass",
	}
	get := func(k string) string { return env[k] }

	targets, errs := inv.Resolve(get, true)
	if len(targets) != 3 {
		t.Fatalf("want 3 targets, got %d (%+v)", len(targets), targets)
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 error, got %d (%v)", len(errs), errs)
	}
	if targets[0].User != "testuser" || targets[0].Community != "public" || targets[0].Password != "defaultpass" {
		t.Errorf("device 0 not filled from env: %+v", targets[0])
	}
	if targets[0].Port != 22 {
		t.Errorf("device 0 default port want 22, got %d", targets[0].Port)
	}
	if targets[1].Vendor != "ruckus" {
		t.Errorf("vendor not normalized to lowercase: %q", targets[1].Vendor)
	}
	if targets[2].Password != "sitepass" {
		t.Errorf("device 2 password_env not resolved: %q", targets[2].Password)
	}
}

func TestDeviceUnmarshalStringOrObject(t *testing.T) {
	var ds []Device
	if err := json.Unmarshal([]byte(`["192.0.2.9", {"host":"192.0.2.30","vendor":"zyxel"}]`), &ds); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ds) != 2 {
		t.Fatalf("want 2 devices, got %d", len(ds))
	}
	if ds[0].Host != "192.0.2.9" || ds[0].Vendor != "" {
		t.Errorf("bare-string device wrong: %+v", ds[0])
	}
	if ds[1].Host != "192.0.2.30" || ds[1].Vendor != "zyxel" {
		t.Errorf("object device wrong: %+v", ds[1])
	}
}

func TestResolveRequiresCommunityAndPassword(t *testing.T) {
	inv := &Inventory{}
	inv.Devices = []Device{
		{Host: "10.0.0.1"}, // no community, no password anywhere
	}
	get := func(string) string { return "" } // empty env, no defaults

	targets, errs := inv.Resolve(get, true)
	if len(targets) != 0 {
		t.Fatalf("want 0 targets, got %d", len(targets))
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 error (community is checked first), got %d (%v)", len(errs), errs)
	}
}

func TestResolveDryRunAllowsMissingCommunity(t *testing.T) {
	inv := &Inventory{}
	inv.Devices = []Device{{Host: "10.0.0.1"}} // no community anywhere
	get := func(k string) string {
		if k == "SSH_PASSWORD" {
			return "pw"
		}
		return ""
	}

	targets, errs := inv.Resolve(get, false) // dry-run: community not required
	if len(targets) != 1 {
		t.Fatalf("want 1 target, got %d", len(targets))
	}
	if len(errs) != 0 {
		t.Fatalf("want 0 errors, got %v", errs)
	}
}

func TestDotenvPrecedence(t *testing.T) {
	// Real env wins over dotenv when set; dotenv fills the rest.
	dotenv := map[string]string{"SSH_USER": "fromfile", "SNMP_COMMUNITY": "filecomm"}
	t.Setenv("SSH_USER", "fromenv")
	get := Getenv(dotenv)

	if got := get("SSH_USER"); got != "fromenv" {
		t.Errorf("real env should win: got %q", got)
	}
	if got := get("SNMP_COMMUNITY"); got != "filecomm" {
		t.Errorf("dotenv fallback failed: got %q", got)
	}
}

func TestUnquote(t *testing.T) {
	cases := map[string]string{
		`"hello"`: "hello",
		`'world'`: "world",
		`plain`:   "plain",
		`"x`:      `"x`,
	}
	for in, want := range cases {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q, want %q", in, got, want)
		}
	}
}
