package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestProbeReason(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"auth", errors.New("handshake ssh: ssh: unable to authenticate, attempted methods [none password]"), "credenciales SSH inválidas"},
		{"timeout", errors.New("conexión: dial tcp 192.0.2.9:22: i/o timeout"), "sin respuesta (timeout)"},
		{"deadline", errors.New("handshake ssh: context deadline exceeded"), "sin respuesta (timeout)"},
		{"refused", errors.New("conexión: dial tcp 192.0.2.9:22: connect: connection refused"), "conexión rechazada"},
		{"noroute", errors.New("conexión: dial tcp: no route to host"), "host inalcanzable"},
		{"nohost", errors.New("conexión: dial tcp: lookup foo: no such host"), "host inalcanzable"},
		{"detect", errors.New("no se pudo identificar el vendor tras show version"), "vendor no identificado"},
		{"other", errors.New("solicitud de pty: algo raro\nsegunda línea"), "solicitud de pty: algo raro"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := probeReason(c.err); got != c.want {
				t.Errorf("probeReason(%q) = %q, want %q", c.err, got, c.want)
			}
		})
	}
}

func TestWriteBackup(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)

	backups := map[string]backupRecord{
		"192.0.2.16": {Vendor: "huawei", SNMPConfig: "snmp-agent community read cipher %^%#x%^%#"},
	}
	path, err := writeBackup(backups)
	if err != nil || path == "" {
		t.Fatalf("writeBackup: path=%q err=%v", path, err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		GeneratedAt string                  `json:"generated_at"`
		Devices     map[string]backupRecord `json:"devices"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("backup is not valid json: %v", err)
	}
	if doc.GeneratedAt == "" {
		t.Error("generated_at missing")
	}
	if got := doc.Devices["192.0.2.16"]; got.Vendor != "huawei" || !strings.Contains(got.SNMPConfig, "cipher") {
		t.Errorf("device record not persisted: %+v", got)
	}

	// No devices → nothing written, no error.
	if p, err := writeBackup(nil); err != nil || p != "" {
		t.Errorf("empty backup should write nothing: p=%q err=%v", p, err)
	}
}
