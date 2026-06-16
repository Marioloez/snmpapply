package driver

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestCaptureSNMP(t *testing.T) {
	cmd := "show snmp-server"
	raw := "show snmp-server\r\n\x1b7  Get  Community  : public\r\n  Set  Community  : private\r\n"
	got := captureSNMP(cmd, raw)
	if strings.Contains(got, "show snmp-server") {
		t.Errorf("echoed command not stripped: %q", got)
	}
	if !strings.Contains(got, "Get  Community  : public") {
		t.Errorf("community line missing: %q", got)
	}
	if strings.Contains(got, "\x1b") {
		t.Errorf("ANSI escape not stripped: %q", got)
	}
}

func TestZyxelSNMPConfig(t *testing.T) {
	esc := "\x1b7"
	steps := []reply{
		{regexp.MustCompile(`show snmp-server`), "show snmp-server\r\n  Get  Community  : public\r\nSW-SOTANO# " + esc},
	}
	s := newScriptedSession("SW-SOTANO# "+esc, steps)
	ctx := context.Background()
	s.Collect(ctx, 150*time.Millisecond, 1*time.Second)

	out, err := zyxel{}.SNMPConfig(ctx, s, Params{})
	if err != nil {
		t.Fatalf("SNMPConfig error: %v", err)
	}
	if !strings.Contains(out, "public") {
		t.Errorf("backup missing community: %q", out)
	}
	if strings.Contains(out, "show snmp-server") {
		t.Errorf("echoed command not stripped: %q", out)
	}
}

func TestHuaweiSNMPConfig(t *testing.T) {
	steps := []reply{
		{regexp.MustCompile(`screen-length`), "\r\n<MPS-Sombrero>"},
		{regexp.MustCompile(`display current-configuration`), "\r\nsnmp-agent community read cipher %^%#abc%^%#\r\nsnmp-agent sys-info version v2c\r\n<MPS-Sombrero>"},
	}
	s := newScriptedSession("\r\n<MPS-Sombrero>", steps)
	ctx := context.Background()
	s.Collect(ctx, 150*time.Millisecond, 1*time.Second)

	out, err := huawei{}.SNMPConfig(ctx, s, Params{})
	if err != nil {
		t.Fatalf("SNMPConfig error: %v", err)
	}
	if !strings.Contains(out, "community read cipher") {
		t.Errorf("backup missing community line: %q", out)
	}
}
