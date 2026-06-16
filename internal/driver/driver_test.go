package driver

import (
	"context"
	"io"
	"regexp"
	"testing"
	"time"

	"github.com/Marioloez/snmpapply/internal/transport"
)

// reply is one scripted device response: when the device sees `when` in the
// commands it receives, it sends `send` back.
type reply struct {
	when *regexp.Regexp
	send string
}

// newScriptedSession wires a transport.Session to an in-memory fake device that
// emits `initial`, then walks `steps` in order, matching each against the
// commands the driver sends. This exercises the real expect engine end-to-end.
func newScriptedSession(initial string, steps []reply) *transport.Session {
	sessRead, devWrite := io.Pipe() // device writes -> session reads
	devRead, sessWrite := io.Pipe() // session writes -> device reads
	sess := transport.NewSession(sessRead, sessWrite, io.Discard, 2*time.Second)

	go func() {
		_, _ = io.WriteString(devWrite, initial)
		buf := make([]byte, 4096)
		acc := ""
		si := 0
		for si < len(steps) {
			n, err := devRead.Read(buf)
			if n > 0 {
				acc += string(buf[:n])
			}
			if err != nil {
				return
			}
			for si < len(steps) && steps[si].when.MatchString(acc) {
				_, _ = io.WriteString(devWrite, steps[si].send)
				acc = ""
				si++
			}
		}
	}()
	return sess
}

func TestHuaweiApply(t *testing.T) {
	steps := []reply{
		{regexp.MustCompile(`screen-length`), "\r\n<MPS-Sombrero>"},
		{regexp.MustCompile(`system-view`), "\r\nEnter system view\r\n[MPS-Sombrero]"},
		{regexp.MustCompile(`sys-info version v2c`), "\r\n[MPS-Sombrero]"},
		{regexp.MustCompile(`community read cipher`), "\r\n[MPS-Sombrero]"},
		{regexp.MustCompile(`display snmp-agent community read`), "\r\nCommunity name: ****** read\r\n[MPS-Sombrero]"},
		{regexp.MustCompile(`quit`), "\r\n<MPS-Sombrero>"},
		{regexp.MustCompile(`save`), "\r\nAre you sure to continue?[Y/N]:"},
		{regexp.MustCompile(`y`), "\r\nSave OK\r\n<MPS-Sombrero>"},
	}
	s := newScriptedSession("\r\n<MPS-Sombrero>", steps)
	ctx := context.Background()
	s.Collect(ctx, 150*time.Millisecond, 1*time.Second) // mimic detect.Prime

	rep, err := huawei{}.Apply(ctx, s, Params{Community: "snmp_test"})
	if err != nil {
		t.Fatalf("apply error: %v", err)
	}
	if !rep.Applied || !rep.Saved {
		t.Fatalf("expected applied+saved, got %+v", rep)
	}
	if !rep.Verified {
		t.Errorf("expected verified true, got %+v", rep)
	}
}

func TestRuckusApplyWithEnableAuth(t *testing.T) {
	steps := []reply{
		{regexp.MustCompile(`enable`), "\r\nUser Name:"},
		{regexp.MustCompile(`admin`), "\r\nPassword:"},
		{regexp.MustCompile(`secret`), "\r\nMPS#"},
		{regexp.MustCompile(`skip-page-display`), "\r\nMPS#"},
		{regexp.MustCompile(`configure terminal`), "\r\nMPS(config)#"},
		{regexp.MustCompile(`community .* ro`), "\r\nMPS(config)#"},
		{regexp.MustCompile(`exit`), "\r\nMPS#"},
		{regexp.MustCompile(`show snmp server`), "\r\ncommunity snmp_test ro\r\nMPS#"},
		{regexp.MustCompile(`write memory`), "\r\nWrite OK\r\nMPS#"},
	}
	s := newScriptedSession("\r\nMPS-Sombrero>", steps)
	ctx := context.Background()
	s.Collect(ctx, 150*time.Millisecond, 1*time.Second)

	rep, err := ruckus{}.Apply(ctx, s, Params{Community: "snmp_test", User: "admin", Password: "secret"})
	if err != nil {
		t.Fatalf("apply error: %v", err)
	}
	if !rep.Applied || !rep.Saved || !rep.Verified {
		t.Fatalf("expected applied+saved+verified, got %+v", rep)
	}
}

func TestZyxelApply(t *testing.T) {
	esc := "\x1b7" // ZyNOS spams ESC-7 after every prompt
	steps := []reply{
		{regexp.MustCompile(`configure`), "configure\r\nSW-SOTANO(config)# " + esc},
		{regexp.MustCompile(`get-community`), "SW-SOTANO(config)# " + esc},
		{regexp.MustCompile(`exit`), "SW-SOTANO# " + esc},
		{regexp.MustCompile(`write`), "SW-SOTANO# " + esc},
		{regexp.MustCompile(`show snmp-server`), "  Get  Community  : snmp_test\r\nSW-SOTANO# " + esc},
	}
	s := newScriptedSession("SW-SOTANO# "+esc, steps)
	ctx := context.Background()
	s.Collect(ctx, 150*time.Millisecond, 1*time.Second)

	rep, err := zyxel{}.Apply(ctx, s, Params{Community: "snmp_test"})
	if err != nil {
		t.Fatalf("apply error: %v", err)
	}
	if !rep.Applied || !rep.Saved || !rep.Verified {
		t.Fatalf("expected applied+saved+verified, got %+v", rep)
	}
}

func TestCiscoApply(t *testing.T) {
	steps := []reply{
		{regexp.MustCompile(`enable`), "\r\nPassword:"},
		{regexp.MustCompile(`secret`), "\r\nMPS-Cat#"},
		{regexp.MustCompile(`terminal length 0`), "\r\nMPS-Cat#"},
		{regexp.MustCompile(`configure terminal`), "\r\nMPS-Cat(config)#"},
		{regexp.MustCompile(`snmp-server community .* RO`), "\r\nMPS-Cat(config)#"},
		{regexp.MustCompile(`end`), "\r\nMPS-Cat#"},
		{regexp.MustCompile(`show running-config \| include snmp-server community`), "\r\nsnmp-server community snmp_test RO\r\nMPS-Cat#"},
		{regexp.MustCompile(`write memory`), "\r\nBuilding configuration...\r\n[OK]\r\nMPS-Cat#"},
	}
	s := newScriptedSession("\r\nMPS-Cat>", steps)
	ctx := context.Background()
	s.Collect(ctx, 150*time.Millisecond, 1*time.Second)

	rep, err := cisco{}.Apply(ctx, s, Params{Community: "snmp_test", User: "admin", Password: "secret"})
	if err != nil {
		t.Fatalf("apply error: %v", err)
	}
	if !rep.Applied || !rep.Saved || !rep.Verified {
		t.Fatalf("expected applied+saved+verified, got %+v", rep)
	}
}

func TestSingleCommunity(t *testing.T) {
	if !(zyxel{}).SingleCommunity() {
		t.Error("zyxel must report SingleCommunity() == true")
	}
	for _, d := range []Driver{huawei{}, arubacx{}, arubawc{}, ruckus{}, cisco{}} {
		if d.SingleCommunity() {
			t.Errorf("%s must report SingleCommunity() == false", d.Name())
		}
	}
}

func TestFingerprints(t *testing.T) {
	cases := []struct {
		text   string
		vendor string
	}{
		{"<sw> Huawei Versatile Routing Platform VRP", "huawei"},
		{"ArubaOS-CX Virtual.10.08", "aruba-cx"},
		{"Image stamp: ProCurve WC.16.10", "aruba-wc"},
		{"Ruckus ICX7150-48 IronWare 08.0.95", "ruckus"},
		{"Copyright (c) 1994 - 2018 Zyxel Communications Corp.", "zyxel"},
		{"Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M)", "cisco"},
	}
	for _, c := range cases {
		got := best(c.text)
		if got != c.vendor {
			t.Errorf("fingerprint(%q) = %q, want %q", c.text, got, c.vendor)
		}
	}
}

// best is a tiny test helper mirroring detection's max-score selection.
func best(text string) string {
	var name string
	score := 0.0
	for _, d := range All() {
		s, _ := d.Fingerprint(text)
		if s > score {
			score, name = s, d.Name()
		}
	}
	return name
}
