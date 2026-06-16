package driver

import (
	"context"
	"regexp"
	"strings"
)

// zyxel drives Zyxel ZyNOS switches (GS/XGS family, e.g. SW-LOBBY-MDF).
// Cisco-like CLI; the management user lands directly in privileged EXEC ('#').
// The read community is the SNMP "GetRequest" community.
//
// Quirks captured from a real device (ZyNOS V4.50):
//   - SNMP is v2c by default — no version command needed.
//   - The prompt is followed by an ANSI ESC-7 (save-cursor) sequence, and the
//     device application-echoes commands even with PTY ECHO off.
//   - `show` and `write` are EXEC-only; the community is set in config mode.
type zyxel struct{}

// zyPrompt matches both EXEC ('#') and config ('(config)#') prompts, tolerating
// the trailing space and ZyNOS's ESC-7/ESC-8 cursor noise.
var zyPrompt = regexp.MustCompile(`[#>]\s*(\x1b[78])?\s*$`)

func (zyxel) Name() string { return "zyxel" }

// SingleCommunity is true: ZyNOS has one get-community field, so applying
// overwrites the existing community instead of adding alongside it.
func (zyxel) SingleCommunity() bool { return true }

func (zyxel) Fingerprint(text string) (float64, bool) {
	lt := strings.ToLower(text)
	if strings.Contains(lt, "zyxel") || strings.Contains(lt, "zynos") {
		return 0.95, true
	}
	return 0, false
}

func (zyxel) Apply(ctx context.Context, s Session, p Params) (Report, error) {
	r := Report{Vendor: "zyxel"}

	_ = s.Sendline("configure")
	if _, err := waitPrompt(ctx, s, zyPrompt); err != nil {
		return r, err
	}
	_ = s.Sendline("snmp-server get-community " + p.Community)
	if _, err := waitPrompt(ctx, s, zyPrompt); err != nil {
		return r, err
	}
	r.Applied = true

	_ = s.Sendline("exit") // back to EXEC (write/show are EXEC-only)
	if _, err := waitPrompt(ctx, s, zyPrompt); err != nil {
		return r, err
	}
	_ = s.Sendline("write")
	if _, err := waitPrompt(ctx, s, zyPrompt); err != nil {
		return r, err
	}
	r.Saved = true

	_ = s.Sendline("show snmp-server")
	if out, err := waitPrompt(ctx, s, zyPrompt); err == nil {
		r.Verified = strings.Contains(out, p.Community) // "Get  Community  : <c>"
	}
	r.Detail = "snmp v2c get-community applied and saved"
	return r, nil
}

func (zyxel) SNMPConfig(ctx context.Context, s Session, _ Params) (string, error) {
	const cmd = "show snmp-server"
	_ = s.Sendline(cmd)
	out, err := waitPrompt(ctx, s, zyPrompt)
	if err != nil {
		return "", err
	}
	return captureSNMP(cmd, out), nil
}
