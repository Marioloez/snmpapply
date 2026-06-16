package driver

import (
	"context"
	"regexp"
	"strings"
)

// cisco drives Cisco IOS / IOS-XE switches (Catalyst family). Cisco-standard
// CLI: user EXEC '>', privileged EXEC '#' (via enable), config '(config)#'.
// SNMP is multi-community and additive — `snmp-server community <c> RO` adds the
// community alongside any existing ones, so applying is non-destructive.
//
// enable may ask for an enable password distinct from the SSH login; we try the
// SSH password, which works when they match or when no enable secret is set.
type cisco struct{}

var (
	// Privileged / config prompt: host#, host(config)#, host(config-if)#.
	ciscoPriv = regexp.MustCompile(`[\w.\-]+(\([\w.\- ]+\))?#\s*$`)
	ciscoPass = regexp.MustCompile(`(?i)password:\s*$`)
)

func (cisco) Name() string          { return "cisco" }
func (cisco) SingleCommunity() bool { return false }

func (cisco) Fingerprint(text string) (float64, bool) {
	lt := strings.ToLower(text)
	if strings.Contains(lt, "cisco ios") || strings.Contains(lt, "cisco internetwork") {
		return 0.95, true
	}
	if strings.Contains(lt, "cisco") {
		return 0.9, true
	}
	return 0, false
}

// ciscoEnable reaches privileged EXEC. At a user-EXEC '>' prompt it answers the
// enable password; at an already-privileged '#' prompt enable is a no-op.
func ciscoEnable(ctx context.Context, s Session, p Params) error {
	_ = s.Sendline("enable")
	idx, _, err := s.Expect(ctx, ciscoPass, ciscoPriv)
	if err != nil {
		return err
	}
	if idx == 0 { // asked for an enable password
		_ = s.Sendline(p.Password)
		if _, err := waitPrompt(ctx, s, ciscoPriv); err != nil {
			return err
		}
	}
	return nil
}

func (cisco) Apply(ctx context.Context, s Session, p Params) (Report, error) {
	r := Report{Vendor: "cisco"}

	if err := ciscoEnable(ctx, s, p); err != nil {
		return r, err
	}
	steps := []string{
		"terminal length 0",
		"configure terminal",
		"snmp-server community " + p.Community + " RO",
		"end",
	}
	for _, cmd := range steps {
		_ = s.Sendline(cmd)
		if _, err := waitPrompt(ctx, s, ciscoPriv); err != nil {
			return r, err
		}
	}
	r.Applied = true

	_ = s.Sendline("show running-config | include snmp-server community")
	if out, err := waitPrompt(ctx, s, ciscoPriv); err == nil {
		r.Verified = strings.Contains(out, p.Community)
	}

	_ = s.Sendline("write memory")
	if _, err := waitPrompt(ctx, s, ciscoPriv); err != nil {
		return r, err
	}
	r.Saved = true
	r.Detail = "snmp v2c read community applied and saved"
	return r, nil
}

func (cisco) SNMPConfig(ctx context.Context, s Session, p Params) (string, error) {
	if err := ciscoEnable(ctx, s, p); err != nil {
		return "", err
	}
	_ = s.Sendline("terminal length 0")
	if _, err := waitPrompt(ctx, s, ciscoPriv); err != nil {
		return "", err
	}
	const cmd = "show running-config | include snmp-server"
	_ = s.Sendline(cmd)
	out, err := waitPrompt(ctx, s, ciscoPriv)
	if err != nil {
		return "", err
	}
	return captureSNMP(cmd, out), nil
}
