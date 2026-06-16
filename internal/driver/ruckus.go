package driver

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// ruckus drives Ruckus ICX / IronWare (ex-Brocade/Foundry) switches.
// Flow: exec '>' -> enable (may re-prompt User Name/Password) -> privileged '#'.
type ruckus struct{}

var (
	rkPriv     = regexp.MustCompile(`#\s*$`)
	rkUserName = regexp.MustCompile(`(?i)user name:\s*$`)
	rkPass     = regexp.MustCompile(`(?i)password:\s*$`)
)

func (ruckus) Name() string          { return "ruckus" }
func (ruckus) SingleCommunity() bool { return false }

func (ruckus) Fingerprint(text string) (float64, bool) {
	lt := strings.ToLower(text)
	for _, m := range []string{"ruckus", "icx", "ironware", "brocade", "foundry"} {
		if strings.Contains(lt, m) {
			return 0.95, true
		}
	}
	return 0, false
}

func (ruckus) Apply(ctx context.Context, s Session, p Params) (Report, error) {
	r := Report{Vendor: "ruckus"}

	// Enter privileged (enable) mode.
	if err := ruckusEnable(ctx, s, p); err != nil {
		return r, err
	}

	_ = s.Sendline("skip-page-display")
	if _, err := waitPrompt(ctx, s, rkPriv); err != nil {
		return r, err
	}
	_ = s.Sendline("configure terminal")
	if _, err := waitPrompt(ctx, s, rkPriv); err != nil {
		return r, err
	}
	_ = s.Sendline(fmt.Sprintf("snmp-server community %s ro", p.Community))
	if _, err := waitPrompt(ctx, s, rkPriv); err != nil {
		return r, err
	}
	_ = s.Sendline("exit")
	if _, err := waitPrompt(ctx, s, rkPriv); err != nil {
		return r, err
	}
	r.Applied = true

	_ = s.Sendline("show snmp server")
	if out, err := waitPrompt(ctx, s, rkPriv); err == nil {
		r.Verified = strings.Contains(out, p.Community)
	}

	_ = s.Sendline("write memory")
	if _, err := waitPrompt(ctx, s, rkPriv); err != nil {
		return r, err
	}
	r.Saved = true
	r.Detail = "snmp v2c read community applied and saved"
	return r, nil
}

// ruckusEnable drives the enable flow, which may re-prompt for user name and/or
// password before landing at the privileged '#' prompt.
func ruckusEnable(ctx context.Context, s Session, p Params) error {
	_ = s.Sendline("enable")
	idx, _, err := s.Expect(ctx, rkUserName, rkPass, rkPriv)
	if err != nil {
		return err
	}
	switch idx {
	case 0: // asks for User Name then Password
		_ = s.Sendline(p.User)
		if _, _, err := s.Expect(ctx, rkPass); err != nil {
			return err
		}
		_ = s.Sendline(p.Password)
		if _, err := waitPrompt(ctx, s, rkPriv); err != nil {
			return err
		}
	case 1: // asks for Password only
		_ = s.Sendline(p.Password)
		if _, err := waitPrompt(ctx, s, rkPriv); err != nil {
			return err
		}
	case 2: // already privileged
	}
	return nil
}

func (ruckus) SNMPConfig(ctx context.Context, s Session, p Params) (string, error) {
	if err := ruckusEnable(ctx, s, p); err != nil {
		return "", err
	}
	_ = s.Sendline("skip-page-display")
	if _, err := waitPrompt(ctx, s, rkPriv); err != nil {
		return "", err
	}
	const cmd = "show running-config | include snmp-server"
	_ = s.Sendline(cmd)
	out, err := waitPrompt(ctx, s, rkPriv)
	if err != nil {
		return "", err
	}
	return captureSNMP(cmd, out), nil
}
