package driver

import (
	"context"
	"regexp"
	"strings"
)

// ciscosb drives Cisco Small Business switches (Sx250/350/550, SG/SF series).
// A different OS from IOS/Catalyst: it presents an in-band "User Name:" login
// (handled by the detector), disables paging with `terminal datadump`, ships
// with the SNMP agent OFF (so `snmp-server server` must enable it), and saves
// with a Y/N-confirmed copy. SNMP is multi-community and additive.
//
// Its `show version` prints only the image paths (no vendor string), so it is
// fingerprinted by that layout; `show system` (SysObjectID 1.3.6.1.4.1.9.*)
// confirms Cisco.
type ciscosb struct{}

var (
	sbPrompt = regexp.MustCompile(`[\w.\-]+(\([\w.\- ]+\))?#\s*$`)
	sbYesNo  = regexp.MustCompile(`(?i)\(y/n\)`)
)

func (ciscosb) Name() string          { return "cisco-sb" }
func (ciscosb) SingleCommunity() bool { return false }

func (ciscosb) Fingerprint(text string) (float64, bool) {
	lt := strings.ToLower(text)
	if strings.Contains(lt, "flash://system/images") {
		return 0.95, true
	}
	if strings.Contains(lt, "active-image") && strings.Contains(lt, "inactive-image") {
		return 0.9, true
	}
	return 0, false
}

func (ciscosb) Apply(ctx context.Context, s Session, p Params) (Report, error) {
	r := Report{Vendor: "cisco-sb"}

	_ = s.Sendline("terminal datadump") // disable paging
	if _, err := waitPrompt(ctx, s, sbPrompt); err != nil {
		return r, err
	}
	steps := []string{
		"configure terminal",
		"snmp-server server", // the SNMP agent is off by default on these
		"snmp-server community " + p.Community + " ro",
		"end",
	}
	for _, cmd := range steps {
		_ = s.Sendline(cmd)
		if _, err := waitPrompt(ctx, s, sbPrompt); err != nil {
			return r, err
		}
	}
	r.Applied = true

	_ = s.Sendline("show snmp")
	if out, err := waitPrompt(ctx, s, sbPrompt); err == nil {
		r.Verified = strings.Contains(out, p.Community)
	}

	// Save: `copy running-config startup-config` asks Y/N to overwrite.
	_ = s.Sendline("copy running-config startup-config")
	idx, _, err := s.Expect(ctx, sbYesNo, sbPrompt)
	if err != nil {
		return r, err
	}
	if idx == 0 {
		_ = s.Sendline("Y")
		if _, err := waitPrompt(ctx, s, sbPrompt); err != nil {
			return r, err
		}
	}
	r.Saved = true
	r.Detail = "snmp v2c read community applied, agent enabled, saved"
	return r, nil
}

func (ciscosb) SNMPConfig(ctx context.Context, s Session, _ Params) (string, error) {
	_ = s.Sendline("terminal datadump")
	if _, err := waitPrompt(ctx, s, sbPrompt); err != nil {
		return "", err
	}
	const cmd = "show snmp"
	_ = s.Sendline(cmd)
	out, err := waitPrompt(ctx, s, sbPrompt)
	if err != nil {
		return "", err
	}
	return captureSNMP(cmd, out), nil
}
