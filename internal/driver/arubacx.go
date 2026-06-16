package driver

import (
	"context"
	"regexp"
	"strings"
)

// arubacx drives ArubaOS-CX switches (6000/6100/6200/6300 ...).
// The vrf default off/on toggle works around AOS-CX builds where a fresh
// `snmp-server vrf default` leaves the agent half-initialized (listening but
// silently dropping requests).
type arubacx struct{}

// Matches switch#, switch>, and config contexts like switch(config)#.
var cxPrompt = regexp.MustCompile(`[\w.\-]+(\([\w.\- ]+\))?[#>]\s*$`)

func (arubacx) Name() string          { return "aruba-cx" }
func (arubacx) SingleCommunity() bool { return false }

func (arubacx) Fingerprint(text string) (float64, bool) {
	lt := strings.ToLower(text)
	if strings.Contains(lt, "arubaos-cx") || strings.Contains(lt, "aos-cx") {
		return 0.95, true
	}
	return 0, false
}

func (arubacx) Apply(ctx context.Context, s Session, p Params) (Report, error) {
	r := Report{Vendor: "aruba-cx"}

	steps := []string{
		"no page",
		"configure",
		"snmp-server community " + p.Community,
		"no snmp-server vrf default",
		"snmp-server vrf default",
		"exit",
	}
	for _, cmd := range steps {
		_ = s.Sendline(cmd)
		if _, err := waitPrompt(ctx, s, cxPrompt); err != nil {
			return r, err
		}
	}
	r.Applied = true

	_ = s.Sendline("copy running-config startup-config")
	if _, err := waitPrompt(ctx, s, cxPrompt); err != nil {
		return r, err
	}
	r.Saved = true

	_ = s.Sendline("show running-config | include snmp")
	if out, err := waitPrompt(ctx, s, cxPrompt); err == nil {
		r.Verified = strings.Contains(out, p.Community)
	}
	r.Detail = "snmp v2c read community applied and saved"
	return r, nil
}

func (arubacx) SNMPConfig(ctx context.Context, s Session, _ Params) (string, error) {
	_ = s.Sendline("no page")
	if _, err := waitPrompt(ctx, s, cxPrompt); err != nil {
		return "", err
	}
	const cmd = "show running-config | include snmp"
	_ = s.Sendline(cmd)
	out, err := waitPrompt(ctx, s, cxPrompt)
	if err != nil {
		return "", err
	}
	return captureSNMP(cmd, out), nil
}
