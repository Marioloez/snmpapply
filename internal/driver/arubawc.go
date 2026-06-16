package driver

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// arubawc drives ArubaOS (ProCurve/WC firmware) switches: 2930F, 2930M, 2540,
// 3810M. Prompt is hostname# / hostname>. A "Press any key to continue" MOTD
// gate before the prompt is handled by the detector (Prime), not here.
type arubawc struct{}

var (
	wcPrompt = regexp.MustCompile(`[\w.\-]+[#>]\s*$`)
	wcFw     = regexp.MustCompile(`(?i)\b(WC|KB|YA|YC|MB|RA|KA|KB)\.\d{2}\.\d{2}`)
)

func (arubawc) Name() string          { return "aruba-wc" }
func (arubawc) SingleCommunity() bool { return false }

func (arubawc) Fingerprint(text string) (float64, bool) {
	lt := strings.ToLower(text)
	if strings.Contains(lt, "procurve") {
		return 0.9, true
	}
	if wcFw.MatchString(text) {
		return 0.75, false
	}
	if strings.Contains(text, "Press any key") {
		return 0.6, false
	}
	return 0, false
}

func (arubawc) Apply(ctx context.Context, s Session, p Params) (Report, error) {
	r := Report{Vendor: "aruba-wc"}

	steps := []string{
		"no page",
		"configure",
		fmt.Sprintf(`snmp-server community "%s" operator`, p.Community),
		"exit",
	}
	for _, cmd := range steps {
		_ = s.Sendline(cmd)
		if _, err := waitPrompt(ctx, s, wcPrompt); err != nil {
			return r, err
		}
	}
	r.Applied = true

	_ = s.Sendline("write memory")
	if _, err := waitPrompt(ctx, s, wcPrompt); err != nil {
		return r, err
	}
	r.Saved = true

	_ = s.Sendline("show snmp-server")
	if out, err := waitPrompt(ctx, s, wcPrompt); err == nil {
		r.Verified = strings.Contains(out, p.Community)
	}
	r.Detail = "snmp v2c read community applied and saved"
	return r, nil
}
