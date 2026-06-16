package driver

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// huawei drives Huawei VRP switches (S5731 et al).
// User view prompt: <hostname>   System view prompt: [hostname]
type huawei struct{}

var (
	hwUser   = regexp.MustCompile(`<[^>\n]+>\s*$`)
	hwSys    = regexp.MustCompile(`\[[^\]\n]+\]\s*$`)
	hwYesNo  = regexp.MustCompile(`(?i)\[y/n\]|\(y/n\)|yes/no`)
	hwPrompt = regexp.MustCompile(`(?m)[<\[][^>\]\n]+[>\]]\s*$`)
)

func (huawei) Name() string          { return "huawei" }
func (huawei) SingleCommunity() bool { return false }

func (huawei) Fingerprint(text string) (float64, bool) {
	lt := strings.ToLower(text)
	if strings.Contains(lt, "huawei") || strings.Contains(lt, "vrp") {
		return 0.95, true
	}
	if hwPrompt.MatchString(text) {
		return 0.7, false
	}
	return 0, false
}

func (huawei) Apply(ctx context.Context, s Session, p Params) (Report, error) {
	r := Report{Vendor: "huawei"}

	_ = s.Sendline("screen-length 0 temporary")
	if _, err := waitPrompt(ctx, s, hwUser); err != nil {
		return r, err
	}
	_ = s.Sendline("system-view")
	if _, err := waitPrompt(ctx, s, hwSys); err != nil {
		return r, err
	}
	_ = s.Sendline("snmp-agent sys-info version v2c")
	if _, err := waitPrompt(ctx, s, hwSys); err != nil {
		return r, err
	}
	_ = s.Sendline(fmt.Sprintf("snmp-agent community read cipher %s", p.Community))
	if _, err := waitPrompt(ctx, s, hwSys); err != nil {
		return r, err
	}
	r.Applied = true

	_ = s.Sendline("display snmp-agent community read")
	if out, err := waitPrompt(ctx, s, hwSys); err == nil {
		lo := strings.ToLower(out)
		r.Verified = strings.Contains(lo, "community") || strings.Contains(lo, "read")
	}

	_ = s.Sendline("quit")
	if _, err := waitPrompt(ctx, s, hwUser); err != nil {
		return r, err
	}
	_ = s.Sendline("save")
	idx, _, err := s.Expect(ctx, hwYesNo, hwUser)
	if err != nil {
		return r, err
	}
	if idx == 0 { // confirmation prompt
		_ = s.Sendline("y")
		if _, err := waitPrompt(ctx, s, hwUser); err != nil {
			return r, err
		}
	}
	r.Saved = true
	r.Detail = "snmp v2c read community applied and saved"
	return r, nil
}

func (huawei) SNMPConfig(ctx context.Context, s Session, _ Params) (string, error) {
	_ = s.Sendline("screen-length 0 temporary")
	if _, err := waitPrompt(ctx, s, hwUser); err != nil {
		return "", err
	}
	const cmd = "display current-configuration | include snmp-agent"
	_ = s.Sendline(cmd)
	out, err := waitPrompt(ctx, s, hwUser)
	if err != nil {
		return "", err
	}
	return captureSNMP(cmd, out), nil
}
