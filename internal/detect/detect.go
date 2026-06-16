// Package detect performs hybrid vendor identification over SSH. SNMP is NOT
// usable here (we are about to configure it), so detection relies entirely on
// the SSH login banner, the prompt style, and a `show version` probe.
package detect

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Marioloez/snmpapply/internal/driver"
)

var moreRe = regexp.MustCompile(`(?i)(--+\s*more\s*--+|----\s*more|<--+\s*more\s*--+>|Press any key)`)

// promptish matches a buffer that ends in a CLI prompt: '#', '>' or ']'
// (Huawei user/system views, Aruba/Ruckus exec/privileged), optional trailing
// space and an optional ANSI escape (ZyNOS spams ESC-7 / ESC-8 cursor
// save/restore after its prompt). Anchored to end so body lines don't match.
var promptish = regexp.MustCompile(`[#>\]]\s*(\x1b[78])?\s*$`)

// Prime drives the session to a usable prompt and returns the banner seen
// (used for fingerprinting). It clears ProCurve's "Press any key" gate and is
// patient with slow CLIs: ArubaOS-CX can take several seconds to initialize its
// shell and stays silent until then, so we poll up to a generous deadline,
// nudging with a carriage return while the device is quiet (harmless to
// vendors already at a prompt) — the same trick netmiko/scrapli use.
func Prime(ctx context.Context, s driver.Session) string {
	var b strings.Builder
	deadline := time.Now().Add(15 * time.Second)
	nudges := 0
	for time.Now().Before(deadline) {
		chunk := s.Collect(ctx, 700*time.Millisecond, 3*time.Second)
		b.WriteString(chunk)
		text := b.String()

		if strings.Contains(text, "Press any key") {
			_ = s.Send(" ")
			continue
		}
		if promptish.MatchString(text) {
			break
		}
		if strings.TrimSpace(chunk) == "" && nudges < 4 {
			_ = s.Send("\r") // wake a silent / slow-starting CLI
			nudges++
		}
	}
	return b.String()
}

// Identify returns the driver matching the device. It first tries to decide
// from the banner alone; if ambiguous, it sends `show version` and re-scores.
func Identify(ctx context.Context, s driver.Session, drivers []driver.Driver) (driver.Driver, string, error) {
	banner := Prime(ctx, s)
	if d := best(drivers, banner, true); d != nil {
		return d, banner, nil
	}

	// Ambiguous (plain #/> prompt): probe. `show version` works on every
	// non-Huawei vendor here, and Huawei is already decisive by its prompt.
	_ = s.Sendline("show version")
	probe := collectPager(ctx, s)
	text := banner + "\n" + probe
	if d := best(drivers, text, false); d != nil {
		return d, text, nil
	}
	return nil, text, fmt.Errorf("no se pudo identificar el vendor (el banner/sonda no coincidió con ningún driver)")
}

// best returns the highest-scoring driver above threshold. When requireDecisive
// is set, only a conclusive match wins (used for the banner-only first pass).
func best(drivers []driver.Driver, text string, requireDecisive bool) driver.Driver {
	var bd driver.Driver
	bestScore := 0.0
	bestDecisive := false
	for _, d := range drivers {
		score, decisive := d.Fingerprint(text)
		if score > bestScore {
			bestScore, bd, bestDecisive = score, d, decisive
		}
	}
	if bd == nil || bestScore < 0.5 {
		return nil
	}
	if requireDecisive && !bestDecisive {
		return nil
	}
	return bd
}

func collectPager(ctx context.Context, s driver.Session) string {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		chunk := s.Collect(ctx, 600*time.Millisecond, 5*time.Second)
		b.WriteString(chunk)
		// Look at a generous tail: the Ruckus pager prompt is ~62 chars
		// ("--More--, next page: Space, next line: Return key, quit: Control-c"),
		// so a 60-char window truncates the "--More--" marker and the device is
		// left mid-pager — breaking the very next interactive command.
		t := chunk
		if len(t) > 256 {
			t = t[len(t)-256:]
		}
		if moreRe.MatchString(t) {
			_ = s.Send(" ")
			continue
		}
		break
	}
	return b.String()
}
