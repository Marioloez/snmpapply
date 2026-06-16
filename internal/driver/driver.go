// Package driver defines the per-vendor strategy (a port in hexagonal terms):
// each network OS implements Driver to fingerprint itself and apply SNMP config
// over an interactive Session. The runner routes each device to its driver, so
// a mixed-vendor inventory "just works" via polymorphism, not a pile of ifs.
package driver

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Params carries everything a driver needs to configure a device.
type Params struct {
	Community string // SNMP read community to apply
	User      string // SSH user actually used (some CLIs re-prompt it on enable)
	Password  string // SSH password (reused for enable/privileged auth)
}

// Report summarizes what a driver did to a device.
type Report struct {
	Vendor   string
	Applied  bool
	Saved    bool
	Verified bool
	Detail   string
}

// Session is the interactive expect interface a driver depends on. It is
// satisfied by *transport.Session / *transport.Conn, and by fakes in tests.
type Session interface {
	Expect(ctx context.Context, pats ...*regexp.Regexp) (idx int, before string, err error)
	Collect(ctx context.Context, quiet, max time.Duration) string
	Send(s string) error
	Sendline(s string) error
	Transcript() string
}

// Driver is the vendor strategy.
type Driver interface {
	// Name is the canonical vendor identifier.
	Name() string
	// SingleCommunity reports whether this vendor stores only ONE read
	// community, so applying REPLACES the existing one (destructive) instead
	// of adding alongside it. Such vendors are skipped by default.
	SingleCommunity() bool
	// Fingerprint scores [0,1] how strongly `text` (login banner and/or
	// `show version` output) indicates this vendor. decisive=true means the
	// match is conclusive and no probe command is needed.
	Fingerprint(text string) (score float64, decisive bool)
	// Apply runs configure + save + verify. The session must already be at a
	// usable prompt (banner consumed by the caller/detector).
	Apply(ctx context.Context, s Session, p Params) (Report, error)
	// SNMPConfig reads the device's current SNMP-related configuration with a
	// vendor-specific show command, for backup BEFORE applying. Read-only. The
	// session must be at a usable prompt; p supplies the credentials some CLIs
	// need to reach a mode where the config is visible (e.g. Ruckus enable).
	SNMPConfig(ctx context.Context, s Session, p Params) (string, error)
}

// ansiRe strips terminal escape sequences some CLIs (notably ZyNOS) interleave.
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[a-zA-Z]|\x1b[78]`)

// captureSNMP turns a raw show-command capture into a stored backup: it drops
// the echoed command line and ANSI noise and trims surrounding blank lines.
func captureSNMP(cmd, out string) string {
	out = ansiRe.ReplaceAllString(out, "")
	var kept []string
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimRight(ln, " \r\t")
		if strings.TrimSpace(ln) == strings.TrimSpace(cmd) { // echoed command
			continue
		}
		kept = append(kept, ln)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

// moreRe matches the common pager prompts across these vendors.
var moreRe = regexp.MustCompile(`(?i)(--+\s*more\s*--+|----\s*more|<--+\s*more\s*--+>|Press any key)`)

// waitPrompt waits for `prompt`, transparently draining any pager prompts by
// sending a space until the real prompt appears. Returns the text before the
// prompt for optional verification.
func waitPrompt(ctx context.Context, s Session, prompt *regexp.Regexp) (string, error) {
	for {
		idx, before, err := s.Expect(ctx, prompt, moreRe)
		if err != nil {
			return before, err
		}
		if idx == 1 { // pager
			_ = s.Send(" ")
			continue
		}
		return before, nil
	}
}
