// Package runner orchestrates the batch: a bounded worker pool dials each
// device, resolves its driver (explicit or autodetected), and applies SNMP.
package runner

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Marioloez/snmpapply/internal/config"
	"github.com/Marioloez/snmpapply/internal/detect"
	"github.com/Marioloez/snmpapply/internal/driver"
	"github.com/Marioloez/snmpapply/internal/snmpcheck"
	"github.com/Marioloez/snmpapply/internal/transport"
)

// Options configures a batch run.
type Options struct {
	Concurrency   int
	DeviceTimeout time.Duration
	Dialer        transport.Dialer
	DryRun        bool
	Verbose       bool
	Out           io.Writer
	// ForceOverwrite applies to single-community vendors (Zyxel) too, which
	// otherwise are skipped because applying overwrites their one community.
	ForceOverwrite bool
	// OnResult, if set, is called once per device the moment it finishes
	// (serialized across goroutines) so callers can stream live progress.
	OnResult func(done, total int, r Result)
}

// ScanResult is the SNMP pre-scan outcome for one device (phase 1).
type ScanResult struct {
	Target  config.Target
	Present bool // already answers SNMP with the target community
}

// Scan probes every target over SNMP concurrently and reports which already
// answer to their target community. This is phase 1: it decides which devices
// still need configuring, so phase 2 (Run) only touches those.
func Scan(ctx context.Context, targets []config.Target, snmpTimeout time.Duration, concurrency int) []ScanResult {
	if concurrency < 1 {
		concurrency = 1
	}
	out := make([]ScanResult, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			t := targets[i]
			present := t.Community != "" && snmpcheck.Configured(t.Host, t.Community, snmpTimeout)
			out[i] = ScanResult{Target: t, Present: present}
		}(i)
	}
	wg.Wait()
	return out
}

// Result is the outcome for one device.
type Result struct {
	Target    config.Target
	Vendor    string
	Report    driver.Report
	Err       error
	Skipped   bool
	Backup    string // device's current SNMP config, captured during the probe
	BackupErr error  // non-nil if the backup read failed
	Elapsed   time.Duration
}

const skipDetail = "omitido: vendor de comunidad única — configurar sobreescribiría la comunidad existente (usa -force-zyxel para forzar)"

// Run processes targets concurrently, preserving input order in the results.
func Run(ctx context.Context, targets []config.Target, opts Options) []Result {
	if opts.Concurrency < 1 {
		opts.Concurrency = 1
	}
	results := make([]Result, len(targets))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	total := len(targets)

	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := runOne(ctx, targets[i], opts)
			results[i] = r
			if opts.OnResult != nil {
				mu.Lock()
				done++
				opts.OnResult(done, total, r)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	return results
}

func runOne(ctx context.Context, t config.Target, opts Options) (res Result) {
	res = Result{Target: t}
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }() // named return so this sticks

	dctx, cancel := context.WithTimeout(ctx, opts.DeviceTimeout)
	defer cancel()

	var echo io.Writer
	if opts.Verbose && opts.Out != nil {
		echo = &prefixWriter{w: opts.Out, prefix: t.Host + " | "}
	}

	// Early skip: an explicitly-declared single-community vendor needs no
	// connection at all — applying would overwrite its one community.
	if t.Vendor != "" && !opts.DryRun && !opts.ForceOverwrite {
		if d, ok := driver.ByName(t.Vendor); ok && d.SingleCommunity() {
			res.Vendor = d.Name()
			res.Skipped = true
			res.Report = driver.Report{Vendor: d.Name(), Detail: skipDetail}
			return res
		}
	}

	// Dial, retrying a couple times on transient drops — rate-limited or busy
	// gear sometimes resets the handshake or PTY request with EOF. Fall back to
	// the generic "admin" user only when SSH_USER isn't set.
	var conn *transport.Conn
	var err error
	var usedUser string
	for attempt := 0; attempt < 3; attempt++ {
		for _, u := range userCandidates(t.User) {
			conn, err = opts.Dialer.Open(dctx, t.Host, t.Port, u, t.Password, echo)
			if err == nil {
				usedUser = u
				break
			}
			if !isAuthErr(err) {
				break // network/handshake error: more users won't help
			}
		}
		if err == nil || !isTransient(err) {
			break
		}
		select { // transient drop — brief backoff, then retry the connection
		case <-time.After(time.Duration(attempt+1) * time.Second):
		case <-dctx.Done():
		}
	}
	if err != nil {
		res.Err = err
		return res
	}
	defer conn.Close()

	// Resolve driver: explicit vendor wins, else autodetect.
	var drv driver.Driver
	if t.Vendor != "" {
		d, ok := driver.ByName(t.Vendor)
		if !ok {
			res.Err = fmt.Errorf("vendor desconocido %q", t.Vendor)
			return res
		}
		drv = d
		detect.Prime(dctx, conn) // consume banner so Apply starts at a prompt
	} else {
		d, _, derr := detect.Identify(dctx, conn, driver.All())
		if derr != nil {
			res.Err = derr
			return res
		}
		drv = d
	}
	res.Vendor = drv.Name()

	// Skip single-community vendors discovered via autodetect (Zyxel) unless
	// forced — applying would overwrite their one existing community.
	if drv.SingleCommunity() && !opts.DryRun && !opts.ForceOverwrite {
		res.Skipped = true
		res.Report = driver.Report{Vendor: drv.Name(), Detail: skipDetail}
		return res
	}

	if opts.DryRun {
		// Phase 2 doubles as the backup pass: capture the device's existing SNMP
		// config before phase 3 can change it.
		res.Backup, res.BackupErr = drv.SNMPConfig(dctx, conn, driver.Params{
			Community: t.Community, User: usedUser, Password: t.Password,
		})
		detail := "dry-run: vendor detected, no changes applied"
		if drv.SingleCommunity() && !opts.ForceOverwrite {
			detail = "dry-run: " + drv.Name() + " detected — single-community, skipped on apply (use -force-zyxel)"
		}
		res.Report = driver.Report{Vendor: drv.Name(), Detail: detail}
		return res
	}

	rep, aerr := drv.Apply(dctx, conn, driver.Params{
		Community: t.Community,
		User:      usedUser,
		Password:  t.Password,
	})
	res.Report = rep
	res.Err = aerr
	return res
}

func userCandidates(u string) []string {
	if strings.TrimSpace(u) == "" {
		return []string{"admin"} // generic last resort; set SSH_USER in .env
	}
	return []string{u}
}

func isAuthErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unable to authenticate")
}

// isTransient reports whether a connection error looks like a temporary drop
// (EOF / reset) worth retrying — as opposed to a dead host (timeout/refused)
// where retrying just wastes time.
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "eof") ||
		strings.Contains(s, "reset by peer") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "broken pipe")
}

// prefixWriter prefixes each line of verbose output with the device host.
type prefixWriter struct {
	w      io.Writer
	prefix string
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	if p.w == nil {
		return len(b), nil
	}
	s := strings.ReplaceAll(string(b), "\n", "\n"+p.prefix)
	_, _ = io.WriteString(p.w, s)
	return len(b), nil
}
