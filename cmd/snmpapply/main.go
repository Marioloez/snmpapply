// Command snmpapply applies an SNMPv2c read community to a mixed-vendor list of
// switches. Devices come from inventory.json; credentials from .env (or the
// real environment). Vendor is taken from JSON or autodetected over SSH.
//
// It runs in two phases: (1) an SNMP scan of the whole inventory to see which
// devices already have the community, and (2) configuring only the ones that
// don't. User-facing output is in Spanish.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Marioloez/snmpapply/internal/config"
	"github.com/Marioloez/snmpapply/internal/runner"
	"github.com/Marioloez/snmpapply/internal/transport"
)

// version is stamped at build time via -ldflags "-X main.version=...".
var version = "dev"

const (
	cGreen  = "\x1b[32m"
	cRed    = "\x1b[31m"
	cYellow = "\x1b[33m"
	cDim    = "\x1b[2m"
	cBold   = "\x1b[1m"
	cReset  = "\x1b[0m"
)

func main() {
	inventoryPath := flag.String("inventory", besideBinary("inventory.json"), "ruta al JSON de inventario (por defecto: junto al binario)")
	envPath := flag.String("env", besideBinary(".env"), "ruta al archivo .env (por defecto: junto al binario)")
	concurrency := flag.Int("concurrency", 10, "máximo de dispositivos en paralelo")
	deviceTimeout := flag.Duration("timeout", 120*time.Second, "timeout total por dispositivo")
	connectTimeout := flag.Duration("connect-timeout", 8*time.Second, "timeout de conexión SSH (los equipos muertos fallan así de rápido)")
	ioTimeout := flag.Duration("io-timeout", 60*time.Second, "timeout de lectura por paso (ZyNOS `write memory` tarda ~40s en escribir flash)")
	dryRun := flag.Bool("dry-run", false, "escanear y probar SSH/vendor sin aplicar cambios")
	vendor := flag.String("vendor", "", "forzar este vendor para todos (sin autodetección)")
	only := flag.String("only", "", "filtro de hosts separados por coma")
	verbose := flag.Bool("v", false, "mostrar la sesión SSH en vivo")
	forceZyxel := flag.Bool("force-zyxel", false, "configurar Zyxel también (SOBREESCRIBE su única comunidad SNMP)")
	forceNoBackup := flag.Bool("force-no-backup", false, "configurar aunque falle el respaldo de la config SNMP (omite el fail-safe)")
	noPrecheck := flag.Bool("no-precheck", false, "saltear el escaneo SNMP (fase 1) y configurar todos")
	snmpTimeout := flag.Duration("snmp-timeout", 2*time.Second, "timeout del escaneo SNMP por dispositivo")
	assumeYes := flag.Bool("yes", false, "no preguntar; configurar los pendientes directamente")
	showVersion := flag.Bool("version", false, "imprimir la versión y salir")
	flag.Parse()

	if *showVersion {
		fmt.Println("snmpapply", version)
		return
	}

	get := config.Getenv(config.LoadDotenv(*envPath))
	inv, err := config.LoadInventory(*inventoryPath)
	if err != nil {
		die(err)
	}
	targets, errs := inv.Resolve(get, !*dryRun)
	for _, e := range errs {
		fmt.Fprintln(os.Stderr, "omitido:", e)
	}
	if *vendor != "" {
		for i := range targets {
			targets[i].Vendor = *vendor
		}
	}
	if *only != "" {
		targets = filterHosts(targets, *only)
	}
	if len(targets) == 0 {
		die(fmt.Errorf("no hay dispositivos para procesar"))
	}

	color := isTTY(os.Stdout)

	// ── Fase 1 · Escaneo SNMP ────────────────────────────────────────────
	missing := targets
	present := 0
	if !*noPrecheck {
		fmt.Println(paint(color, cBold, fmt.Sprintf("Fase 1 · Escaneo SNMP — %d dispositivo(s)", len(targets))))
		scan := runner.Scan(context.Background(), targets, *snmpTimeout, *concurrency)
		var have, need []config.Target
		for _, sr := range scan {
			if sr.Present {
				have = append(have, sr.Target)
			} else {
				need = append(need, sr.Target)
			}
		}
		present, missing = len(have), need
		printScanTable(scan)
		fmt.Println(paint(color, cBold, fmt.Sprintf("%d configurados · %d pendientes", len(have), len(need))))

		if len(missing) == 0 {
			fmt.Println(paint(color, cGreen, fmt.Sprintf("\n✅ Los %d dispositivos ya tienen la comunidad — nada que hacer.", len(targets))))
			return
		}
	}

	opts := runner.Options{
		Concurrency:    *concurrency,
		DeviceTimeout:  *deviceTimeout,
		Dialer:         transport.Dialer{ConnectTimeout: *connectTimeout, IOTimeout: *ioTimeout},
		Verbose:        *verbose,
		Out:            os.Stdout,
		ForceOverwrite: *forceZyxel,
	}

	// ── Fase 2 · Acceso SSH + detección de vendor ────────────────────────
	// A single SSH connection per device validates the credentials AND detects
	// the vendor, without changing anything. Devices that don't answer SSH (bad
	// login, unreachable) are discarded here; only the survivors reach phase 3.
	if !*assumeYes && !confirm(color, fmt.Sprintf("¿Probar acceso SSH a los %d dispositivos pendientes?", len(missing))) {
		fmt.Println("Cancelado.")
		return
	}
	fmt.Println(paint(color, cBold, fmt.Sprintf("\nFase 2 · Acceso SSH + detección de vendor — %d dispositivo(s)", len(missing))))

	probeOpts := opts
	probeOpts.DryRun = true // connect + detect, never apply
	if !*verbose {
		probeOpts.OnResult = func(_, _ int, r runner.Result) { printProbe(r, color) }
	}
	probe := runner.Run(context.Background(), missing, probeOpts)

	var reachable []config.Target
	backups := map[string]backupRecord{}
	discarded, forcedNoBackup, skippedNoBackup := 0, 0, 0
	for _, r := range probe {
		if r.Err != nil {
			discarded++ // SSH/vendor failed: not reachable
			continue
		}
		t := r.Target
		t.Vendor = r.Vendor // carry the detected vendor so phase 3 skips re-detection
		switch {
		case r.BackupErr == nil && strings.TrimSpace(r.Backup) != "":
			backups[r.Target.Host] = backupRecord{Vendor: r.Vendor, SNMPConfig: r.Backup}
			reachable = append(reachable, t)
		case *forceNoBackup: // backup failed but the operator chose to proceed
			reachable = append(reachable, t)
			forcedNoBackup++
		default: // fail-safe: never change what we couldn't back up
			skippedNoBackup++
		}
	}

	// Persist the backup of the existing SNMP config before phase 3 can change it.
	if path, err := writeBackup(backups); err != nil {
		fmt.Fprintln(os.Stderr, "aviso: no se pudo escribir el respaldo:", err)
	} else if path != "" {
		fmt.Println(paint(color, cDim, fmt.Sprintf("respaldo: %s (%d equipos)", path, len(backups))))
	}

	line := fmt.Sprintf("%d accesibles · %d descartados (SSH)", len(reachable), discarded)
	if skippedNoBackup > 0 {
		line += fmt.Sprintf(" · %d omitidos sin respaldo", skippedNoBackup)
	}
	if forcedNoBackup > 0 {
		line += fmt.Sprintf(" · %d forzados sin respaldo", forcedNoBackup)
	}
	fmt.Println(paint(color, cBold, line))

	if len(reachable) == 0 {
		fmt.Println(paint(color, cYellow, "\nNingún dispositivo respondió SSH — nada que configurar."))
		return
	}

	if *dryRun {
		fmt.Printf("\nSimulación: se configurarían %d dispositivo(s): %s\n", len(reachable), hostsCSV(reachable))
		return
	}

	// ── Fase 3 · Configurar los accesibles ───────────────────────────────
	if !*assumeYes && !confirm(color, fmt.Sprintf("¿Configurar los %d dispositivos accesibles?", len(reachable))) {
		fmt.Println("Cancelado.")
		return
	}
	fmt.Println(paint(color, cBold, fmt.Sprintf("\nFase 3 · Configurando %d dispositivo(s)", len(reachable))))

	applyOpts := opts
	if !*verbose { // verbose already streams raw session output; don't double up
		applyOpts.OnResult = func(_, _ int, r runner.Result) { printApply(r, color) }
	}

	start := time.Now()
	results := runner.Run(context.Background(), reachable, applyOpts)
	elapsed := time.Since(start)

	configured, skipped, failed := 0, 0, 0
	for _, r := range results {
		switch {
		case r.Err != nil:
			failed++
		case r.Skipped:
			skipped++
		default:
			configured++
		}
	}
	fmt.Println()
	summary := fmt.Sprintf("%d presentes · %d configurados · %d omitidos · %d descartados (SSH)", present, configured, skipped, discarded)
	if skippedNoBackup > 0 {
		summary += fmt.Sprintf(" · %d sin respaldo", skippedNoBackup)
	}
	summary += fmt.Sprintf(" · %d con error", failed)
	fmt.Println(paint(color, cBold, summary) +
		paint(color, cDim, fmt.Sprintf("  (%s)", elapsed.Round(100*time.Millisecond))))
	if failed > 0 {
		os.Exit(1)
	}
}

// confirm asks the user a yes/no question and reports whether they accepted.
func confirm(color bool, msg string) bool {
	fmt.Print(paint(color, cBold, fmt.Sprintf("\n%s [s/N]: ", msg)))
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "s", "si", "sí", "y", "yes":
		return true
	default:
		return false
	}
}

// printScanTable renders the phase-1 SNMP scan as a table: which devices
// already have the target community and which still need it.
func printScanTable(scan []runner.ScanResult) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tVENDOR\tSNMP")
	for _, sr := range scan {
		result := "❌ pendiente"
		if sr.Present {
			result = "✅ configurado"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", sr.Target.Host, dash(sr.Target.Vendor), result)
	}
	tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// printProbe streams one line per device in phase 2: a check plus the detected
// vendor and whether its current SNMP config was backed up, or the reason it was
// discarded.
func printProbe(r runner.Result, color bool) {
	if r.Err != nil {
		fmt.Printf("  %s %-16s %s\n", paint(color, cRed, "✗"), r.Target.Host, paint(color, cDim, probeReason(r.Err)))
		return
	}
	mark, tag := paint(color, cGreen, "✓"), paint(color, cDim, "respaldado")
	if r.BackupErr != nil || strings.TrimSpace(r.Backup) == "" {
		mark, tag = paint(color, cYellow, "⚠"), paint(color, cYellow, "sin respaldo")
	}
	fmt.Printf("  %s %-16s %-10s %s\n", mark, r.Target.Host, r.Vendor, tag)
}

// backupRecord is one device's saved SNMP config in the backup file.
type backupRecord struct {
	Vendor     string `json:"vendor"`
	SNMPConfig string `json:"snmp_config"`
}

// writeBackup persists the captured SNMP config of each device to a timestamped
// JSON file in the current directory, NEVER overwriting a prior backup, so a
// destructive apply always has an undo trail. Returns the path written, or "".
func writeBackup(backups map[string]backupRecord) (string, error) {
	if len(backups) == 0 {
		return "", nil
	}
	now := time.Now()
	doc := struct {
		GeneratedAt string                  `json:"generated_at"`
		Devices     map[string]backupRecord `json:"devices"`
	}{now.Format(time.RFC3339), backups}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	name := "community-backup-" + now.Format("20060102-150405") + ".json"
	if err := os.WriteFile(name, append(b, '\n'), 0o600); err != nil {
		return "", err
	}
	return name, nil
}

// probeReason maps a phase-2 failure to a short Spanish reason so the operator
// can tell a credential problem from an unreachable host at a glance.
func probeReason(err error) string {
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "unable to authenticate"):
		return "credenciales SSH inválidas"
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"):
		return "sin respuesta (timeout)"
	case strings.Contains(s, "connection refused"):
		return "conexión rechazada"
	case strings.Contains(s, "no route to host"), strings.Contains(s, "no such host"):
		return "host inalcanzable"
	case strings.Contains(s, "no se pudo identificar"):
		return "vendor no identificado"
	default:
		return firstLine(err.Error())
	}
}

// printApply streams one minimal line per device as it finishes: a check for
// success, the reason for a skip or failure.
func printApply(r runner.Result, color bool) {
	switch {
	case r.Err != nil:
		fmt.Printf("  %s %-16s %s\n", paint(color, cRed, "❌"), r.Target.Host, firstLine(r.Err.Error()))
	case r.Skipped:
		fmt.Printf("  %s %-16s %s\n", paint(color, cYellow, "⊘"), r.Target.Host, firstLine(r.Report.Detail))
	default:
		fmt.Printf("  %s %-16s %s\n", paint(color, cGreen, "✅"), r.Target.Host, paint(color, cDim, r.Vendor))
	}
}

func hostsCSV(ts []config.Target) string {
	if len(ts) == 0 {
		return "(ninguno)"
	}
	hs := make([]string, len(ts))
	for i, t := range ts {
		hs[i] = t.Host
	}
	return strings.Join(hs, ", ")
}

func paint(color bool, code, s string) string {
	if !color {
		return s
	}
	return code + s + cReset
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && (st.Mode()&os.ModeCharDevice) != 0
}

// besideBinary resolves a config file to the binary's own folder first (the
// portable "drop the config next to the binary" layout), falling back to the
// current directory so `go run` and CWD-based usage still work.
func besideBinary(name string) string {
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return name
}

func filterHosts(targets []config.Target, csv string) []config.Target {
	want := map[string]bool{}
	for _, h := range strings.Split(csv, ",") {
		if h = strings.TrimSpace(h); h != "" {
			want[h] = true
		}
	}
	var out []config.Target
	for _, t := range targets {
		if want[t.Host] {
			out = append(out, t)
		}
	}
	return out
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
