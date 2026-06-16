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
	deviceTimeout := flag.Duration("timeout", 90*time.Second, "timeout total por dispositivo")
	connectTimeout := flag.Duration("connect-timeout", 8*time.Second, "timeout de conexión SSH (los equipos muertos fallan así de rápido)")
	ioTimeout := flag.Duration("io-timeout", 30*time.Second, "timeout de lectura por paso")
	dryRun := flag.Bool("dry-run", false, "solo escanear; lista lo que se configuraría, sin cambios")
	vendor := flag.String("vendor", "", "forzar este vendor para todos (sin autodetección)")
	only := flag.String("only", "", "filtro de hosts separados por coma")
	verbose := flag.Bool("v", false, "mostrar la sesión SSH en vivo")
	forceZyxel := flag.Bool("force-zyxel", false, "configurar Zyxel también (SOBREESCRIBE su única comunidad SNMP)")
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

	if *dryRun {
		fmt.Printf("\nSimulación: se configurarían %d dispositivo(s): %s\n", len(missing), hostsCSV(missing))
		return
	}

	// Confirmación antes de tocar nada.
	if !*assumeYes && !confirm(color, len(missing)) {
		fmt.Println("Cancelado.")
		return
	}

	// ── Fase 2 · configurar los pendientes ───────────────────────────────
	fmt.Println(paint(color, cBold, fmt.Sprintf("\nFase 2 · Configurando %d dispositivo(s)", len(missing))))
	opts := runner.Options{
		Concurrency:    *concurrency,
		DeviceTimeout:  *deviceTimeout,
		Dialer:         transport.Dialer{ConnectTimeout: *connectTimeout, IOTimeout: *ioTimeout},
		Verbose:        *verbose,
		Out:            os.Stdout,
		ForceOverwrite: *forceZyxel,
	}
	if !*verbose { // verbose already streams raw session output; don't double up
		opts.OnResult = func(_, _ int, r runner.Result) { printApply(r, color) }
	}

	start := time.Now()
	results := runner.Run(context.Background(), missing, opts)
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
	fmt.Println(paint(color, cBold, fmt.Sprintf("%d presentes · %d configurados · %d omitidos · %d con error", present, configured, skipped, failed)) +
		paint(color, cDim, fmt.Sprintf("  (%s)", elapsed.Round(100*time.Millisecond))))
	if failed > 0 {
		os.Exit(1)
	}
}

// confirm asks the user whether to configure the pending devices.
func confirm(color bool, n int) bool {
	fmt.Print(paint(color, cBold, fmt.Sprintf("\n¿Configurar los %d dispositivos pendientes? [s/N]: ", n)))
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
