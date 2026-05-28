package ui

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/matinsenpai/senpaiscanner/internal/engine"
	"github.com/matinsenpai/senpaiscanner/internal/ipsrc"
	"github.com/matinsenpai/senpaiscanner/internal/output"
	"github.com/matinsenpai/senpaiscanner/internal/prober"
	"github.com/matinsenpai/senpaiscanner/internal/result"
)

// scanCancel holds the cancel function for the active scan so the TUI can
// abort it when the user presses esc/q.
var scanCancel context.CancelFunc

// StartScanCmd builds a tea.Cmd that runs the scan engine in the background,
// sending ResultMsg and StatsMsg messages to the Bubble Tea program.
func StartScanCmd(cfg ScanConfig) tea.Cmd {
	return func() tea.Msg {
		go runScan(cfg)
		return nil
	}
}

// CancelScanCmd cancels the running scan.
func CancelScanCmd() tea.Cmd {
	return func() tea.Msg {
		if scanCancel != nil {
			scanCancel()
		}
		return nil
	}
}

// StartTestCmd runs the test pass against a file of IPs.
func StartTestCmd(ipFile string) tea.Cmd {
	return func() tea.Msg {
		go runTest(ipFile)
		return nil
	}
}

// StartColosCmd discovers accessible Cloudflare PoPs.
func StartColosCmd() tea.Cmd {
	return func() tea.Msg {
		go runColos()
		return nil
	}
}

// prog is set by main before launching the Bubble Tea program so the
// background goroutines can send messages back.
var prog *tea.Program

// SetProgram must be called before any scan command is started.
func SetProgram(p *tea.Program) { prog = p }

// ---------------------------------------------------------------------------
// Background runners
// ---------------------------------------------------------------------------

func runScan(cfg ScanConfig) {
	count, _ := strconv.Atoi(cfg.Count)
	concurrency, _ := strconv.Atoi(cfg.Concurrency)
	if concurrency <= 0 {
		concurrency = 100
	}
	timeout := parseTimeout(cfg.Timeout, 3*time.Second)
	tries, _ := strconv.Atoi(cfg.Tries)
	if tries <= 0 {
		tries = 4
	}
	port, _ := strconv.Atoi(cfg.Port)
	if port <= 0 {
		port = 443
	}

	mode, err := prober.ParseMode(cfg.Mode)
	if err != nil {
		mode = prober.ModeTLS
	}

	var extra []string
	for _, c := range strings.Split(cfg.CIDR, ",") {
		c = strings.TrimSpace(c)
		if c != "" {
			extra = append(extra, c)
		}
	}

	src, err := ipsrc.New(cfg.UseV4, cfg.UseV6, extra)
	if err != nil {
		if prog != nil {
			prog.Send(DoneMsg{})
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	engCfg := engine.Config{
		Concurrency: concurrency,
		ProbeConfig: prober.Config{
			Port:       port,
			Mode:       mode,
			Tries:      tries,
			Timeout:    timeout,
			SNI:        cfg.SNI,
			SpeedBytes: speedSampleForMode(mode),
		},
	}
	eng := engine.New(engCfg)

	coloSet := buildColoSet(cfg.ColoFilter)

	var writer *output.Writer
	if cfg.OutputFile != "" {
		fmt2 := output.DetectFormat(cfg.OutputFile)
		if w, e := output.New(cfg.OutputFile, fmt2); e == nil {
			writer = w
			defer writer.Close()
		}
	}

	ipStream := src.Stream(ctx, count)
	eng.Run(ctx, ipStream, func(r *result.Result) {
		if !passesColoFilter(r, coloSet) {
			return
		}
		if writer != nil {
			_ = writer.Write(r)
		}
		if prog != nil {
			s := eng.Stats()
			prog.Send(ResultMsg(r))
			prog.Send(StatsMsg{s.Tested.Load(), s.Healthy.Load(), s.Failed.Load(), s.InFlight.Load()})
		}
	})

	if prog != nil {
		prog.Send(DoneMsg{})
	}
}

func runTest(ipFile string) {
	ips, err := loadIPs(ipFile)
	if err != nil || len(ips) == 0 {
		if prog != nil {
			prog.Send(DoneMsg{})
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	engCfg := engine.Config{
		Concurrency: 20,
		ProbeConfig: prober.Config{
			Port:       443,
			Mode:       prober.ModeHTTP,
			Tries:      6,
			Timeout:    10 * time.Second,
			SNI:        "speed.cloudflare.com",
			SpeedBytes: 512 * 1024,
		},
	}
	eng := engine.New(engCfg)

	eng.RunList(ctx, ips, func(r *result.Result) {
		if prog != nil {
			s := eng.Stats()
			prog.Send(ResultMsg(r))
			prog.Send(StatsMsg{s.Tested.Load(), s.Healthy.Load(), s.Failed.Load(), s.InFlight.Load()})
		}
	})

	if prog != nil {
		prog.Send(DoneMsg{})
	}
}

func runColos() {
	src, err := ipsrc.New(true, false, nil)
	if err != nil {
		if prog != nil {
			prog.Send(ColosDoneMsg{})
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	defer cancel()

	engCfg := engine.Config{
		Concurrency: 80,
		ProbeConfig: prober.Config{
			Port:       443,
			Mode:       prober.ModeHTTP,
			Tries:      2,
			Timeout:    5 * time.Second,
			SpeedBytes: 0,
		},
	}
	eng := engine.New(engCfg)
	ipStream := src.Stream(ctx, 300)

	eng.Run(ctx, ipStream, func(r *result.Result) {
		if !r.IsHealthy() || r.Colo == "" {
			return
		}
		if prog != nil {
			s := eng.Stats()
			prog.Send(ResultMsg(r))
			prog.Send(StatsMsg{s.Tested.Load(), s.Healthy.Load(), s.Failed.Load(), s.InFlight.Load()})
		}
	})

	if prog != nil {
		prog.Send(ColosDoneMsg{})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func buildColoSet(raw string) map[string]bool {
	if raw == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, c := range strings.Split(raw, ",") {
		c = strings.TrimSpace(strings.ToUpper(c))
		if c != "" {
			set[c] = true
		}
	}
	return set
}

func passesColoFilter(r *result.Result, set map[string]bool) bool {
	if set == nil {
		return true
	}
	return set[strings.ToUpper(r.Colo)]
}

func loadIPs(path string) ([]net.IP, error) {
	var f *os.File
	var err error
	if path == "" || path == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()
	}
	var ips []net.IP
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "ip") {
			continue
		}
		field := strings.SplitN(line, ",", 2)[0]
		if ip := net.ParseIP(strings.TrimSpace(field)); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, sc.Err()
}

func speedSampleForMode(mode prober.Mode) int64 {
	if mode != prober.ModeHTTP {
		return 0
	}
	// Small enough for large scans, big enough to catch IPs that connect but
	// stall once real payload starts moving.
	return 256 * 1024
}

func parseTimeout(raw string, fallback time.Duration) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	if timeout, err := time.ParseDuration(raw); err == nil {
		return timeout
	}
	if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}
