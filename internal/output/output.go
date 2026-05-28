package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/matinsenpai/senpaiscanner/internal/result"
)

// Format identifies the output format.
type Format int

const (
	FormatCSV Format = iota
	FormatJSON
	FormatTXT
)

// DetectFormat infers the output format from the file extension.
func DetectFormat(path string) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return FormatJSON
	case ".txt":
		return FormatTXT
	default:
		return FormatCSV
	}
}

// Writer writes results to a file in a thread-safe manner.
type Writer struct {
	mu    sync.Mutex
	f     *os.File
	fmt   Format
	csv   *csv.Writer
	first bool // for JSON array formatting
}

// New creates (or truncates) the output file and returns a ready Writer.
func New(path string, fmt Format) (*Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt2err(path, err)
	}

	w := &Writer{f: f, fmt: fmt, first: true}

	switch fmt {
	case FormatCSV:
		w.csv = csv.NewWriter(f)
		_ = w.csv.Write([]string{
			"ip", "loss_pct", "avg_ms", "min_ms", "max_ms",
			"jitter_ms", "download_kbps", "speed_tested", "colo", "tls_ok", "http_status",
		})
		w.csv.Flush()
	case FormatJSON:
		_, _ = f.WriteString("[\n")
	}

	return w, nil
}

// Write appends a result to the output file.
func (w *Writer) Write(r *result.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.fmt {
	case FormatCSV:
		return w.writeCSV(r)
	case FormatJSON:
		return w.writeJSON(r)
	default:
		return w.writeTXT(r)
	}
}

// Close flushes and closes the underlying file.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.fmt == FormatJSON {
		_, _ = w.f.WriteString("\n]\n")
	}
	if w.csv != nil {
		w.csv.Flush()
	}
	return w.f.Close()
}

func (w *Writer) writeCSV(r *result.Result) error {
	row := []string{
		r.IP.String(),
		fmt.Sprintf("%.1f", r.Loss()),
		fmt.Sprintf("%.2f", float64(r.Avg().Milliseconds())),
		fmt.Sprintf("%.2f", float64(r.Min().Milliseconds())),
		fmt.Sprintf("%.2f", float64(r.Max().Milliseconds())),
		fmt.Sprintf("%.2f", float64(r.Jitter().Milliseconds())),
		fmt.Sprintf("%.1f", r.Throughput/1024),
		boolStr(r.SpeedTested),
		r.Colo,
		boolStr(r.TLSOk),
		fmt.Sprintf("%d", r.HTTPStatus),
	}
	w.csv.Write(row)
	w.csv.Flush()
	return w.csv.Error()
}

func (w *Writer) writeJSON(r *result.Result) error {
	type jsonResult struct {
		IP          string  `json:"ip"`
		LossPct     float64 `json:"loss_pct"`
		AvgMs       float64 `json:"avg_ms"`
		MinMs       float64 `json:"min_ms"`
		MaxMs       float64 `json:"max_ms"`
		JitterMs    float64 `json:"jitter_ms"`
		DownloadKB  float64 `json:"download_kbps,omitempty"`
		SpeedTested bool    `json:"speed_tested,omitempty"`
		Colo        string  `json:"colo,omitempty"`
		TLSOk       bool    `json:"tls_ok"`
		HTTPStatus  int     `json:"http_status,omitempty"`
	}
	obj := jsonResult{
		IP:          r.IP.String(),
		LossPct:     r.Loss(),
		AvgMs:       ms(r.Avg()),
		MinMs:       ms(r.Min()),
		MaxMs:       ms(r.Max()),
		JitterMs:    ms(r.Jitter()),
		DownloadKB:  r.Throughput / 1024,
		SpeedTested: r.SpeedTested,
		Colo:        r.Colo,
		TLSOk:       r.TLSOk,
		HTTPStatus:  r.HTTPStatus,
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	if !w.first {
		_, err = w.f.WriteString(",\n")
		if err != nil {
			return err
		}
	}
	w.first = false
	_, err = w.f.Write(b)
	return err
}

func (w *Writer) writeTXT(r *result.Result) error {
	line := fmt.Sprintf("%-15s  loss=%-5.1f%%  avg=%-7.2fms  jitter=%-7.2fms  dl=%-7.1fKB/s  colo=%-4s\n",
		r.IP.String(),
		r.Loss(),
		ms(r.Avg()),
		ms(r.Jitter()),
		r.Throughput/1024,
		r.Colo,
	)
	_, err := w.f.WriteString(line)
	return err
}

// --- State / Resume ----------------------------------------------------------

// State persists scanner progress for resume capability.
type State struct {
	Tested  int64    `json:"tested"`
	Healthy int64    `json:"healthy"`
	Seen    []string `json:"seen"`
}

// LoadState reads a previously saved state file. Returns empty State on error.
func LoadState(path string) State {
	b, err := os.ReadFile(path)
	if err != nil {
		return State{}
	}
	var s State
	_ = json.Unmarshal(b, &s)
	return State{Tested: s.Tested, Healthy: s.Healthy, Seen: s.Seen}
}

// SaveState atomically writes the state to disk.
func SaveState(path string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- helpers -----------------------------------------------------------------

func ms(d interface{ Milliseconds() int64 }) float64 {
	return float64(d.Milliseconds())
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func fmt2err(path string, err error) error {
	return fmt.Errorf("opening output file %q: %w", path, err)
}
