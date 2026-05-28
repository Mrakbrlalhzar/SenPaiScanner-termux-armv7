// Package config holds default value constants for scan and test operations.
// The TUI reads these defaults when building form initial values.
package config

import "time"

// ScanDefaults are the factory defaults shown in the scan config form.
var ScanDefaults = struct {
	Count       int
	Concurrency int
	Timeout     time.Duration
	Tries       int
	Port        int
	Mode        string
	UseV4       bool
	UseV6       bool
	Top         int
}{
	Count:       500,
	Concurrency: 100,
	Timeout:     3 * time.Second,
	Tries:       4,
	Port:        443,
	Mode:        "tls",
	UseV4:       true,
	UseV6:       false,
	Top:         10,
}
