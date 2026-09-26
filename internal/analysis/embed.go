package analysis

import "embed"

// templateFS carries the dashboard template into the binary, so the
// honeypot ships as a single static file with no runtime assets to lose.
//
//go:embed templates/dashboard.html
var templateFS embed.FS
