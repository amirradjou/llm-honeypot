package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/amirradjou/llm-honeypot/internal/analysis"
)

// runReport reads the recordings and writes the "what the bots did"
// report. It never touches the live honeypot, so it is safe to run
// against a data directory that is currently being written to.
func runReport(args []string) error {
	fs := flag.NewFlagSet("honeypot report", flag.ContinueOnError)
	dataDir := fs.String("data", envOr("HONEYPOT_DATA_DIR", "./data"), "data directory holding sessions/ (HONEYPOT_DATA_DIR)")
	out := fs.String("o", "", "write the report to this file instead of stdout")
	title := fs.String("title", "", "report title (default: generated from the date range)")
	topN := fs.Int("top", 10, "rows per ranked table")
	clusters := fs.Int("clusters", 5, "how many attacker behaviours to describe")
	transcript := fs.Bool("transcript", false, "include an example transcript for each behaviour")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sessions, err := analysis.Load(*dataDir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *dataDir, err)
	}

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	if err := analysis.WriteReport(w, sessions, analysis.ReportOptions{
		Title:      *title,
		TopN:       *topN,
		Clusters:   *clusters,
		Transcript: *transcript,
	}); err != nil {
		return err
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "wrote %s (%d session(s))\n", *out, len(sessions))
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
