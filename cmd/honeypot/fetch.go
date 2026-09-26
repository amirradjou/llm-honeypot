package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/analysis"
	"github.com/amirradjou/llm-honeypot/internal/capture"
)

// runFetch downloads the payloads attackers pointed at, into a quarantine
// directory, for later analysis.
//
// It is a dry run unless -confirm is passed. That is deliberate: this
// command downloads live malware onto the machine that runs it, and the
// request tells the attacker's server that somebody looked. Neither is a
// surprise worth springing on someone who typed a command to see what it
// did.
func runFetch(args []string) error {
	fs := flag.NewFlagSet("honeypot fetch", flag.ContinueOnError)
	dataDir := fs.String("data", envOr("HONEYPOT_DATA_DIR", "./data"), "data directory holding sessions/ (HONEYPOT_DATA_DIR)")
	outDir := fs.String("out", "", "quarantine directory (default <data>/payloads)")
	confirm := fs.Bool("confirm", false, "actually download; without this the command only lists what it would fetch")
	maxBytes := fs.Int64("max-bytes", 8<<20, "per-payload size cap")
	timeout := fs.Duration("timeout", 30*time.Second, "per-payload timeout")
	limit := fs.Int("limit", 0, "stop after this many URLs (0 = no limit)")
	pause := fs.Duration("pause", time.Second, "wait between fetches")
	allowPrivate := fs.Bool("allow-private", false, "permit private/loopback targets (testing only; unsafe)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sessions, err := analysis.Load(*dataDir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", *dataDir, err)
	}
	urls := distinctURLs(sessions)
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "no download URLs recorded yet")
		return nil
	}
	if *limit > 0 && len(urls) > *limit {
		urls = urls[:*limit]
	}

	if !*confirm {
		fmt.Fprintf(os.Stderr, "%d URL(s) recorded. This is a dry run — nothing will be downloaded.\n\n", len(urls))
		for _, u := range urls {
			fmt.Println(u)
		}
		fmt.Fprintf(os.Stderr, "\nRe-run with -confirm to download them into quarantine.\n"+
			"Be aware that doing so pulls live malware onto this machine and tells\n"+
			"each server that someone is looking at it.\n")
		return nil
	}

	quarantine := *outDir
	if quarantine == "" {
		quarantine = *dataDir + "/payloads"
	}
	store, err := capture.NewStore(quarantine)
	if err != nil {
		return err
	}
	fetcher := capture.NewFetcher(capture.Fetcher{
		MaxBytes:     *maxBytes,
		Timeout:      *timeout,
		AllowPrivate: *allowPrivate,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var fetched, deduped, failed int
	for i, u := range urls {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "interrupted")
			break
		}
		if i > 0 && *pause > 0 {
			select {
			case <-time.After(*pause):
			case <-ctx.Done():
			}
		}
		res, err := fetcher.Fetch(ctx, u)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  skip  %s: %v\n", u, err)
			continue
		}
		meta, isNew, err := store.Put(res.Data, u, res.ContentType, res.Truncated)
		if err != nil {
			failed++
			fmt.Fprintf(os.Stderr, "  error %s: %v\n", u, err)
			continue
		}
		if isNew {
			fetched++
			fmt.Fprintf(os.Stderr, "  new   %s  %s  %d bytes%s\n", meta.SHA256[:12], u, meta.Size, truncNote(res.Truncated))
		} else {
			deduped++
			fmt.Fprintf(os.Stderr, "  dup   %s  %s\n", meta.SHA256[:12], u)
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d new, %d already held, %d failed — quarantine: %s\n",
		fetched, deduped, failed, store.Dir())
	return nil
}

func truncNote(t bool) string {
	if t {
		return " (truncated at the size cap)"
	}
	return ""
}

// distinctURLs collects every download URL seen, in a stable order.
func distinctURLs(sessions []*analysis.Session) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range sessions {
		for _, d := range s.Downloads {
			if d.URL != "" && !seen[d.URL] {
				seen[d.URL] = true
				out = append(out, d.URL)
			}
		}
	}
	sort.Strings(out)
	return out
}
