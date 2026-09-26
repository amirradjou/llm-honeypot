package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/analysis"
)

// runDashboard serves the live view of the recordings.
//
// The default bind address is loopback on purpose. This page is a summary
// of hostile input, sitting on a machine that is deliberately inviting
// attackers; it should be reached over an SSH tunnel, not published. A
// non-loopback address is honoured but warned about.
func runDashboard(args []string) error {
	fs := flag.NewFlagSet("honeypot dashboard", flag.ContinueOnError)
	addr := fs.String("addr", envOr("HONEYPOT_DASHBOARD_ADDR", "127.0.0.1:8080"), "listen address (HONEYPOT_DASHBOARD_ADDR)")
	dataDir := fs.String("data", envOr("HONEYPOT_DATA_DIR", "./data"), "data directory holding sessions/ (HONEYPOT_DATA_DIR)")
	ttl := fs.Duration("refresh", 5*time.Second, "how often the recordings may be re-read")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !isLoopback(*addr) {
		fmt.Fprintf(os.Stderr,
			"honeypot: warning: serving the dashboard on %s exposes a summary of attacker\n"+
				"          activity beyond this host. Prefer the default loopback address and an\n"+
				"          SSH tunnel: ssh -L 8080:127.0.0.1:8080 <host>\n", *addr)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           analysis.NewDashboard(*dataDir, *ttl),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "honeypot: dashboard on http://%s (data %s)\n", *addr, *dataDir)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// isLoopback reports whether addr binds only to the loopback interface.
// An empty or wildcard host is not loopback.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
