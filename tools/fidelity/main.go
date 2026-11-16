// Command fidelity runs bot-style command lines against a running honeypot and
// against a real Ubuntu 22.04 container, and reports where the two disagree.
//
// It is a development tool, not part of the honeypot. The honeypot side goes
// over real SSH (one connection per line, so every line gets a fresh machine);
// the reference side is one `docker run --rm --network none` per line.
//
//	docker build -t llm-honeypot-fidelity-ref tools/fidelity
//	./bin/honeypot -addr 127.0.0.1:2222 &
//	go run ./tools/fidelity -addr 127.0.0.1:2222 -o docs/fidelity.md
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

type mode string

const (
	modeSame  mode = "same"
	modeExact mode = "exact"
	modeNet   mode = "net"
)

type line struct {
	Family  string `json:"family"`
	Mode    mode   `json:"mode"`
	Command string `json:"command"`
}

type outcome struct {
	Exit   int    `json:"exit"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Err    string `json:"error,omitempty"`
}

type result struct {
	line
	Honeypot  outcome  `json:"honeypot"`
	Reference *outcome `json:"reference,omitempty"`
	Match     bool     `json:"match"`
	Reasons   []string `json:"reasons,omitempty"`
	Giveaway  bool     `json:"giveaway"`
}

func main() {
	var (
		corpus   = flag.String("corpus", "tools/fidelity/corpus.txt", "command corpus")
		addr     = flag.String("addr", "127.0.0.1:2222", "honeypot SSH address")
		image    = flag.String("image", "llm-honeypot-fidelity-ref", "reference Docker image")
		out      = flag.String("o", "", "write the Markdown report here (default stdout)")
		jsonOut  = flag.String("json", "", "also write every result as JSON here")
		label    = flag.String("label", "", "a note about this run, printed in the report header")
		parallel = flag.Int("parallel", 6, "lines run at once")
		timeout  = flag.Duration("timeout", 20*time.Second, "per-line time limit on each side")
	)
	flag.Parse()

	lines, err := readCorpus(*corpus)
	if err != nil {
		fatal(err)
	}
	results := make([]result, len(lines))
	sem := make(chan struct{}, max(1, *parallel))
	var wg sync.WaitGroup
	for i, l := range lines {
		wg.Add(1)
		go func(i int, l line) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = check(l, *addr, *image, *timeout)
		}(i, l)
	}
	wg.Wait()

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		w = f
	}
	report(w, results, *label)

	if *jsonOut != "" {
		b, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(*jsonOut, append(b, '\n'), 0o644); err != nil {
			fatal(err)
		}
	}
	score, total, give := tally(results)
	fmt.Fprintf(os.Stderr, "fidelity: %d of %d lines match Ubuntu 22.04, %d giveaways\n", score, total, give)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fidelity:", err)
	os.Exit(1)
}

func readCorpus(path string) ([]line, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []line
	family := "misc"
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		t := sc.Text()
		switch {
		case strings.HasPrefix(t, "## "):
			family = strings.TrimSpace(t[3:])
		case strings.TrimSpace(t) == "", strings.HasPrefix(t, "#"):
		default:
			m, cmd, ok := strings.Cut(t, "\t")
			if !ok || (mode(m) != modeSame && mode(m) != modeExact && mode(m) != modeNet) {
				return nil, fmt.Errorf("%s:%d: want \"same|exact|net<TAB>command\"", path, n)
			}
			out = append(out, line{Family: family, Mode: mode(m), Command: cmd})
		}
	}
	return out, sc.Err()
}

func check(l line, addr, image string, timeout time.Duration) result {
	r := result{line: l, Honeypot: runHoneypot(addr, l.Command, timeout)}
	if l.Mode == modeNet {
		r.Reasons = netGiveaways(r.Honeypot)
		r.Giveaway = len(r.Reasons) > 0
		r.Match = !r.Giveaway
		return r
	}
	ref := runReference(image, l.Command, timeout)
	r.Reference = &ref
	r.Reasons = compare(l.Mode, r.Honeypot, ref)
	r.Match = len(r.Reasons) == 0
	r.Giveaway = giveaway(r.Honeypot) && !giveaway(ref)
	return r
}

// compare lists the ways the honeypot's answer differs from Ubuntu's.
func compare(m mode, hp, ref outcome) []string {
	var why []string
	if hp.Err != "" {
		why = append(why, "honeypot: "+hp.Err)
	}
	if ref.Err != "" {
		why = append(why, "reference: "+ref.Err)
	}
	if hp.Exit != ref.Exit {
		why = append(why, fmt.Sprintf("exit %d, Ubuntu %d", hp.Exit, ref.Exit))
	}
	if (hp.Stdout == "") != (ref.Stdout == "") {
		why = append(why, "stdout "+emptiness(hp.Stdout)+", Ubuntu "+emptiness(ref.Stdout))
	} else if m == modeExact && hp.Stdout != ref.Stdout {
		why = append(why, "stdout differs")
	}
	if (hp.Stderr == "") != (ref.Stderr == "") {
		why = append(why, "stderr "+emptiness(hp.Stderr)+", Ubuntu "+emptiness(ref.Stderr))
	}
	return why
}

func emptiness(s string) string {
	if s == "" {
		return "empty"
	}
	return "not empty"
}

// giveaway reports output no real server would print for a stock command.
func giveaway(o outcome) bool {
	all := o.Stdout + o.Stderr
	for _, m := range []string{"command not found", "syntax error", "unexpected EOF", "Exec format error"} {
		if strings.Contains(all, m) {
			return true
		}
	}
	return false
}

// netGiveaways checks a line the reference box cannot run. Downloads are faked
// by design, so the only question is whether the fake looks broken.
func netGiveaways(o outcome) []string {
	var why []string
	all := o.Stdout + o.Stderr
	for _, m := range []string{"command not found", "syntax error", "unexpected EOF"} {
		if strings.Contains(all, m) {
			why = append(why, "says "+m)
		}
	}
	if !utf8.ValidString(all) {
		why = append(why, "prints binary garbage")
	}
	if len(all) > 4096 {
		why = append(why, fmt.Sprintf("prints %d bytes", len(all)))
	}
	if o.Err != "" {
		why = append(why, o.Err)
	}
	return why
}

const outputCap = 64 << 10

func runHoneypot(addr, cmd string, timeout time.Duration) outcome {
	cfg := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("fidelity")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a local test target
		Timeout:         timeout,
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return outcome{Exit: -1, Err: err.Error()}
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return outcome{Exit: -1, Err: err.Error()}
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()
	s, err := client.NewSession()
	if err != nil {
		return outcome{Exit: -1, Err: err.Error()}
	}
	var stdout, stderr capped
	s.Stdout, s.Stderr = &stdout, &stderr
	err = s.Run(cmd)
	o := outcome{Stdout: stdout.String(), Stderr: stderr.String()}
	var ee *ssh.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		o.Exit = ee.ExitStatus()
	default:
		o.Exit, o.Err = -1, err.Error()
	}
	return o
}

func runReference(image, cmd string, timeout time.Duration) outcome {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "docker", "run", "--rm", "--network", "none",
		"--hostname", "srv-web01", "-w", "/root",
		"-e", "SHELL=/bin/bash", "-e", "USER=root", "-e", "LOGNAME=root",
		image, "bash", "-c", cmd)
	var stdout, stderr capped
	c.Stdout, c.Stderr = &stdout, &stderr
	err := c.Run()
	o := outcome{Stdout: stdout.String(), Stderr: stderr.String()}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		o.Exit = ee.ExitCode()
	default:
		o.Exit, o.Err = -1, err.Error()
	}
	if ctx.Err() != nil {
		o.Err = "timed out"
	}
	return o
}

// capped is a buffer that silently stops growing at outputCap.
type capped struct{ bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := outputCap - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}

func tally(rs []result) (match, total, giveaways int) {
	for _, r := range rs {
		total++
		if r.Match {
			match++
		}
		if r.Giveaway {
			giveaways++
		}
	}
	return
}

func report(w io.Writer, rs []result, label string) {
	match, total, give := tally(rs)
	fmt.Fprintf(w, "# Fidelity check\n\n")
	fmt.Fprintf(w, "Bot-style command lines from [`tools/fidelity/corpus.txt`](../tools/fidelity/corpus.txt), "+
		"each run once in the honeypot over SSH and once in a fresh Ubuntu 22.04 container "+
		"([`tools/fidelity/Dockerfile`](../tools/fidelity/Dockerfile), no network). ")
	fmt.Fprintf(w, "A line matches when the exit code is the same and stdout and stderr are empty or "+
		"non-empty on both sides; `exact` lines must also print the same stdout. "+
		"Download lines (`net`) cannot run on a box with no network, so they only have to avoid looking broken.\n\n")
	if label != "" {
		fmt.Fprintf(w, "%s\n\n", label)
	}
	fmt.Fprintf(w, "**%d of %d lines behave like Ubuntu 22.04 (%d%%). Giveaways: %d.**\n\n",
		match, total, pct(match, total), give)
	fmt.Fprintf(w, "A giveaway is an answer no stock server gives: `command not found` for a tool Ubuntu ships, "+
		"a syntax error on valid bash, binary garbage on the terminal.\n\n")

	fmt.Fprintf(w, "| Group | Lines | Match |\n|---|---:|---:|\n")
	var families []string
	seen := map[string]bool{}
	for _, r := range rs {
		if !seen[r.Family] {
			seen[r.Family] = true
			families = append(families, r.Family)
		}
	}
	for _, f := range families {
		n, m := 0, 0
		for _, r := range rs {
			if r.Family == f {
				n++
				if r.Match {
					m++
				}
			}
		}
		fmt.Fprintf(w, "| %s | %d | %d |\n", f, n, m)
	}

	var bad []result
	for _, r := range rs {
		if !r.Match {
			bad = append(bad, r)
		}
	}
	if len(bad) == 0 {
		return
	}
	fmt.Fprintf(w, "\n## Differences\n\n| Command | Why | Honeypot said | Ubuntu said |\n|---|---|---|---|\n")
	for _, r := range bad {
		refSaid := "—"
		if r.Reference != nil {
			refSaid = said(*r.Reference)
		}
		fmt.Fprintf(w, "| `%s` | %s | %s | %s |\n", cell(r.Command, 70), cell(strings.Join(r.Reasons, "; "), 80),
			said(r.Honeypot), refSaid)
	}
}

func said(o outcome) string {
	first := firstLine(o.Stderr)
	if first == "" {
		first = firstLine(o.Stdout)
	}
	if !utf8.ValidString(first) {
		first = "(binary)"
	}
	if first == "" {
		return fmt.Sprintf("exit %d, no output", o.Exit)
	}
	return fmt.Sprintf("exit %d: `%s`", o.Exit, cell(first, 60))
}

func firstLine(s string) string {
	s = strings.TrimLeft(s, "\n")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func cell(s string, n int) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "\n", " ")
	if r := []rune(s); len(r) > n {
		s = string(r[:n-1]) + "…"
	}
	return s
}

func pct(a, b int) int {
	if b == 0 {
		return 0
	}
	return a * 100 / b
}
