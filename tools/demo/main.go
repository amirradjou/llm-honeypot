// Command demo types a scripted attacker session into a honeypot running on
// this machine, at a steady human pace, so the honeypot's own recording
// (<conn>.cast) can be turned into the README's GIF:
//
//	./bin/honeypot -addr 127.0.0.1:2222 -data /tmp/demo -llm ollama -llm-model qwen2.5:7b &
//	go run ./tools/demo -addr 127.0.0.1:2222 -script tools/demo/session.txt
//	agg --idle-time-limit 1.2 /tmp/demo/sessions/*/*.cast docs/demo.gif
//
// Everything on screen comes from the honeypot; this program only types.
// It refuses non-loopback targets: it is a recording aid, not a client for
// other people's servers.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:2222", "honeypot address (loopback only)")
	script := flag.String("script", "tools/demo/session.txt", "one command per line; '# pause 2s' waits")
	user := flag.String("user", "root", "login name")
	pass := flag.String("pass", "admin123", "password (the honeypot accepts any)")
	cols := flag.Int("cols", 100, "terminal width")
	rows := flag.Int("rows", 26, "terminal height")
	keyDelay := flag.Duration("key", 45*time.Millisecond, "delay between keystrokes")
	think := flag.Duration("think", 900*time.Millisecond, "pause after each prompt before typing")
	flag.Parse()

	host, _, err := net.SplitHostPort(*addr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		fatal(fmt.Errorf("refusing %q: demo only talks to a honeypot on this machine", *addr))
	}
	lines, err := readScript(*script)
	if err != nil {
		fatal(err)
	}

	client, err := ssh.Dial("tcp", *addr, &ssh.ClientConfig{
		User:            *user,
		Auth:            []ssh.AuthMethod{ssh.Password(*pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a local honeypot
		Timeout:         10 * time.Second,
	})
	if err != nil {
		fatal(err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", *rows, *cols, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		fatal(err)
	}

	screen := &watcher{}
	go func() { _, _ = io.Copy(io.MultiWriter(screen, os.Stdout), stdout) }()

	for _, l := range lines {
		if d, ok := pause(l); ok {
			time.Sleep(d)
			continue
		}
		if err := screen.waitPrompt(3 * time.Minute); err != nil {
			fatal(err)
		}
		time.Sleep(*think)
		for _, r := range l {
			_, _ = io.WriteString(stdin, string(r))
			time.Sleep(*keyDelay)
		}
		time.Sleep(*keyDelay * 4)
		screen.reset()
		_, _ = io.WriteString(stdin, "\r")
	}
	_ = screen.waitPrompt(3 * time.Minute)
	time.Sleep(2 * *think)
	_, _ = io.WriteString(stdin, "exit\r")
	_ = sess.Wait()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "demo:", err)
	os.Exit(1)
}

func readScript(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), " ")
		if l == "" || (strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "# pause")) {
			continue
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

func pause(l string) (time.Duration, bool) {
	if !strings.HasPrefix(l, "# pause ") {
		return 0, false
	}
	d, err := time.ParseDuration(strings.TrimPrefix(l, "# pause "))
	return d, err == nil
}

// watcher remembers recent output so the driver can wait for a prompt.
type watcher struct {
	mu   sync.Mutex
	tail []byte
}

func (w *watcher) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.tail = append(w.tail, p...)
	if len(w.tail) > 4096 {
		w.tail = w.tail[len(w.tail)-4096:]
	}
	return len(p), nil
}

func (w *watcher) reset() {
	w.mu.Lock()
	w.tail = nil
	w.mu.Unlock()
}

func (w *watcher) waitPrompt(limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		t := bytes.TrimRight(w.tail, " ")
		ready := bytes.HasSuffix(t, []byte("#")) || bytes.HasSuffix(t, []byte("$"))
		w.mu.Unlock()
		if ready {
			// Let any trailing output settle before typing.
			time.Sleep(150 * time.Millisecond)
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("no prompt after %s", limit)
}
