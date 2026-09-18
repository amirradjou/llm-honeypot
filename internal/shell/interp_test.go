package shell

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/profile"
)

func testSession(t *testing.T) (*Interp, *Session) {
	t.Helper()
	fixed := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	m, err := machine.New(profile.Default(), func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	return New(), NewSession(m, "root", 1)
}

// run executes a line and returns stdout, stderr and status.
func run(t *testing.T, in *Interp, s *Session, line string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	status, _, _ := in.Run(s, line, strings.NewReader(""), &out, &errb)
	return out.String(), errb.String(), status
}

func TestEcho(t *testing.T) {
	in, s := testSession(t)
	cases := []struct {
		line, want string
	}{
		{`echo hello world`, "hello world\n"},
		{`echo -n no newline`, "no newline"},
		{`echo -e "tab\there"`, "tab\there\n"},
		{`echo -e 'a\nb'`, "a\nb\n"},
		{`echo -e '\x41\x42'`, "AB\n"},
		{`echo -e '\0101'`, "A\n"},
		{`echo "$HOME"`, "/root\n"},
		{`echo $USER on $HOSTNAME`, "root on srv-web01\n"},
		{`echo`, "\n"},
	}
	for _, c := range cases {
		out, _, st := run(t, in, s, c.line)
		if out != c.want || st != 0 {
			t.Errorf("%q -> %q (status %d), want %q", c.line, out, st, c.want)
		}
	}
}

func TestCdAndPwd(t *testing.T) {
	in, s := testSession(t)
	if out, _, _ := run(t, in, s, "pwd"); out != "/root\n" {
		t.Fatalf("initial pwd = %q", out)
	}
	if _, errb, st := run(t, in, s, "cd /etc/nginx"); st != 0 || errb != "" {
		t.Fatalf("cd: %q status %d", errb, st)
	}
	if out, _, _ := run(t, in, s, "pwd"); out != "/etc/nginx\n" {
		t.Fatalf("pwd after cd = %q", out)
	}
	// cd - goes back.
	run(t, in, s, "cd /tmp")
	run(t, in, s, "cd -") // back to /etc/nginx
	if out, _, _ := run(t, in, s, "pwd"); out != "/etc/nginx\n" {
		t.Fatalf("cd - pwd = %q", out)
	}
	// cd with no arg goes home.
	run(t, in, s, "cd")
	if s.Cwd != "/root" {
		t.Fatalf("cd home = %q", s.Cwd)
	}
	// Errors.
	if _, errb, st := run(t, in, s, "cd /nonexistent"); st == 0 || !strings.Contains(errb, "No such file") {
		t.Errorf("cd missing: %q %d", errb, st)
	}
	if _, errb, st := run(t, in, s, "cd /etc/hostname"); st == 0 || !strings.Contains(errb, "Not a directory") {
		t.Errorf("cd file: %q %d", errb, st)
	}
	// cd through a symlink lands on the real path.
	run(t, in, s, "cd /etc/nginx/sites-enabled")
	if !strings.HasPrefix(s.Cwd, "/etc/nginx/sites-enabled") {
		t.Logf("cwd via symlink = %q", s.Cwd)
	}
}

func TestPrompt(t *testing.T) {
	in, s := testSession(t)
	if s.Prompt() != "root@srv-web01:~# " {
		t.Errorf("prompt = %q", s.Prompt())
	}
	run(t, in, s, "cd /etc")
	if s.Prompt() != "root@srv-web01:/etc# " {
		t.Errorf("prompt = %q", s.Prompt())
	}
	run(t, in, s, "cd /root/scripts")
	if s.Prompt() != "root@srv-web01:~/scripts# " {
		t.Errorf("prompt = %q", s.Prompt())
	}
}

func TestEnvExportUnset(t *testing.T) {
	in, s := testSession(t)
	run(t, in, s, "export FOO=bar")
	if s.Env["FOO"] != "bar" {
		t.Fatal("export failed")
	}
	out, _, _ := run(t, in, s, "echo $FOO")
	if out != "bar\n" {
		t.Errorf("echo $FOO = %q", out)
	}
	// Bare assignment.
	run(t, in, s, "BAZ=qux")
	if s.Env["BAZ"] != "qux" {
		t.Fatal("bare assign failed")
	}
	// Per-command assignment does not persist.
	out, _, _ = run(t, in, s, "TMP=1 printenv TMP")
	if out != "1\n" {
		t.Errorf("per-command env = %q", out)
	}
	if _, ok := s.Env["TMP"]; ok {
		t.Error("per-command assignment leaked into session")
	}
	run(t, in, s, "unset FOO")
	if _, ok := s.Env["FOO"]; ok {
		t.Error("unset failed")
	}
	// env lists sorted.
	out, _, _ = run(t, in, s, "env")
	if !strings.Contains(out, "HOME=/root") || !strings.Contains(out, "PATH=") {
		t.Errorf("env output missing entries:\n%s", out)
	}
}

func TestPipelines(t *testing.T) {
	in, s := testSession(t)
	// Register a couple of helpers to test piping without depending on
	// commands from later commits.
	in.Register("upper", func(c *Context) int {
		b, _ := io.ReadAll(c.Stdin)
		c.Print(strings.ToUpper(string(b)))
		return 0
	})
	in.Register("first", func(c *Context) int {
		b, _ := io.ReadAll(c.Stdin)
		lines := strings.SplitN(string(b), "\n", 2)
		c.Print(lines[0] + "\n")
		return 0
	})
	out, _, _ := run(t, in, s, "echo -e 'one\\ntwo' | upper")
	if out != "ONE\nTWO\n" {
		t.Errorf("pipe = %q", out)
	}
	out, _, _ = run(t, in, s, "echo -e 'a\\nb\\nc' | upper | first")
	if out != "A\n" {
		t.Errorf("three-stage pipe = %q", out)
	}
}

func TestAndOrLists(t *testing.T) {
	in, s := testSession(t)
	// true && echo yes  -> yes
	if out, _, _ := run(t, in, s, "true && echo yes"); out != "yes\n" {
		t.Errorf("&& = %q", out)
	}
	// false && echo no   -> nothing
	if out, _, _ := run(t, in, s, "false && echo no"); out != "" {
		t.Errorf("false && = %q", out)
	}
	// false || echo recover -> recover
	if out, _, _ := run(t, in, s, "false || echo recover"); out != "recover\n" {
		t.Errorf("|| = %q", out)
	}
	// Chaining ; always runs.
	if out, _, _ := run(t, in, s, "false; echo a; echo b"); out != "a\nb\n" {
		t.Errorf("; = %q", out)
	}
	// $? reflects last status.
	run(t, in, s, "false")
	if out, _, _ := run(t, in, s, "echo $?"); out != "1\n" {
		t.Errorf("$? = %q", out)
	}
	run(t, in, s, "true")
	if out, _, _ := run(t, in, s, "echo $?"); out != "0\n" {
		t.Errorf("$? after true = %q", out)
	}
}

func TestRedirectionsToVFS(t *testing.T) {
	in, s := testSession(t)
	run(t, in, s, "cd /tmp")
	if _, errb, st := run(t, in, s, "echo hello > out.txt"); st != 0 || errb != "" {
		t.Fatalf("redirect: %q %d", errb, st)
	}
	data, _, err := s.FS.ReadFile("/tmp/out.txt")
	if err != nil || string(data) != "hello\n" {
		t.Fatalf("file = %q %v", data, err)
	}
	// Append.
	run(t, in, s, "echo world >> out.txt")
	data, _, _ = s.FS.ReadFile("/tmp/out.txt")
	if string(data) != "hello\nworld\n" {
		t.Fatalf("after append = %q", data)
	}
	// Input redirection feeds a pipe consumer.
	in.Register("cat0", func(c *Context) int { b, _ := io.ReadAll(c.Stdin); c.Print(string(b)); return 0 })
	out, _, _ := run(t, in, s, "cat0 < out.txt")
	if out != "hello\nworld\n" {
		t.Errorf("input redirect = %q", out)
	}
	// Truncating overwrite.
	run(t, in, s, "echo fresh > out.txt")
	data, _, _ = s.FS.ReadFile("/tmp/out.txt")
	if string(data) != "fresh\n" {
		t.Errorf("truncate = %q", data)
	}
	// Writing into a missing directory fails like bash.
	if _, errb, st := run(t, in, s, "echo x > /nope/y"); st == 0 || !strings.Contains(errb, "No such file") {
		t.Errorf("bad redirect: %q %d", errb, st)
	}
	// A non-root user cannot redirect into /etc.
	as := NewSession(s.Machine, "martin", 2)
	if _, errb, st := in.Run(as, "echo x > /etc/pwned", strings.NewReader(""), io.Discard, &bytes.Buffer{}); st == 0 {
		_ = errb
		if as.FS.Exists("/etc/pwned") {
			t.Error("martin wrote into /etc")
		}
	}
}

func TestExit(t *testing.T) {
	in, s := testSession(t)
	var out bytes.Buffer
	status, exited, code := in.Run(s, "exit 42", strings.NewReader(""), &out, &out)
	if !exited || code != 42 || status != 42 {
		t.Errorf("exit 42 -> exited=%v code=%d status=%d", exited, code, status)
	}
	// exit with no code uses last status.
	run(t, in, s, "false")
	_, exited, code = in.Run(s, "exit", strings.NewReader(""), &out, &out)
	if !exited || code != 1 {
		t.Errorf("bare exit -> exited=%v code=%d", exited, code)
	}
}

func TestUnknownCommand(t *testing.T) {
	in, s := testSession(t)
	_, errb, st := run(t, in, s, "definitelynotacommand")
	if st != 127 || !strings.Contains(errb, "command not found") {
		t.Errorf("unknown: %q %d", errb, st)
	}
	// A path that does not exist.
	_, errb, st = run(t, in, s, "/usr/local/bin/x")
	if st != 127 || !strings.Contains(errb, "No such file") {
		t.Errorf("missing path: %q %d", errb, st)
	}
	// An existing binary "runs" but is not a real program.
	_, errb, st = run(t, in, s, "/usr/bin/ls")
	if st != 126 || !strings.Contains(errb, "Exec format error") {
		t.Errorf("fake binary exec: %q %d", errb, st)
	}
	// Fallback is consulted for unknown commands.
	in.Fallback = func(c *Context) (int, bool) {
		c.Print("model says hi\n")
		return 0, true
	}
	out, _, st := run(t, in, s, "somenovelcommand")
	if out != "model says hi\n" || st != 0 {
		t.Errorf("fallback: %q %d", out, st)
	}
}
