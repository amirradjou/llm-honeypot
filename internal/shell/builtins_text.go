package shell

import (
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// registerText adds the text tools every Ubuntu server has and bot scripts
// lean on: awk, sed, base64, xargs. A missing awk is the quickest way to
// tell a honeypot from a real box.
func (in *Interp) registerText() {
	in.Register("awk", cmdAwk)
	in.Register("mawk", cmdAwk)
	in.Register("sed", cmdSed)
	in.Register("base64", cmdBase64)
	in.Register("xargs", cmdXargs)
}

// --- sed ---

const sedVersion = `sed (GNU sed) 4.8
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Jay Fenlason, Tom Lord, Ken Pizzini,
Paolo Bonzini, Jim Meyering, and Assaf Gordon.
`

type sedAddr struct {
	kind byte // 'n' line number, '$' last line, '/' regex
	line int
	re   *regexp.Regexp
}

type sedCmd struct {
	a1, a2  *sedAddr
	negate  bool
	name    byte // s y p d q = a i c
	re      *regexp.Regexp
	repl    string
	global  bool
	nth     int
	print   bool
	from    []rune
	to      []rune
	text    string
	inRange bool
}

type sedError struct{ msg string }

func (e sedError) Error() string { return e.msg }

func cmdSed(c *Context) int {
	var scripts []string
	var files []string
	quiet, inPlace, extended, separate := false, false, false, false
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--version":
			c.Print(sedVersion)
			return 0
		case a == "--help":
			c.Print("Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...\n")
			return 0
		case a == "-n" || a == "--quiet" || a == "--silent":
			quiet = true
		case a == "-e" || a == "--expression":
			if i+1 < len(args) {
				scripts = append(scripts, args[i+1])
				i++
			}
		case strings.HasPrefix(a, "--expression="):
			scripts = append(scripts, strings.TrimPrefix(a, "--expression="))
		case a == "-f":
			if i+1 < len(args) {
				data, err := c.readTarget(args[i+1])
				if err != nil {
					fmt.Fprintf(c.Stderr, "sed: couldn't open file %s: No such file or directory\n", args[i+1])
					return 1
				}
				scripts = append(scripts, string(data))
				i++
			}
		case a == "-E" || a == "-r" || a == "--regexp-extended":
			extended = true
		case a == "-s" || a == "--separate":
			separate = true
		case a == "-i" || strings.HasPrefix(a, "-i") || strings.HasPrefix(a, "--in-place"):
			inPlace, separate = true, true
		case strings.HasPrefix(a, "-") && len(a) > 1 && !strings.HasPrefix(a, "--"):
			// Bundled short flags such as -ne or -nE.
			for k, r := range a[1:] {
				switch r {
				case 'n':
					quiet = true
				case 'E', 'r':
					extended = true
				case 's':
					separate = true
				case 'i':
					inPlace, separate = true, true
				case 'e':
					if k == len(a)-2 && i+1 < len(args) {
						scripts = append(scripts, args[i+1])
						i++
					}
				}
			}
		default:
			files = append(files, a)
		}
	}
	if len(scripts) == 0 {
		if len(files) == 0 {
			fmt.Fprint(c.Stderr, "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...\n\n")
			return 1
		}
		scripts, files = []string{files[0]}, files[1:]
	}
	cmds, err := parseSed(strings.Join(scripts, "\n"), extended)
	if err != nil {
		fmt.Fprintf(c.Stderr, "sed: -e expression #1, char %d: %s\n", len(scripts[0]), err)
		return 1
	}
	if inPlace && len(files) == 0 {
		fmt.Fprint(c.Stderr, "sed: no input files\n")
		return 1
	}
	if len(files) == 0 {
		files = []string{"-"}
	}

	status := 0
	read := func(f string) ([]byte, bool) {
		if f == "-" {
			d, _ := io.ReadAll(c.Stdin)
			return d, true
		}
		d, err := c.readTarget(f)
		if err != nil {
			fmt.Fprintf(c.Stderr, "sed: can't read %s: No such file or directory\n", f)
			status = 2
			return nil, false
		}
		return d, true
	}
	if !separate {
		var all []byte
		for _, f := range files {
			if d, ok := read(f); ok {
				all = append(all, d...)
			}
		}
		out, _ := runSed(cmds, all, quiet)
		c.Print(out)
		return status
	}
	for _, f := range files {
		d, ok := read(f)
		if !ok {
			continue
		}
		for _, cmd := range cmds {
			cmd.inRange = false
		}
		out, _ := runSed(cmds, d, quiet)
		if !inPlace {
			c.Print(out)
			continue
		}
		abs := c.Sess.abs(f)
		info, err := c.FS().Stat(abs)
		mode := c.writeOpts()
		if err == nil {
			mode = vfs.WriteOptions{Mode: info.Mode.Perm(), UID: info.UID, GID: info.GID}
		}
		if err := c.FS().WriteFile(abs, []byte(out), mode); err != nil {
			fmt.Fprintf(c.Stderr, "sed: couldn't open temporary file %s: %s\n", f, vfs.Strerror(err))
			status = 4
		}
	}
	return status
}

func parseSed(script string, extended bool) ([]*sedCmd, error) {
	rs := []rune(script)
	i := 0
	var cmds []*sedCmd
	skipSpace := func() {
		for i < len(rs) && (rs[i] == ' ' || rs[i] == '\t') {
			i++
		}
	}
	readDelimited := func(delim rune) (string, error) {
		var b strings.Builder
		for i < len(rs) {
			r := rs[i]
			if r == '\\' && i+1 < len(rs) {
				if rs[i+1] == delim {
					b.WriteRune(delim)
				} else if rs[i+1] == 'n' {
					b.WriteRune('\n')
				} else {
					b.WriteRune('\\')
					b.WriteRune(rs[i+1])
				}
				i += 2
				continue
			}
			if r == delim {
				i++
				return b.String(), nil
			}
			b.WriteRune(r)
			i++
		}
		return "", sedError{"unterminated address regex"}
	}
	compile := func(p string, flagsI bool) (*regexp.Regexp, error) {
		re, err := compileRegex(p, extended, flagsI)
		if err != nil {
			return nil, sedError{"Invalid preceding regular expression"}
		}
		return re, nil
	}
	readAddr := func() (*sedAddr, error) {
		switch {
		case i < len(rs) && rs[i] >= '0' && rs[i] <= '9':
			j := i
			for j < len(rs) && rs[j] >= '0' && rs[j] <= '9' {
				j++
			}
			n, _ := strconv.Atoi(string(rs[i:j]))
			i = j
			return &sedAddr{kind: 'n', line: n}, nil
		case i < len(rs) && rs[i] == '$':
			i++
			return &sedAddr{kind: '$'}, nil
		case i < len(rs) && (rs[i] == '/' || rs[i] == '\\'):
			delim := '/'
			if rs[i] == '\\' && i+1 < len(rs) {
				delim = rs[i+1]
				i++
			}
			i++
			p, err := readDelimited(delim)
			if err != nil {
				return nil, err
			}
			ci := false
			if i < len(rs) && rs[i] == 'I' {
				ci = true
				i++
			}
			re, err := compile(p, ci)
			if err != nil {
				return nil, err
			}
			return &sedAddr{kind: '/', re: re}, nil
		}
		return nil, nil
	}
	for i < len(rs) {
		for i < len(rs) && (rs[i] == ' ' || rs[i] == '\t' || rs[i] == '\n' || rs[i] == ';') {
			i++
		}
		if i >= len(rs) {
			break
		}
		cmd := &sedCmd{}
		var err error
		if cmd.a1, err = readAddr(); err != nil {
			return nil, err
		}
		if cmd.a1 != nil && i < len(rs) && rs[i] == ',' {
			i++
			if cmd.a2, err = readAddr(); err != nil {
				return nil, err
			}
			if cmd.a2 == nil {
				return nil, sedError{"unexpected `,'"}
			}
		}
		skipSpace()
		if i < len(rs) && rs[i] == '!' {
			cmd.negate = true
			i++
			skipSpace()
		}
		if i >= len(rs) {
			return nil, sedError{"missing command"}
		}
		cmd.name = byte(rs[i])
		i++
		switch cmd.name {
		case 's':
			if i >= len(rs) {
				return nil, sedError{"unterminated `s' command"}
			}
			delim := rs[i]
			i++
			pat, err := readDelimited(delim)
			if err != nil {
				return nil, sedError{"unterminated `s' command"}
			}
			repl, err := readDelimited(delim)
			if err != nil {
				return nil, sedError{"unterminated `s' command"}
			}
			ci := false
			for i < len(rs) && strings.ContainsRune("gpiI0123456789", rs[i]) {
				switch r := rs[i]; {
				case r == 'g':
					cmd.global = true
				case r == 'p':
					cmd.print = true
				case r == 'i' || r == 'I':
					ci = true
				default:
					cmd.nth = cmd.nth*10 + int(r-'0')
				}
				i++
			}
			if cmd.re, err = compile(pat, ci); err != nil {
				return nil, err
			}
			cmd.repl = repl
		case 'y':
			if i >= len(rs) {
				return nil, sedError{"unterminated `y' command"}
			}
			delim := rs[i]
			i++
			from, err := readDelimited(delim)
			if err != nil {
				return nil, sedError{"unterminated `y' command"}
			}
			to, err := readDelimited(delim)
			if err != nil {
				return nil, sedError{"unterminated `y' command"}
			}
			cmd.from, cmd.to = []rune(from), []rune(to)
			if len(cmd.from) != len(cmd.to) {
				return nil, sedError{"strings for `y' command are different lengths"}
			}
		case 'a', 'i', 'c':
			// GNU one-liner form: "a text" or "a\" followed by text.
			if i < len(rs) && rs[i] == '\\' {
				i++
				if i < len(rs) && rs[i] == '\n' {
					i++
				}
			}
			skipSpace()
			j := i
			for j < len(rs) && rs[j] != '\n' {
				j++
			}
			cmd.text = string(rs[i:j])
			i = j
		case 'p', 'd', 'q', '=', 'Q':
		default:
			return nil, sedError{fmt.Sprintf("unknown command: `%c'", cmd.name)}
		}
		cmds = append(cmds, cmd)
	}
	return cmds, nil
}

func (a *sedAddr) matches(n int, last bool, line string) bool {
	switch a.kind {
	case 'n':
		return n == a.line
	case '$':
		return last
	}
	return a.re.MatchString(line)
}

func (cmd *sedCmd) selects(n int, last bool, line string) bool {
	sel := true
	switch {
	case cmd.a1 == nil:
	case cmd.a2 == nil:
		sel = cmd.a1.matches(n, last, line)
	case cmd.inRange:
		if cmd.a2.kind == 'n' && n >= cmd.a2.line || cmd.a2.kind != 'n' && cmd.a2.matches(n, last, line) {
			cmd.inRange = false
		}
	case cmd.a1.matches(n, last, line):
		cmd.inRange = !(cmd.a2.kind == 'n' && cmd.a2.line <= n) && !(cmd.a2.kind == '$' && last)
	default:
		sel = false
	}
	return sel != cmd.negate
}

// runSed applies a parsed script to data and returns the output text.
func runSed(cmds []*sedCmd, data []byte, quiet bool) (string, bool) {
	text := string(data)
	trailingNL := strings.HasSuffix(text, "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" && len(data) == 0 {
		return "", false
	}
	lines := strings.Split(text, "\n")
	var out strings.Builder
	for n, line := range lines {
		last := n == len(lines)-1
		var before, after []string
		deleted, quit := false, false
		for _, cmd := range cmds {
			if !cmd.selects(n+1, last, line) {
				continue
			}
			switch cmd.name {
			case 's':
				line = sedSubstitute(cmd, line, &out)
			case 'y':
				line = strings.Map(func(r rune) rune {
					for k, f := range cmd.from {
						if f == r {
							return cmd.to[k]
						}
					}
					return r
				}, line)
			case 'p':
				out.WriteString(line + "\n")
			case 'd':
				deleted = true
			case '=':
				out.WriteString(strconv.Itoa(n+1) + "\n")
			case 'a':
				after = append(after, cmd.text)
			case 'i':
				before = append(before, cmd.text)
			case 'c':
				before = append(before, cmd.text)
				deleted = true
			case 'q':
				quit = true
			case 'Q':
				return out.String(), true
			}
			if deleted || quit {
				break
			}
		}
		for _, b := range before {
			out.WriteString(b + "\n")
		}
		if !deleted && !quiet {
			out.WriteString(line)
			if !last || trailingNL || len(after) > 0 {
				out.WriteString("\n")
			}
		}
		for _, a := range after {
			out.WriteString(a + "\n")
		}
		if quit {
			return out.String(), true
		}
	}
	return out.String(), false
}

func sedSubstitute(cmd *sedCmd, line string, out *strings.Builder) string {
	var b strings.Builder
	last := 0
	replaced := false
	for k, m := range cmd.re.FindAllStringSubmatchIndex(line, -1) {
		n := k + 1
		want := n == cmd.nth
		switch {
		case cmd.nth == 0:
			want = cmd.global || n == 1
		case cmd.global:
			want = n >= cmd.nth
		}
		if !want {
			continue
		}
		sub := make([]string, len(m)/2)
		for g := range sub {
			if m[2*g] >= 0 {
				sub[g] = line[m[2*g]:m[2*g+1]]
			}
		}
		b.WriteString(line[last:m[0]])
		b.WriteString(sedExpand(cmd.repl, sub))
		last = m[1]
		replaced = true
	}
	if !replaced {
		return line
	}
	b.WriteString(line[last:])
	res := b.String()
	if cmd.print {
		out.WriteString(res + "\n")
	}
	return res
}

// sedExpand fills a replacement: & is the match, \1-\9 the groups.
func sedExpand(repl string, sub []string) string {
	var b strings.Builder
	for i := 0; i < len(repl); i++ {
		ch := repl[i]
		switch {
		case ch == '&':
			if len(sub) > 0 {
				b.WriteString(sub[0])
			}
		case ch == '\\' && i+1 < len(repl):
			i++
			n := repl[i]
			switch {
			case n >= '1' && n <= '9':
				if k := int(n - '0'); k < len(sub) {
					b.WriteString(sub[k])
				}
			case n == 'n':
				b.WriteByte('\n')
			case n == 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(n)
			}
		default:
			b.WriteByte(ch)
		}
	}
	return b.String()
}

// --- base64 ---

func cmdBase64(c *Context) int {
	decode := false
	wrap := 76
	var file string
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--version":
			c.Print("base64 (GNU coreutils) 8.32\n")
			return 0
		case a == "-d" || a == "--decode" || a == "-di" || a == "-id":
			decode = true
		case a == "-i" || a == "--ignore-garbage":
		case a == "-w" && i+1 < len(args):
			wrap, _ = strconv.Atoi(args[i+1])
			i++
		case strings.HasPrefix(a, "-w"):
			wrap, _ = strconv.Atoi(a[2:])
		case strings.HasPrefix(a, "--wrap="):
			wrap, _ = strconv.Atoi(strings.TrimPrefix(a, "--wrap="))
		case strings.HasPrefix(a, "-") && a != "-":
			fmt.Fprintf(c.Stderr, "base64: invalid option -- '%s'\nTry 'base64 --help' for more information.\n", strings.TrimLeft(a, "-"))
			return 1
		default:
			file = a
		}
	}
	var data []byte
	if file == "" || file == "-" {
		data, _ = io.ReadAll(c.Stdin)
	} else {
		d, err := c.readTarget(file)
		if err != nil {
			fmt.Fprintf(c.Stderr, "base64: %s: No such file or directory\n", file)
			return 1
		}
		data = d
	}
	if decode {
		clean := strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
				return -1
			}
			return r
		}, string(data))
		out, err := base64.StdEncoding.DecodeString(clean)
		if err != nil {
			if out, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "=")); err != nil {
				fmt.Fprint(c.Stderr, "base64: invalid input\n")
				return 1
			}
		}
		c.Stdout.Write(out)
		return 0
	}
	enc := base64.StdEncoding.EncodeToString(data)
	if wrap > 0 {
		for len(enc) > wrap {
			c.Print(enc[:wrap] + "\n")
			enc = enc[wrap:]
		}
	}
	c.Print(enc)
	if wrap > 0 && len(data) > 0 {
		c.Print("\n")
	}
	return 0
}

// --- xargs ---

// maxXargsRuns bounds how many command invocations one xargs may make.
const maxXargsRuns = 1000

func cmdXargs(c *Context) int {
	args := c.Args[1:]
	noRunEmpty, trace, nulSep := false, false, false
	maxArgs := 0
	replace := ""
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-" {
		a := args[0]
		args = args[1:]
		switch {
		case a == "--":
			goto cmd
		case a == "-r" || a == "--no-run-if-empty":
			noRunEmpty = true
		case a == "-t" || a == "--verbose":
			trace = true
		case a == "-0" || a == "--null":
			nulSep = true
		case a == "-n" && len(args) > 0:
			maxArgs, _ = strconv.Atoi(args[0])
			args = args[1:]
		case strings.HasPrefix(a, "-n"):
			maxArgs, _ = strconv.Atoi(a[2:])
		case a == "-I" && len(args) > 0:
			replace, args = args[0], args[1:]
		case strings.HasPrefix(a, "-I"):
			replace = a[2:]
		case a == "-i":
			replace = "{}"
		case a == "-P" || a == "-L" || a == "-s" || a == "-d" || a == "-E":
			if len(args) > 0 {
				args = args[1:]
			}
		case strings.HasPrefix(a, "-P") || strings.HasPrefix(a, "-L"):
		case a == "--version":
			c.Print("xargs (GNU findutils) 4.8.0\n")
			return 0
		default:
			fmt.Fprintf(c.Stderr, "xargs: invalid option -- '%s'\n", strings.TrimLeft(a, "-"))
			return 1
		}
	}
cmd:
	command := args
	if len(command) == 0 {
		command = []string{"echo"}
	}
	data, _ := io.ReadAll(c.Stdin)
	var items []string
	switch {
	case nulSep:
		for _, s := range strings.Split(string(data), "\x00") {
			if s != "" {
				items = append(items, s)
			}
		}
	case replace != "":
		for _, s := range strings.Split(string(data), "\n") {
			if s = strings.TrimSpace(s); s != "" {
				items = append(items, s)
			}
		}
	default:
		items = splitXargs(string(data))
	}

	var batches [][]string
	switch {
	case replace != "":
		for _, it := range items {
			var argv []string
			for _, w := range command {
				argv = append(argv, strings.ReplaceAll(w, replace, it))
			}
			batches = append(batches, argv)
		}
	case maxArgs > 0:
		for k := 0; k < len(items); k += maxArgs {
			batches = append(batches, append(append([]string{}, command...), items[k:min(k+maxArgs, len(items))]...))
		}
	case len(items) > 0:
		batches = append(batches, append(append([]string{}, command...), items...))
	}
	if len(batches) == 0 && !noRunEmpty && replace == "" {
		batches = append(batches, command)
	}

	status := 0
	for k, argv := range batches {
		if k >= maxXargsRuns {
			break
		}
		if trace {
			fmt.Fprintln(c.Stderr, strings.Join(argv, " "))
		}
		code, _, _ := c.Interp.Run(c.Sess, shellQuoteJoin(argv), strings.NewReader(""), c.Stdout, c.Stderr)
		switch {
		case code == 127:
			return 127
		case code == 126:
			return 126
		case code != 0:
			status = 123
		}
	}
	return status
}

// splitXargs splits input on blanks and newlines, honouring simple quotes
// and backslashes the way xargs does.
func splitXargs(s string) []string {
	var out []string
	var b strings.Builder
	inWord := false
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				out = append(out, b.String())
				b.Reset()
				inWord = false
			}
		default:
			b.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		out = append(out, b.String())
	}
	return out
}
