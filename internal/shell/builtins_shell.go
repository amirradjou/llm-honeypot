package shell

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

// bashBuiltins is bash 5.1's builtin list, in the order `enable` prints it.
var bashBuiltins = []string{".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller", "cd", "command",
	"compgen", "complete", "compopt", "continue", "declare", "dirs", "disown", "echo", "enable", "eval", "exec",
	"exit", "export", "false", "fc", "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let", "local",
	"logout", "mapfile", "popd", "printf", "pushd", "pwd", "read", "readarray", "readonly", "return", "set",
	"shift", "shopt", "source", "suspend", "test", "times", "trap", "true", "type", "typeset", "ulimit", "umask",
	"unalias", "unset", "wait"}

var bashKeywords = []string{"!", "[[", "]]", "case", "coproc", "do", "done", "elif", "else", "esac", "fi", "for",
	"function", "if", "in", "select", "then", "time", "until", "while", "{", "}"}

var builtinSet, keywordSet = toSet(bashBuiltins), toSet(bashKeywords)

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func isBashBuiltin(name string) bool { return builtinSet[name] }

// declBuiltins take NAME=value arguments that expand like assignments.
var declBuiltins = map[string]bool{"export": true, "local": true, "declare": true, "typeset": true, "readonly": true}

// registerShell registers the builtins that drive the shell itself.
func (in *Interp) registerShell() {
	in.Register("type", cmdType)
	in.Register("command", cmdCommand)
	in.Register("builtin", cmdBuiltin)
	in.Register("enable", cmdEnable)
	in.Register("ulimit", cmdUlimit)
	in.Register("eval", cmdEval)
	in.Register("read", cmdRead)
	in.Register("source", cmdSource)
	in.Register(".", cmdSource)
	in.Register("exec", cmdExec)
	in.Register("break", cmdBreak)
	in.Register("continue", cmdBreak)
	in.Register("return", cmdReturn)
	in.Register("shift", cmdShift)
	in.Register("local", cmdLocal)
	in.Register("declare", cmdDeclare)
	in.Register("typeset", cmdDeclare)
	in.Register("readonly", cmdDeclare)
	in.Register("let", cmdLet)
	in.Register("hash", cmdHash)
	in.Register("times", func(c *Context) int { c.Print("0m0.004s 0m0.002s\n0m0.000s 0m0.000s\n"); return 0 })
	for _, name := range []string{"trap", "wait", "jobs", "shopt", "disown", "bind", "caller", "compgen",
		"complete", "compopt", "getopts", "suspend", "fc", "mapfile", "readarray", "dirs", "pushd", "popd", "help"} {
		in.Register(name, func(*Context) int { return 0 })
	}
	in.Register("bg", cmdNoJobControl)
	in.Register("fg", cmdNoJobControl)
}

func cmdNoJobControl(c *Context) int {
	if c.shell().interactive {
		c.shellErrorf("current: no such job")
	} else {
		c.shellErrorf("no job control")
	}
	return 1
}

// optArgs splits leading -abc option clusters off args.
func optArgs(args []string) (opts string, rest []string) {
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' {
		if args[0] == "--" {
			return opts, args[1:]
		}
		opts += args[0][1:]
		args = args[1:]
	}
	return opts, args
}

// whatIs classifies a command name the way type and command -v do.
func (sh *shell) whatIs(name string) (kind, where string) {
	switch {
	case keywordSet[name]:
		return "keyword", ""
	case sh.s.funcs[name] != nil:
		return "function", ""
	case isBashBuiltin(name):
		return "builtin", ""
	}
	if p, ok := sh.s.hashed[name]; ok {
		return "hashed", p
	}
	if strings.ContainsRune(name, '/') {
		abs := sh.s.abs(name)
		if info, err := sh.s.FS.Stat(abs); err == nil && !info.IsDir() && permit(sh.s, abs, 'x') {
			return "file", name
		}
		return "", ""
	}
	if p := sh.lookPath(name); p != "" {
		return "file", p
	}
	if sh.in.Has(name) {
		return "file", "/usr/bin/" + name
	}
	return "", ""
}

// allPaths lists every executable called name on $PATH (type -a).
func (sh *shell) allPaths(name string) []string {
	var out []string
	pathVar, _ := sh.getVar("PATH")
	for _, dir := range strings.Split(pathVar, ":") {
		if dir == "" {
			dir = "."
		}
		p := strings.TrimSuffix(dir, "/") + "/" + name
		abs := sh.s.abs(p)
		if info, err := sh.s.FS.Stat(abs); err == nil && !info.IsDir() && permit(sh.s, abs, 'x') {
			out = append(out, p)
		}
	}
	return out
}

func cmdType(c *Context) int {
	sh := c.shell()
	opts, names := optArgs(c.Args[1:])
	for _, r := range opts {
		if !strings.ContainsRune("afptP", r) {
			c.shellErrorf("-%c: invalid option", r)
			fmt.Fprintln(c.Stderr, "type: usage: type [-afptP] name [name ...]")
			return 2
		}
	}
	terse, pathOnly, forcePath, all, noFunc := strings.ContainsRune(opts, 't'), strings.ContainsRune(opts, 'p'),
		strings.ContainsRune(opts, 'P'), strings.ContainsRune(opts, 'a'), strings.ContainsRune(opts, 'f')
	status := 0
	for _, name := range names {
		found := false
		say := func(kind, verbose string) {
			found = true
			switch {
			case terse:
				c.Print(kind + "\n")
			case !pathOnly && !forcePath:
				c.Print(verbose)
			}
		}
		if !forcePath {
			if keywordSet[name] {
				say("keyword", name+" is a shell keyword\n")
			}
			if fn := sh.s.funcs[name]; fn != nil && !noFunc && (all || !found) {
				say("function", name+" is a function\n"+name+" () \n"+fn.src+"\n")
			}
			if isBashBuiltin(name) && (all || !found) {
				say("builtin", name+" is a shell builtin\n")
			}
		}
		if all || !found || forcePath {
			var paths []string
			hashed := ""
			if !all {
				if p, ok := sh.s.hashed[name]; ok {
					hashed = p
					paths = []string{p}
				}
			}
			if paths == nil {
				if strings.ContainsRune(name, '/') {
					if kind, p := sh.whatIs(name); kind == "file" {
						paths = []string{p}
					}
				} else {
					paths = sh.allPaths(name)
					if len(paths) == 0 && sh.in.Has(name) && !isBashBuiltin(name) {
						paths = []string{"/usr/bin/" + name}
					}
					if !all && len(paths) > 1 {
						paths = paths[:1]
					}
				}
			}
			for _, p := range paths {
				found = true
				switch {
				case terse:
					c.Print("file\n")
				case pathOnly || forcePath:
					c.Print(p + "\n")
				case hashed != "":
					c.Printf("%s is hashed (%s)\n", name, p)
				default:
					c.Printf("%s is %s\n", name, p)
				}
			}
		}
		if !found {
			status = 1
			if !terse && !pathOnly && !forcePath {
				c.shellErrorf("%s: not found", name)
			}
		}
	}
	return status
}

func cmdCommand(c *Context) int {
	sh := c.shell()
	opts, args := optArgs(c.Args[1:])
	for _, r := range opts {
		if !strings.ContainsRune("pvV", r) {
			c.shellErrorf("-%c: invalid option", r)
			fmt.Fprintln(c.Stderr, "command: usage: command [-pVv] command [arg ...]")
			return 2
		}
	}
	if len(args) == 0 {
		return 0
	}
	terse, verbose := strings.ContainsRune(opts, 'v'), strings.ContainsRune(opts, 'V')
	if !terse && !verbose {
		return sh.dispatch(args, c.Env, c.fdTable(), false)
	}
	status := 0
	for _, name := range args {
		kind, where := sh.whatIs(name)
		switch {
		case kind == "":
			status = 1
			if verbose {
				c.shellErrorf("%s: not found", name)
			}
		case terse && (kind == "file" || kind == "hashed"):
			c.Print(where + "\n")
		case terse:
			c.Print(name + "\n")
		case kind == "hashed":
			c.Printf("%s is hashed (%s)\n", name, where)
		case kind == "file":
			c.Printf("%s is %s\n", name, where)
		case kind == "function":
			c.Printf("%s is a function\n%s () \n%s\n", name, name, sh.s.funcs[name].src)
		default:
			c.Printf("%s is a shell %s\n", name, kind)
		}
	}
	return status
}

func cmdBuiltin(c *Context) int {
	if len(c.Args) < 2 {
		return 0
	}
	name := c.Args[1]
	if !isBashBuiltin(name) {
		c.shellErrorf("%s: not a shell builtin", name)
		return 1
	}
	return c.shell().dispatch(c.Args[1:], c.Env, c.fdTable(), false)
}

func cmdEnable(c *Context) int {
	opts, names := optArgs(c.Args[1:])
	if len(names) == 0 {
		if strings.ContainsRune(opts, 'n') {
			return 0 // nothing is disabled
		}
		for _, b := range bashBuiltins {
			c.Printf("enable %s\n", b)
		}
		return 0
	}
	status := 0
	for _, n := range names {
		if !isBashBuiltin(n) {
			c.shellErrorf("%s: not a shell builtin", n)
			status = 1
		}
	}
	return status
}

// ulimitRow is one resource in `ulimit -a`, in bash 5.1's order.
type ulimitRow struct {
	opt         byte
	desc, units string
	soft, hard  string // "" means computed from the machine
}

var ulimitRows = []ulimitRow{
	{'R', "real-time non-blocking time", "microseconds", "unlimited", "unlimited"},
	{'c', "core file size", "blocks", "0", "unlimited"},
	{'d', "data seg size", "kbytes", "unlimited", "unlimited"},
	{'e', "scheduling priority", "", "0", "0"},
	{'f', "file size", "blocks", "unlimited", "unlimited"},
	{'i', "pending signals", "", "", ""},
	{'l', "max locked memory", "kbytes", "8192", "8192"},
	{'m', "max memory size", "kbytes", "unlimited", "unlimited"},
	{'n', "open files", "", "1024", "1048576"},
	{'p', "pipe size", "512 bytes", "8", "8"},
	{'q', "POSIX message queues", "bytes", "819200", "819200"},
	{'r', "real-time priority", "", "0", "0"},
	{'s', "stack size", "kbytes", "8192", "unlimited"},
	{'t', "cpu time", "seconds", "unlimited", "unlimited"},
	{'u', "max user processes", "", "", ""},
	{'v', "virtual memory", "kbytes", "unlimited", "unlimited"},
	{'x', "file locks", "", "unlimited", "unlimited"},
}

func (r ulimitRow) value(s *Session, hard bool) string {
	key := string(r.opt)
	if hard {
		key = "H" + key
	}
	if v, ok := s.ulimits[key]; ok {
		return v
	}
	v := r.soft
	if hard {
		v = r.hard
	}
	if v == "" {
		// The kernel sizes the process and signal limits from memory.
		v = strconv.Itoa(s.Machine.Profile.MemMB * 4)
	}
	return v
}

func (r ulimitRow) line(s *Session, hard bool) string {
	unit := "(-" + string(r.opt) + ") "
	if r.units != "" {
		unit = "(" + r.units + ", -" + string(r.opt) + ") "
	}
	return fmt.Sprintf("%-20s %20s%s\n", r.desc, unit, r.value(s, hard))
}

func cmdUlimit(c *Context) int {
	s := c.Sess
	var res []byte
	hard, all := false, false
	var value string
	for _, a := range c.Args[1:] {
		if len(a) > 1 && a[0] == '-' {
			for i := 1; i < len(a); i++ {
				switch r := a[i]; r {
				case 'H':
					hard = true
				case 'S':
					hard = false
				case 'a':
					all = true
				default:
					if !strings.ContainsRune("Rcdefilmnpqrstuvx", rune(r)) {
						c.shellErrorf("-%c: invalid option", r)
						fmt.Fprintln(c.Stderr, "ulimit: usage: ulimit [-SHabcdefiklmnpqrstuvxPT] [limit]")
						return 2
					}
					res = append(res, r)
				}
			}
			continue
		}
		value = a
	}
	if all {
		for _, r := range ulimitRows {
			c.Print(r.line(s, hard))
		}
		return 0
	}
	if len(res) == 0 {
		res = []byte{'f'}
	}
	if value != "" {
		if _, err := strconv.ParseUint(value, 10, 63); err != nil && value != "unlimited" && value != "hard" && value != "soft" {
			c.shellErrorf("%s: invalid number", value)
			return 1
		}
		if s.ulimits == nil {
			s.ulimits = map[string]string{}
		}
		for _, r := range res {
			s.ulimits[string(r)] = value
			if hard {
				s.ulimits["H"+string(r)] = value
			}
		}
		return 0
	}
	for _, opt := range res {
		for _, r := range ulimitRows {
			if r.opt != opt {
				continue
			}
			if len(res) > 1 {
				c.Print(r.line(s, hard))
			} else {
				c.Print(r.value(s, hard) + "\n")
			}
		}
	}
	return 0
}

func cmdEval(c *Context) int {
	if len(c.Args) < 2 {
		return 0
	}
	return c.shell().evalString(strings.Join(c.Args[1:], " "), c.fdTable())
}

func cmdSource(c *Context) int {
	sh := c.shell()
	args := c.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		c.shellErrorf("filename argument required")
		fmt.Fprintf(c.Stderr, "%s: usage: %s filename [arguments]\n", c.Args[0], c.Args[0])
		return 2
	}
	file := args[0]
	p := file
	if !strings.ContainsRune(file, '/') {
		for _, cand := range sh.allPaths(file) {
			p = cand
			break
		}
	}
	abs := sh.s.abs(p)
	info, err := sh.s.FS.Stat(abs)
	switch {
	case err != nil:
		c.shellErrorf("%s: No such file or directory", file)
		return 1
	case info.IsDir():
		c.shellErrorf("%s: is a directory", file)
		return 1
	case !permit(sh.s, abs, 'r'):
		c.shellErrorf("%s: Permission denied", file)
		return 1
	}
	data, dinfo, err := sh.s.FS.ReadFile(abs)
	if err != nil || dinfo.Placeholder || looksBinary(data) {
		return 0 // nothing a shell could run
	}
	sh.enter(false)
	defer sh.leave()
	savedParams, savedSrc, savedBase := sh.params, sh.srcName, sh.lineBase
	if len(args) > 1 {
		sh.params = args[1:]
	}
	sh.srcName, sh.lineBase = file, 0
	sh.srcDepth++
	status := sh.runSource(string(data), c.fdTable())
	sh.srcDepth--
	sh.srcName, sh.lineBase = savedSrc, savedBase
	if len(args) > 1 {
		sh.params = savedParams
	}
	if sh.flow == flowReturn {
		sh.flow = flowNone
		status = sh.ret
	}
	return status
}

func isShellName(name string) bool {
	switch name {
	case "sh", "bash", "dash", "rbash", "ash":
		return true
	}
	return false
}

func cmdExec(c *Context) int {
	sh := c.shell()
	args := c.Args[1:]
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		if args[0] == "-a" && len(args) > 1 {
			args = args[1:]
		}
		args = args[1:]
	}
	if len(args) == 0 {
		return 0
	}
	if isShellName(path.Base(args[0])) && len(args) == 1 && sh.interactive {
		return 0 // the new interactive shell is this one
	}
	status := sh.dispatch(args, c.Env, c.fdTable(), false)
	if status == 127 && sh.interactive {
		return status
	}
	panic(exitSignal{code: status})
}

func cmdBreak(c *Context) int {
	sh := c.shell()
	n := 1
	if len(c.Args) > 1 {
		v, err := strconv.Atoi(c.Args[1])
		if err != nil {
			c.shellErrorf("%s: numeric argument required", c.Args[1])
			return 1
		}
		if v < 1 {
			c.shellErrorf("%d: loop count out of range", v)
			return 1
		}
		n = v
	}
	if sh.loopDepth == 0 {
		c.shellErrorf("only meaningful in a `for', `while', or `until' loop")
		return 0
	}
	sh.flow = flowBreak
	if c.Args[0] == "continue" {
		sh.flow = flowContinue
	}
	sh.flowN = min(n, sh.loopDepth)
	return 0
}

func cmdReturn(c *Context) int {
	sh := c.shell()
	n := sh.s.Status
	if len(c.Args) > 1 {
		v, err := strconv.Atoi(c.Args[1])
		if err != nil {
			c.shellErrorf("%s: numeric argument required", c.Args[1])
			v = 2
		}
		n = v & 0xff
	}
	if sh.funcDepth == 0 && sh.srcDepth == 0 {
		c.shellErrorf("can only `return' from a function or sourced script")
		return 1
	}
	sh.flow, sh.ret = flowReturn, n
	return n
}

func cmdShift(c *Context) int {
	sh := c.shell()
	n := 1
	if len(c.Args) > 1 {
		v, err := strconv.Atoi(c.Args[1])
		if err != nil || v < 0 {
			c.shellErrorf("%s: numeric argument required", c.Args[1])
			return 1
		}
		n = v
	}
	if n > len(sh.params) {
		return 1
	}
	sh.params = sh.params[n:]
	return 0
}

// assignArg applies a NAME=value / NAME+=value / NAME argument of a
// declaration builtin.
func assignArg(c *Context, a string, local bool) int {
	name, val, hasVal := strings.Cut(a, "=")
	add := strings.HasSuffix(name, "+")
	name = strings.TrimSuffix(name, "+")
	if !isName(name) {
		c.shellErrorf("`%s': not a valid identifier", a)
		return 1
	}
	sh := c.shell()
	if local {
		sh.declareLocal(name)
	}
	if hasVal {
		if add {
			old, _ := sh.getVar(name)
			val = old + val
		}
		sh.setVar(name, val)
	}
	return 0
}

func cmdLocal(c *Context) int {
	sh := c.shell()
	if sh.funcDepth == 0 {
		c.shellErrorf("can only be used in a function")
		return 1
	}
	_, args := optArgs(c.Args[1:])
	status := 0
	for _, a := range args {
		status |= assignArg(c, a, true)
	}
	return status
}

func cmdDeclare(c *Context) int {
	sh := c.shell()
	opts, args := optArgs(c.Args[1:])
	if strings.ContainsAny(opts, "fF") {
		names := make([]string, 0, len(sh.s.funcs))
		for n := range sh.s.funcs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if len(args) > 0 && !contains(args, n) {
				continue
			}
			if strings.ContainsRune(opts, 'F') {
				c.Printf("declare -f %s\n", n)
			} else {
				c.Printf("%s () \n%s\n", n, sh.s.funcs[n].src)
			}
		}
		return 0
	}
	if len(args) == 0 {
		if c.Args[0] == "readonly" {
			return 0
		}
		return cmdEnvSorted(c, "")
	}
	if strings.ContainsRune(opts, 'p') {
		status := 0
		for _, n := range args {
			v, ok := sh.getVar(n)
			if !ok {
				c.shellErrorf("%s: not found", n)
				status = 1
				continue
			}
			c.Printf("declare -- %s=%q\n", n, v)
		}
		return status
	}
	local := sh.funcDepth > 0 && c.Args[0] != "readonly" && !strings.ContainsRune(opts, 'g')
	status := 0
	for _, a := range args {
		status |= assignArg(c, a, local)
	}
	return status
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func cmdLet(c *Context) int {
	if len(c.Args) < 2 {
		c.shellErrorf("expression expected")
		return 1
	}
	sh := c.shell()
	var v int64
	for _, a := range c.Args[1:] {
		var err error
		if v, err = evalArith(a, shellEnv{sh, c.fdTable()}); err != nil {
			c.shellErrorf("%s", err)
			return 1
		}
	}
	return boolStatus(v != 0)
}

func cmdHash(c *Context) int {
	sh := c.shell()
	opts, names := optArgs(c.Args[1:])
	if strings.ContainsRune(opts, 'r') {
		sh.s.hashed = nil
		return 0
	}
	if len(names) == 0 {
		if len(sh.s.hashed) == 0 {
			c.Printf("%s: hash table empty\n", c.Args[0])
			return 0
		}
		keys := make([]string, 0, len(sh.s.hashed))
		for k := range sh.s.hashed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		c.Print("hits\tcommand\n")
		for _, k := range keys {
			c.Printf("   1\t%s\n", sh.s.hashed[k])
		}
		return 0
	}
	status := 0
	for _, n := range names {
		if isBashBuiltin(n) {
			continue
		}
		before := len(sh.s.hashed)
		sh.remember(n)
		if _, ok := sh.s.hashed[n]; !ok && len(sh.s.hashed) == before {
			c.shellErrorf("%s: not found", n)
			status = 1
		}
	}
	return status
}

// cmdRead implements read [-rs] [-d delim] [-n n] [-p prompt] [-t t]
// [-u fd] [name ...].
func cmdRead(c *Context) int {
	sh := c.shell()
	args := c.Args[1:]
	raw := false
	delim := byte('\n')
	limit := -1
	src := c.Stdin
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' {
		a := args[0]
		args = args[1:]
		if a == "--" {
			break
		}
	opts:
		for i := 1; i < len(a); i++ {
			opt := a[i]
			if strings.IndexByte("dnNptuai", opt) >= 0 {
				// Options with a value: the rest of this word, or the next.
				val := a[i+1:]
				if val == "" {
					if len(args) == 0 {
						c.shellErrorf("-%c: option requires an argument", opt)
						return 2
					}
					val, args = args[0], args[1:]
				}
				switch opt {
				case 'd':
					delim = 0
					if val != "" {
						delim = val[0]
					}
				case 'n', 'N':
					n, err := strconv.Atoi(val)
					if err != nil || n < 0 {
						c.shellErrorf("%s: invalid number", val)
						return 1
					}
					limit = n
				case 'u':
					fd, err := strconv.Atoi(val)
					t := c.fdTable()
					if err != nil || fd < 0 || fd > maxFd || !t.open[fd] || t.r[fd] == nil {
						c.shellErrorf("%s: invalid file descriptor specification", val)
						return 1
					}
					src = t.r[fd]
				case 'a':
					args = append([]string{val}, args...)
				}
				break opts
			}
			switch opt {
			case 'r':
				raw = true
			case 's', 'e':
			default:
				c.shellErrorf("-%c: invalid option", opt)
				fmt.Fprintln(c.Stderr, "read: usage: read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars] [-p prompt] [-t timeout] [-u fd] [name ...]")
				return 2
			}
		}
	}
	line, protected, eof := readShellLine(src, delim, limit, raw)
	names := args
	if len(names) == 0 {
		sh.setVar("REPLY", line)
		return boolStatus(!eof)
	}
	ifs, ok := c.Env["IFS"]
	if !ok {
		ifs, _ = sh.getVar("IFS")
	}
	for i, name := range names {
		if !isName(name) {
			c.shellErrorf("`%s': not a valid identifier", name)
			return 1
		}
		var v string
		if i == len(names)-1 {
			v = trimIFS(line, protected, ifs)
			line = ""
		} else {
			v, line, protected = nextIFSField(line, protected, ifs)
		}
		sh.setVar(name, v)
	}
	return boolStatus(!eof)
}

// readShellLine reads up to delim one byte at a time, so the rest of the
// input stays for the next command. Without -r a backslash escapes the
// next character (protected[i] marks those) and joins continued lines.
func readShellLine(r io.Reader, delim byte, limit int, raw bool) (string, []bool, bool) {
	var out []byte
	var protected []bool
	one := make([]byte, 1)
	readByte := func() (byte, bool) {
		if br, ok := r.(io.ByteReader); ok {
			b, err := br.ReadByte()
			return b, err == nil
		}
		if n, _ := r.Read(one); n == 1 {
			return one[0], true
		}
		return 0, false
	}
	for len(out) < 1<<20 && (limit < 0 || len(out) < limit) {
		b, ok := readByte()
		if !ok {
			return string(out), protected, true
		}
		if b == delim {
			return string(out), protected, false
		}
		if b == '\\' && !raw {
			n, ok := readByte()
			if !ok {
				return string(out), protected, true
			}
			if n == '\n' {
				continue
			}
			out = append(out, n)
			protected = append(protected, true)
			continue
		}
		out = append(out, b)
		protected = append(protected, false)
	}
	return string(out), protected, false
}

func isIFSWhite(c byte, ifs string) bool {
	return (c == ' ' || c == '\t' || c == '\n') && strings.IndexByte(ifs, c) >= 0
}

// nextIFSField splits the first field off line for read.
func nextIFSField(line string, prot []bool, ifs string) (string, string, []bool) {
	i := 0
	for i < len(line) && !prot[i] && isIFSWhite(line[i], ifs) {
		i++
	}
	start := i
	for i < len(line) && (prot[i] || strings.IndexByte(ifs, line[i]) < 0) {
		i++
	}
	field := line[start:i]
	// Consume the delimiter: whitespace, at most one other IFS character,
	// whitespace.
	for i < len(line) && !prot[i] && isIFSWhite(line[i], ifs) {
		i++
	}
	if i < len(line) && !prot[i] && strings.IndexByte(ifs, line[i]) >= 0 && !isIFSWhite(line[i], ifs) {
		i++
		for i < len(line) && !prot[i] && isIFSWhite(line[i], ifs) {
			i++
		}
	}
	return field, line[i:], prot[i:]
}

// trimIFS strips leading and trailing IFS whitespace for read's last name.
func trimIFS(line string, prot []bool, ifs string) string {
	i, j := 0, len(line)
	for i < j && !prot[i] && isIFSWhite(line[i], ifs) {
		i++
	}
	for j > i && !prot[j-1] && isIFSWhite(line[j-1], ifs) {
		j--
	}
	return line[i:j]
}

// runChildShell implements sh, bash and dash: a -c string, a script file
// or commands piped on stdin each run in a child shell.
func runChildShell(c *Context) int {
	sh := c.shell()
	base := path.Base(c.Args[0])
	dash := base == "sh" || base == "dash"
	args := c.Args[1:]
	cflag, sflag := false, false
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" || a == "-" {
			i++
			break
		}
		if len(a) < 2 || (a[0] != '-' && a[0] != '+') {
			break
		}
		if strings.HasPrefix(a, "--") {
			if a == "--rcfile" || a == "--init-file" {
				i++
			}
			continue
		}
		for _, r := range a[1:] {
			switch r {
			case 'c':
				cflag = true
			case 's':
				sflag = true
			case 'o', 'O':
				i++ // takes an option name
			}
		}
	}
	args = args[min(i, len(args)):]
	if cflag {
		if len(args) == 0 {
			if dash {
				fmt.Fprintf(c.Stderr, "%s: 0: -c requires an argument\n", base)
			} else {
				fmt.Fprintf(c.Stderr, "%s: -c: option requires an argument\n", base)
			}
			return 2
		}
		name0, params := c.Args[0], []string(nil)
		if len(args) > 1 {
			name0, params = args[1], args[2:]
		}
		child := sh.childShell(name0, params, dash)
		return child.isolate(func() int { return child.runScript(args[0], c) })
	}
	if len(args) > 0 && !sflag {
		return runScriptFile(c, sh, args[0], args[1:], dash)
	}
	// No script: the commands come on stdin (curl ... | sh).
	data, _ := io.ReadAll(io.LimitReader(c.Stdin, maxCapture))
	if len(bytes.TrimSpace(data)) == 0 || looksBinary(data) {
		return 0
	}
	child := sh.childShell(c.Args[0], args, dash)
	return child.isolate(func() int { return child.runScript(string(data), c) })
}

// runScriptFile runs `sh FILE`. A downloaded payload (or anything else
// that is not text) "runs" silently: there is nothing a shell could do
// with it, and printing its bytes as errors would give the game away.
func runScriptFile(c *Context, sh *shell, file string, params []string, dash bool) int {
	base := path.Base(c.Args[0])
	abs := sh.s.abs(file)
	cantOpen := func(why string, bashCode int) int {
		if dash {
			fmt.Fprintf(c.Stderr, "%s: 0: cannot open %s: %s\n", base, file, why)
			return 2
		}
		fmt.Fprintf(c.Stderr, "%s: %s: %s\n", base, file, why)
		return bashCode
	}
	info, err := sh.s.FS.Stat(abs)
	switch {
	case err != nil:
		if dash {
			return cantOpen("No such file", 2)
		}
		return cantOpen("No such file or directory", 127)
	case info.IsDir():
		return cantOpen("Is a directory", 126)
	case !permit(sh.s, abs, 'r'):
		return cantOpen("Permission denied", 126)
	}
	data, dinfo, err := sh.s.FS.ReadFile(abs)
	if err != nil || dinfo.Placeholder || looksBinary(data) {
		return 0
	}
	child := sh.childShell(file, params, dash)
	child.srcName = file
	return child.isolate(func() int { return child.runScript(string(data), c) })
}
