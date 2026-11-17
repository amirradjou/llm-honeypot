package shell

import (
	"strconv"
	"strings"
)

// registerCore registers shell built-ins that manage session state:
// navigation, environment, control flow and history.
func (in *Interp) registerCore() {
	in.Register("echo", cmdEcho)
	in.Register("pwd", cmdPwd)
	in.Register("cd", cmdCd)
	in.Register("true", func(*Context) int { return 0 })
	in.Register("false", func(*Context) int { return 1 })
	in.Register(":", func(*Context) int { return 0 })
	in.Register("export", cmdExport)
	in.Register("unset", cmdUnset)
	in.Register("env", cmdEnv)
	in.Register("printenv", cmdPrintenv)
	in.Register("set", cmdSet)
	in.Register("exit", cmdExit)
	in.Register("logout", cmdExit)
	in.Register("history", cmdHistory)
	in.Register("clear", func(c *Context) int { c.Print("\x1b[H\x1b[2J\x1b[3J"); return 0 })
	in.Register("umask", cmdUmask)
	in.Register("alias", func(*Context) int { return 0 })
	in.Register("unalias", func(*Context) int { return 0 })
	in.Register("test", cmdTest)
	in.Register("[", cmdTest)
	in.registerShell()
}

// exitSignal is panicked by `exit` (and a few fatal errors) and recovered
// where the shell process ends: Run, a subshell, or a child sh -c.
type exitSignal struct{ code int }

func cmdEcho(c *Context) int {
	args := c.Args[1:]
	interpret := false
	newline := true
	for len(args) > 0 && len(args[0]) > 1 && args[0][0] == '-' {
		flag := args[0]
		ok := true
		for _, r := range flag[1:] {
			if r != 'e' && r != 'n' && r != 'E' {
				ok = false
				break
			}
		}
		if !ok {
			break
		}
		if strings.ContainsRune(flag, 'n') {
			newline = false
		}
		if strings.ContainsRune(flag, 'e') {
			interpret = true
		}
		if strings.ContainsRune(flag, 'E') {
			interpret = false
		}
		args = args[1:]
	}
	s := strings.Join(args, " ")
	if interpret {
		s = expandEscapes(s)
	}
	c.Print(s)
	if newline {
		c.Print("\n")
	}
	return 0
}

// expandEscapes handles echo -e backslash escapes, including \xHH and \0NNN
// (the ones malware droppers use to write binaries with echo).
func expandEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'f':
			b.WriteByte(12)
		case 'v':
			b.WriteByte(11)
		case '\\':
			b.WriteByte('\\')
		case '0':
			// \0NNN octal, up to 3 digits
			j, val := i+1, 0
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				val = val*8 + int(s[j]-'0')
				j++
			}
			b.WriteByte(byte(val))
			i = j - 1
		case 'x':
			// \xHH hex, up to 2 digits
			j, val := i+1, 0
			for j < len(s) && j < i+3 && isHex(s[j]) {
				val = val*16 + hexVal(s[j])
				j++
			}
			if j > i+1 {
				b.WriteByte(byte(val))
				i = j - 1
			} else {
				b.WriteByte('\\')
				b.WriteByte('x')
			}
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func isHex(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}
func hexVal(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	default:
		return int(b-'A') + 10
	}
}

func cmdPwd(c *Context) int {
	c.Print(c.Sess.Cwd + "\n")
	return 0
}

func cmdCd(c *Context) int {
	s := c.Sess
	opts, args := optArgs(c.Args[1:])
	physical := strings.ContainsRune(opts, 'P')
	if len(args) > 1 {
		c.shellErrorf("too many arguments")
		return 1
	}
	home, ok := s.Env["HOME"]
	arg := home
	if len(args) == 1 {
		arg = args[0]
	} else if !ok {
		c.shellErrorf("HOME not set")
		return 1
	}
	if arg == "-" {
		old, ok := s.Env["OLDPWD"]
		if !ok || old == "" {
			c.shellErrorf("OLDPWD not set")
			return 1
		}
		arg = old
		c.Print(arg + "\n")
	}
	if arg == "" {
		return 0
	}
	target := s.abs(arg)
	info, err := s.FS.Stat(target)
	if err != nil {
		c.shellErrorf("%s: No such file or directory", arg)
		return 1
	}
	if !info.IsDir() {
		c.shellErrorf("%s: Not a directory", arg)
		return 1
	}
	if !permit(s, target, 'x') {
		c.shellErrorf("%s: Permission denied", arg)
		return 1
	}
	// Like bash, the new directory is the logical path (cd /bin; pwd
	// says /bin) unless -P asks for the physical one.
	if physical {
		target, _ = s.FS.RealPath(target)
	}
	s.Env["OLDPWD"] = s.Cwd
	s.Cwd = target
	s.Env["PWD"] = target
	return 0
}

func cmdExport(c *Context) int {
	opts, args := optArgs(c.Args[1:])
	if len(args) == 0 || strings.ContainsRune(opts, 'p') {
		env := effectiveEnv(c)
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			c.Printf("declare -x %s=%q\n", k, env[k])
		}
		return 0
	}
	if strings.ContainsAny(opts, "nf") {
		return 0
	}
	status := 0
	for _, a := range args {
		// export NAME with no value keeps the existing value.
		status |= assignArg(c, a, false)
	}
	return status
}

func cmdUnset(c *Context) int {
	opts, args := optArgs(c.Args[1:])
	funcs := strings.ContainsRune(opts, 'f')
	for _, a := range args {
		if funcs {
			delete(c.Sess.funcs, a)
			continue
		}
		if _, ok := c.Sess.Env[a]; !ok && !strings.ContainsRune(opts, 'v') {
			delete(c.Sess.funcs, a)
		}
		delete(c.Sess.Env, a)
		if a == "PATH" {
			c.Sess.hashed = nil
		}
	}
	return 0
}

func cmdEnv(c *Context) int { return cmdEnvSorted(c, "") }

func cmdPrintenv(c *Context) int {
	env := effectiveEnv(c)
	if len(c.Args) > 1 {
		v, ok := env[c.Args[1]]
		if !ok {
			return 1
		}
		c.Print(v + "\n")
		return 0
	}
	return cmdEnvSorted(c, "")
}

// effectiveEnv is the session environment overlaid with any per-command
// NAME=val assignments captured on the Context.
func effectiveEnv(c *Context) map[string]string {
	if c.Env != nil {
		return c.Env
	}
	return c.Sess.Env
}

func cmdEnvSorted(c *Context, prefix string) int {
	env := effectiveEnv(c)
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sortStrings(keys)
	for _, k := range keys {
		c.Printf("%s%s=%s\n", prefix, k, env[k])
	}
	return 0
}

func cmdSet(c *Context) int {
	// `set` with no args lists variables like env (bash lists shell vars too,
	// but env is close enough for a honeypot). Options are accepted
	// silently; `set -- a b` and `set a b` set the positional parameters.
	args := c.Args[1:]
	if len(args) == 0 {
		return cmdEnvSorted(c, "")
	}
	for len(args) > 0 {
		a := args[0]
		if a == "--" || a == "-" {
			c.shell().params = append([]string(nil), args[1:]...)
			return 0
		}
		if len(a) < 2 || (a[0] != '-' && a[0] != '+') {
			c.shell().params = append([]string(nil), args...)
			return 0
		}
		args = args[1:]
		if strings.ContainsRune(a, 'o') && len(args) > 0 {
			args = args[1:] // -o name
		}
	}
	return 0
}

func cmdExit(c *Context) int {
	code := c.Sess.Status
	if len(c.Args) > 1 {
		n, err := strconv.Atoi(c.Args[1])
		if err != nil {
			c.shellErrorf("%s: numeric argument required", c.Args[1])
			n = 2
		}
		code = n & 0xff
	}
	panic(exitSignal{code: code})
}

func cmdHistory(c *Context) int {
	opts, _ := optArgs(c.Args[1:])
	if strings.ContainsRune(opts, 'c') {
		c.Sess.History = nil
		return 0
	}
	if opts != "" {
		return 0 // -w, -a, -r, -d ...: nothing to show
	}
	for i, h := range c.Sess.History {
		c.Printf("%5d  %s\n", i+1, h)
	}
	return 0
}

func cmdUmask(c *Context) int {
	if len(c.Args) > 1 {
		if n, err := strconv.ParseInt(c.Args[1], 8, 32); err == nil {
			c.Sess.Umask = fsFileMode(n)
		}
		return 0
	}
	c.Printf("%04o\n", int(c.Sess.Umask))
	return 0
}
