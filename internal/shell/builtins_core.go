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
}

// ErrExit is returned via the session when `exit` runs, so the caller
// (the pty loop) can close the connection. We signal it with a status
// field rather than an error to keep Command simple.
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
	target := s.Env["HOME"]
	if len(c.Args) > 1 {
		arg := c.Args[1]
		if arg == "-" {
			arg = s.Env["OLDPWD"]
			if arg == "" {
				c.Errorf("OLDPWD not set")
				return 1
			}
			c.Print(arg + "\n")
		}
		target = s.abs(arg)
	}
	info, err := s.FS.Stat(target)
	if err != nil {
		c.Errorf("%s: No such file or directory", argOr(c, s.Env["HOME"]))
		return 1
	}
	if !info.IsDir() {
		c.Errorf("%s: Not a directory", c.Args[len(c.Args)-1])
		return 1
	}
	if !permit(s, target, 'x') {
		c.Errorf("%s: Permission denied", c.Args[len(c.Args)-1])
		return 1
	}
	real, _ := s.FS.RealPath(target)
	s.Env["OLDPWD"] = s.Cwd
	s.Cwd = real
	s.Env["PWD"] = real
	return 0
}

func argOr(c *Context, def string) string {
	if len(c.Args) > 1 {
		return c.Args[1]
	}
	return def
}

func cmdExport(c *Context) int {
	if len(c.Args) == 1 {
		return cmdEnvSorted(c, "declare -x ")
	}
	for _, a := range c.Args[1:] {
		if name, val, ok := strings.Cut(a, "="); ok {
			c.Sess.Env[name] = val
		}
		// export NAME with no value keeps the existing value; nothing to do.
	}
	return 0
}

func cmdUnset(c *Context) int {
	for _, a := range c.Args[1:] {
		delete(c.Sess.Env, a)
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
	// but env is close enough for a honeypot). Options are accepted silently.
	if len(c.Args) > 1 {
		return 0
	}
	return cmdEnvSorted(c, "")
}

func cmdExit(c *Context) int {
	code := c.Sess.Status
	if len(c.Args) > 1 {
		if n, err := strconv.Atoi(c.Args[1]); err == nil {
			code = n & 0xff
		}
	}
	panic(exitSignal{code: code})
}

func cmdHistory(c *Context) int {
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
