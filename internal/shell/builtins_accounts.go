package shell

import (
	"io"
	"strings"
)

func (in *Interp) registerAccounts() {
	in.Register("passwd", cmdPasswd)
	in.Register("chpasswd", cmdChpasswd)
	in.Register("useradd", cmdUseradd)
	in.Register("adduser", cmdUseradd)
	in.Register("userdel", cmdUserdel)
	in.Register("deluser", cmdUserdel)
	in.Register("usermod", cmdUsermod)
	in.Register("groupadd", func(c *Context) int { return rootGate(c, "") })
	in.Register("groupdel", func(c *Context) int { return rootGate(c, "") })
	in.Register("chsh", func(c *Context) int { return 0 })
	in.Register("chfn", func(c *Context) int { return 0 })
	in.Register("ssh-keygen", cmdSSHKeygen)
	in.Register("kill", func(c *Context) int { return 0 })
	in.Register("killall", func(c *Context) int { return 0 })
	in.Register("pkill", func(c *Context) int { return 0 })
	in.Register("nohup", cmdNohup)
	in.Register("timeout", cmdTimeout)
	in.Register("wall", func(c *Context) int { io.Copy(io.Discard, c.Stdin); return 0 })
	in.Register("mesg", func(c *Context) int { c.Print("is y\n"); return 0 })
	in.Register("locale", cmdLocale)
	in.Register("getent", cmdGetent)
	in.Register("bc", func(c *Context) int { io.Copy(io.Discard, c.Stdin); return 0 })
	in.Register("reboot", func(c *Context) int { return rootGate(c, "") })
	in.Register("shutdown", func(c *Context) int { return rootGate(c, "") })
	in.Register("halt", func(c *Context) int { return rootGate(c, "") })
	in.Register("poweroff", func(c *Context) int { return rootGate(c, "") })
}

// rootGate returns 0 for root (a silent success, since we never actually
// change accounts) and a permission error otherwise.
func rootGate(c *Context, okMsg string) int {
	if !c.Sess.Cred.IsRoot() {
		c.Errorf("Permission denied.")
		return 1
	}
	if okMsg != "" {
		c.Print(okMsg)
	}
	return 0
}

func cmdPasswd(c *Context) int {
	target := c.Sess.User
	if len(c.Args) > 1 && !strings.HasPrefix(c.Args[len(c.Args)-1], "-") {
		target = c.Args[len(c.Args)-1]
	}
	if target != c.Sess.User && !c.Sess.Cred.IsRoot() {
		c.Errorf("You may not view or modify password information for %s.", target)
		return 1
	}
	// A real passwd prompts; over an automated session there is no tty
	// dialogue, so we behave like passwd fed from a pipe: consume stdin
	// and report success.
	io.Copy(io.Discard, c.Stdin)
	c.Printf("passwd: password updated successfully\n")
	return 0
}

func cmdChpasswd(c *Context) int {
	if !c.Sess.Cred.IsRoot() {
		c.Errorf("Permission denied.")
		return 1
	}
	// chpasswd reads user:password lines from stdin. Consume them (this is
	// exactly the "root:newpass" line droppers pipe in) and succeed.
	io.Copy(io.Discard, c.Stdin)
	return 0
}

func cmdUseradd(c *Context) int {
	if !c.Sess.Cred.IsRoot() {
		c.Errorf("Permission denied.")
		return 1
	}
	// We accept the request and succeed, but do not really add the user;
	// the transcript is what matters.
	return 0
}

func cmdUserdel(c *Context) int { return rootGate(c, "") }

func cmdUsermod(c *Context) int {
	if !c.Sess.Cred.IsRoot() {
		c.Errorf("Permission denied.")
		return 1
	}
	return 0
}

func cmdSSHKeygen(c *Context) int {
	// The common hostile use is `ssh-keygen -A` or generating a key to add
	// to authorized_keys. We report a plausible success.
	for _, a := range c.Args[1:] {
		if a == "-A" {
			return 0
		}
	}
	fp := "SHA256:" + base64ish("keygen"+c.Sess.User, 43)
	c.Print("Generating public/private ed25519 key pair.\n")
	c.Printf("Your identification has been saved in %s/.ssh/id_ed25519\n", c.Sess.Env["HOME"])
	c.Printf("Your public key has been saved in %s/.ssh/id_ed25519.pub\n", c.Sess.Env["HOME"])
	c.Print("The key fingerprint is:\n")
	c.Printf("%s %s@%s\n", fp, c.Sess.User, c.Sess.Machine.Profile.Hostname)
	return 0
}

func cmdNohup(c *Context) int {
	if len(c.Args) < 2 {
		return 0
	}
	c.Errorf("ignoring input and appending output to 'nohup.out'")
	line := shellQuoteJoin(c.Args[1:])
	return c.Interp.run(c.Sess, line, c.Stdin, c.Stdout, c.Stderr)
}

func cmdTimeout(c *Context) int {
	// timeout DURATION CMD...: drop the duration, run the command.
	args := c.Args[1:]
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if args[i] == "-s" || args[i] == "--signal" {
			i++
		}
		i++
	}
	if i < len(args) {
		i++ // skip the duration
	}
	if i >= len(args) {
		return 0
	}
	return c.Interp.run(c.Sess, shellQuoteJoin(args[i:]), c.Stdin, c.Stdout, c.Stderr)
}

func cmdLocale(c *Context) int {
	vars := []string{"LANG", "LANGUAGE", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY",
		"LC_MESSAGES", "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION", "LC_ALL"}
	lang := c.Getenv("LANG")
	for _, v := range vars {
		switch v {
		case "LANG":
			c.Printf("LANG=%s\n", lang)
		case "LANGUAGE":
			c.Print("LANGUAGE=\n")
		case "LC_ALL":
			c.Print("LC_ALL=\n")
		default:
			c.Printf("%s=\"%s\"\n", v, lang)
		}
	}
	return 0
}

func cmdGetent(c *Context) int {
	if len(c.Args) < 2 {
		return 1
	}
	db := c.Args[1]
	var file string
	switch db {
	case "passwd":
		file = "/etc/passwd"
	case "group":
		file = "/etc/group"
	case "hosts":
		file = "/etc/hosts"
	case "shadow":
		file = "/etc/shadow"
	default:
		return 2
	}
	data, err := c.readTarget(file)
	if err != nil {
		return 2
	}
	keys := c.Args[2:]
	if len(keys) == 0 {
		c.Stdout.Write(data)
		return 0
	}
	found := 2
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) == 0 || line == "" {
			continue
		}
		for _, k := range keys {
			if f[0] == k {
				c.Print(line + "\n")
				found = 0
			}
		}
	}
	return found
}
