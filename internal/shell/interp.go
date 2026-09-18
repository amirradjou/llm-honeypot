package shell

import (
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// Command is one shell command. It reads Args and the streams on ctx and
// returns an exit status. It must never touch the real OS.
type Command func(ctx *Context) int

// Context is what a Command runs against.
type Context struct {
	Sess   *Session
	Interp *Interp
	Args   []string // Args[0] is the command name
	Env    map[string]string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Getenv reads the effective environment (command assignments over session).
func (c *Context) Getenv(name string) string {
	if c.Env != nil {
		if v, ok := c.Env[name]; ok {
			return v
		}
	}
	return c.Sess.Env[name]
}

// Printf/Print write to stdout; Errorf writes a "cmd: msg" line to stderr.
func (c *Context) Printf(format string, a ...any) { fmt.Fprintf(c.Stdout, format, a...) }
func (c *Context) Print(s string)                 { io.WriteString(c.Stdout, s) }
func (c *Context) Errorf(format string, a ...any) {
	fmt.Fprintf(c.Stderr, c.Args[0]+": "+format+"\n", a...)
}

// FS is the session's filesystem.
func (c *Context) FS() *vfs.FS { return c.Sess.FS }

// Interp holds the command table and optional hooks.
type Interp struct {
	cmds map[string]Command
	// Fallback handles a command with no registered builtin. It returns the
	// exit status and whether it handled the command; when it returns false
	// (or is nil) the shell prints "command not found". This is where the
	// model-driven output plugs in.
	Fallback func(ctx *Context) (int, bool)
	// Hook, if set, is called for every command just before it runs, for
	// recording. It must not modify ctx.
	Hook func(ctx *Context)
	// FileContent, if set, generates the contents of a placeholder file on
	// first read (the model backing store). It returns the bytes and whether
	// it handled the file; false falls back to empty.
	FileContent func(ctx *Context, path string, info vfs.Info) ([]byte, bool)
}

// New returns an interpreter with all built-in commands registered.
func New() *Interp {
	in := &Interp{cmds: map[string]Command{}}
	in.registerCore()
	in.registerFiles()
	in.registerSystem()
	in.registerNet()
	in.registerAccounts()
	return in
}

// Register adds or overrides a command. Used by tests and by New's groups.
func (in *Interp) Register(name string, cmd Command) { in.cmds[name] = cmd }

// Has reports whether name is a registered builtin.
func (in *Interp) Has(name string) bool { _, ok := in.cmds[name]; return ok }

// Names returns the registered command names, sorted.
func (in *Interp) Names() []string {
	out := make([]string, 0, len(in.cmds))
	for n := range in.cmds {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ErrExit reports that the attacker asked to end the shell (exit/logout).
// The pty loop uses Code to set the SSH exit status and close the session.
type ErrExit struct{ Code int }

func (e ErrExit) Error() string { return "exit" }

// Run parses and executes one command line, returning the exit status. If
// the line ran `exit`/`logout`, it returns exited=true with the code.
func (in *Interp) Run(s *Session, line string, stdin io.Reader, stdout, stderr io.Writer) (status int, exited bool, exitCode int) {
	defer func() {
		if r := recover(); r != nil {
			if sig, ok := r.(exitSignal); ok {
				exited = true
				exitCode = sig.code
				status = sig.code
				s.Status = sig.code
				return
			}
			panic(r)
		}
	}()
	return in.run(s, line, stdin, stdout, stderr), false, 0
}

func (in *Interp) run(s *Session, line string, stdin io.Reader, stdout, stderr io.Writer) int {
	exp := sessionExpander{s: s, status: s.Status}
	ao, err := Parse(line, exp)
	if err != nil {
		fmt.Fprintf(stderr, "-bash: %s\n", err)
		s.Status = 2
		return 2
	}
	if len(ao.Pipelines) == 0 {
		return s.Status
	}
	status := in.execList(s, ao, stdin, stdout, stderr)
	s.Status = status
	return status
}

// execList runs the pipelines honouring &&, || and ;.
func (in *Interp) execList(s *Session, ao *AndOr, stdin io.Reader, stdout, stderr io.Writer) int {
	status := s.Status
	skip := false
	for i, pl := range ao.Pipelines {
		if i > 0 {
			switch ao.Ops[i-1] {
			case "&&":
				skip = status != 0
			case "||":
				skip = status == 0
			case ";":
				skip = false
			}
		}
		if skip {
			continue
		}
		status = in.execPipeline(s, pl, stdin, stdout, stderr)
		s.Status = status
	}
	return status
}

// execPipeline chains commands with buffers: cmd[i] stdout feeds cmd[i+1]
// stdin. The pipeline's exit status is the last command's. Running
// sequentially is fine here because command output is small and bounded.
func (in *Interp) execPipeline(s *Session, pl *Pipeline, stdin io.Reader, stdout, stderr io.Writer) int {
	n := len(pl.Cmds)
	if n == 0 {
		return 0
	}
	var status int
	curIn := stdin
	for i, c := range pl.Cmds {
		var out io.Writer
		var buf *bytes.Buffer
		if i == n-1 {
			out = stdout
		} else {
			buf = &bytes.Buffer{}
			out = buf
		}
		status = in.execSimple(s, c, curIn, out, stderr)
		if buf != nil {
			curIn = bytes.NewReader(buf.Bytes())
		}
	}
	return status
}

// execSimple runs one command: assignments, redirections, then dispatch.
func (in *Interp) execSimple(s *Session, c *SimpleCommand, stdin io.Reader, stdout, stderr io.Writer) int {
	// Bare assignments (no command word): set the session environment.
	if len(c.Args) == 0 {
		for _, a := range c.Assigns {
			name, val, _ := strings.Cut(a, "=")
			s.Env[name] = val
		}
		return 0
	}

	// Apply redirections. Any failure aborts the command with status 1.
	stdout, stderr, cleanup, err := in.applyRedirects(s, c, stdout, stderr, &stdin)
	if err != nil {
		fmt.Fprintf(stderr, "-bash: %s\n", err)
		return 1
	}
	defer cleanup()

	// Per-command environment = session env plus this command's assignments.
	var env map[string]string
	if len(c.Assigns) > 0 {
		env = make(map[string]string, len(s.Env)+len(c.Assigns))
		for k, v := range s.Env {
			env[k] = v
		}
		for _, a := range c.Assigns {
			name, val, _ := strings.Cut(a, "=")
			env[name] = val
		}
	}

	ctx := &Context{Sess: s, Interp: in, Args: c.Args, Env: env, Stdin: stdin, Stdout: stdout, Stderr: stderr}
	if in.Hook != nil {
		in.Hook(ctx)
	}
	name := c.Args[0]
	if cmd, ok := in.cmds[name]; ok {
		return cmd(ctx)
	}
	if in.Fallback != nil {
		if code, handled := in.Fallback(ctx); handled {
			return code
		}
	}
	return in.notFound(ctx)
}

// notFound mimics bash's message for an unknown command or path.
func (in *Interp) notFound(ctx *Context) int {
	name := ctx.Args[0]
	if strings.ContainsRune(name, '/') {
		if info, err := ctx.FS().Stat(name); err == nil {
			if info.IsDir() {
				fmt.Fprintf(ctx.Stderr, "-bash: %s: Is a directory\n", name)
				return 126
			}
			if !vfs.Allowed(info, ctx.Sess.Cred, vfs.X) {
				fmt.Fprintf(ctx.Stderr, "-bash: %s: Permission denied\n", name)
				return 126
			}
			// Executable but we never run anything: it "runs" and exits 0
			// unless it is obviously not a program.
			fmt.Fprintf(ctx.Stderr, "-bash: %s: cannot execute binary file: Exec format error\n", name)
			return 126
		}
		fmt.Fprintf(ctx.Stderr, "-bash: %s: No such file or directory\n", name)
		return 127
	}
	fmt.Fprintf(ctx.Stderr, "-bash: %s: command not found\n", name)
	return 127
}
