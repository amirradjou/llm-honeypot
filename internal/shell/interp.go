package shell

import (
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

	sh  *shell   // the shell running the command
	fds *fdTable // its file descriptors (for read -u, eval, exec ...)

	applet       bool // run as a busybox applet rather than from $PATH
	notInstalled bool // only noting what a missing tool was asked to fetch
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
	// OnDownload, if set, is called whenever a command fetches a URL
	// (wget/curl/tftp/...). The honeypot never actually fetches anything;
	// this is where the recorder captures the URL for later analysis.
	OnDownload func(ctx *Context, d Download)
}

// Download describes an attempted fetch. Nothing is really retrieved.
type Download struct {
	Tool    string // "wget", "curl", "tftp", ...
	URL     string
	Method  string // GET, POST, ...
	SavedAs string // absolute path the payload was "written" to, if any
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

// Run parses and executes one command line (or a whole script: it may
// contain newlines), returning the exit status. If the line ran
// `exit`/`logout`, or failed in a way that ends a non-interactive bash, it
// returns exited=true with the code.
func (in *Interp) Run(s *Session, line string, stdin io.Reader, stdout, stderr io.Writer) (status int, exited bool, exitCode int) {
	sh := in.topShell(s)
	sh.lim.tty = stdout
	prev := s.active
	// A builtin running a command line of its own (xargs) is still part of
	// the line being run: it shares that line's limits, so recursion
	// through it stays bounded, and a limit hit inside stops the whole line.
	nested := prev != nil && prev.in == in
	if nested {
		sh.lim = prev.lim
		sh.enter(false)
		defer sh.leave()
	}
	s.active = sh
	defer func() {
		s.active = prev
		if !s.Interactive && !nested {
			s.lines += strings.Count(line, "\n") + 1
		}
		if r := recover(); r != nil {
			switch sig := r.(type) {
			case exitSignal:
				status, exited, exitCode = sig.code, true, sig.code
			case fatalSignal:
				status = sig.code
				if !s.Interactive {
					exited, exitCode = true, sig.code
				}
			case abortSignal:
				if nested {
					panic(r)
				}
				io.WriteString(stderr, sig.msg)
				status = sig.code
			default:
				panic(r)
			}
			s.Status = status
		}
	}()
	status = sh.runSource(line, newFdTable(stdin, stdout, stderr))
	s.Status = status
	return status, false, 0
}

// run executes a line from inside a builtin (sudo, nohup, timeout, su -c):
// in the shell already running, sharing its limits, like eval.
func (in *Interp) run(s *Session, line string, stdin io.Reader, stdout, stderr io.Writer) int {
	if sh := s.active; sh != nil && sh.in == in {
		return sh.evalString(line, newFdTable(stdin, stdout, stderr))
	}
	status, _, _ := in.Run(s, line, stdin, stdout, stderr)
	return status
}

// shell returns the shell running this command.
func (c *Context) shell() *shell {
	if c.sh != nil {
		return c.sh
	}
	if a := c.Sess.active; a != nil && a.in == c.Interp {
		return a
	}
	c.sh = c.Interp.topShell(c.Sess)
	return c.sh
}

// fdTable returns the command's file descriptors, with 0-2 taken from the
// Context's streams (a builtin may have swapped them).
func (c *Context) fdTable() *fdTable {
	t := &fdTable{}
	if c.fds != nil {
		*t = *c.fds
	}
	t.setReader(0, c.Stdin)
	t.setWriter(1, c.Stdout)
	t.setWriter(2, c.Stderr)
	return t
}

// shellErrorf prints a bash builtin's error: "bash: line 1: cd: ...".
func (c *Context) shellErrorf(format string, a ...any) {
	fmt.Fprintf(c.Stderr, c.shell().prefix()+c.Args[0]+": "+format+"\n", a...)
}
