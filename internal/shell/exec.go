package shell

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

// Hard limits. Attacker input must never hang or exhaust the honeypot, so
// every way of doing unbounded work in a line is capped.
const (
	maxLoopIters = 10000            // loop iterations per line
	maxCommands  = 100000           // simple commands per line
	maxDepth     = 32               // nested substitutions, evals, sources, functions, child shells
	maxCapture   = 1 << 20          // bytes kept from one command substitution
	maxPipe      = 4 << 20          // bytes kept in one pipe
	maxFileWrite = 16 << 20         // bytes redirected into files per line
	maxLoopTime  = 10 * time.Second // wall time after which loops stop
)

// limits is shared by everything one top-level line runs.
type limits struct {
	start   time.Time
	iters   int
	cmds    int
	depth   int
	written int
	tty     io.Writer // the terminal, for /dev/tty
}

// fatalSignal ends a non-interactive shell after an expansion error (an
// interactive one abandons the line), like bash.
type fatalSignal struct{ code int }

// abortSignal stops the whole line when a limit is hit; msg is printed.
type abortSignal struct {
	code int
	msg  string
}

type flowKind int

const (
	flowNone flowKind = iota
	flowBreak
	flowContinue
	flowReturn
)

// shell is one running shell: the top-level login or -c shell, a subshell,
// or a child sh/bash. It walks the syntax tree.
type shell struct {
	in  *Interp
	s   *Session
	lim *limits

	name0       string   // $0
	params      []string // $1 ...
	interactive bool
	dash        bool   // sh/dash: dash's wording
	srcName     string // script being run or sourced, for messages
	line        int    // line of the command running (messages, $LINENO)
	lineBase    int    // added to parser lines (piped sessions)

	loopDepth int
	funcDepth int
	srcDepth  int
	forked    bool // in a subshell, pipeline or background job
	flow      flowKind
	flowN     int
	ret       int
	locals    []map[string]*string
}

// topShell is the shell that runs one line for a session.
func (in *Interp) topShell(s *Session) *shell {
	sh := &shell{in: in, s: s, lim: &limits{start: time.Now()}, interactive: s.Interactive}
	if s.Interactive {
		sh.name0 = "-bash"
	} else {
		sh.name0 = "bash"
		sh.lineBase = s.lines
	}
	return sh
}

// prefix starts an error message: "-bash: ", "bash: line 1: ",
// "sh: 1: " or "script.sh: line 3: ".
func (sh *shell) prefix() string {
	n := strconv.Itoa(sh.line)
	if sh.srcName != "" {
		if sh.dash {
			return sh.srcName + ": " + n + ": "
		}
		return sh.srcName + ": line " + n + ": "
	}
	switch {
	case sh.interactive:
		return sh.name0 + ": "
	case sh.dash:
		return sh.name0 + ": " + n + ": "
	}
	return sh.name0 + ": line " + n + ": "
}

func (sh *shell) errorf(w io.Writer, format string, a ...any) {
	fmt.Fprintf(w, sh.prefix()+format+"\n", a...)
}

// syntaxFailed reports a parse error the way bash or dash does.
func (sh *shell) syntaxFailed(e *syntaxError, src string, w io.Writer) {
	line := sh.lineBase + e.line
	if sh.dash {
		where := sh.name0
		if sh.srcName != "" {
			where = sh.srcName
		}
		fmt.Fprintf(w, "%s: %d: Syntax error: %s\n", where, line, e.dashText())
		return
	}
	pre := func(n int) string {
		switch {
		case sh.srcName != "":
			return sh.srcName + ": line " + strconv.Itoa(n) + ": "
		case sh.interactive:
			return sh.name0 + ": "
		}
		return sh.name0 + ": -c: line " + strconv.Itoa(n) + ": "
	}
	switch {
	case e.eofMatch != "":
		fmt.Fprintf(w, "%s%s\n", pre(line), e.Error())
		fmt.Fprintf(w, "%ssyntax error: unexpected end of file\n", pre(line+1))
	case e.eof:
		fmt.Fprintf(w, "%s%s\n", pre(line), e.Error())
	default:
		fmt.Fprintf(w, "%s%s\n", pre(line), e.Error())
		if !sh.interactive {
			lines := strings.Split(src, "\n")
			if e.line >= 1 && e.line <= len(lines) {
				fmt.Fprintf(w, "%s`%s'\n", pre(line), lines[e.line-1])
			}
		}
	}
}

// expansionFailed reports an expansion error; fatal ones unwind the shell.
func (sh *shell) expansionFailed(e *expandError, stderr io.Writer) int {
	msg := e.msg
	if sh.dash && e.dash != "" {
		msg = e.dash
	}
	fmt.Fprintf(stderr, "%s%s\n", sh.prefix(), msg)
	if !e.fatal {
		return 1
	}
	code := e.status
	switch {
	case sh.interactive:
		code = 1
	case sh.dash:
		code = 2
	}
	panic(fatalSignal{code: code})
}

// runSource parses src and runs it one complete command line at a time,
// the way bash reads a -c string or a script: earlier lines run even if a
// later one has a syntax error.
func (sh *shell) runSource(src string, fds *fdTable) int {
	p := newParser(src)
	status := sh.s.Status
	for {
		l, err := p.nextLine()
		if err != nil {
			var se *syntaxError
			if errors.As(err, &se) {
				sh.syntaxFailed(se, src, fds.out(2))
			}
			sh.s.Status = 2
			return 2
		}
		if l == nil {
			return status
		}
		status = sh.execList(l, fds)
		if sh.flow != flowNone {
			return status
		}
	}
}

// evalString runs src in this shell (eval, and builtins such as sudo that
// re-enter the interpreter).
func (sh *shell) evalString(src string, fds *fdTable) int {
	sh.enter(false)
	defer sh.leave()
	return sh.runSource(src, fds)
}

func (sh *shell) execList(l *list, fds *fdTable) int {
	status := sh.s.Status
	for _, ao := range l.items {
		if ao.bg {
			sh.runBackground(ao, fds)
			status = 0
		} else {
			status = sh.execAndOr(ao, fds)
		}
		sh.s.Status = status
		if sh.flow != flowNone {
			break
		}
	}
	return status
}

func (sh *shell) execAndOr(ao *andOr, fds *fdTable) int {
	status := 0
	for i, pl := range ao.pipes {
		if i > 0 {
			op := ao.ops[i-1]
			if (op == "&&" && status != 0) || (op == "||" && status == 0) {
				continue
			}
		}
		status = sh.execPipeline(pl, fds)
		sh.s.Status = status
		if sh.flow != flowNone {
			break
		}
	}
	return status
}

// runBackground runs "cmd &". Nothing really runs concurrently: the job
// runs to completion in a subshell and the line carries on with status 0.
func (sh *shell) runBackground(ao *andOr, fds *fdTable) {
	pid := sh.s.nextPID()
	sh.s.jobs++
	if sh.interactive {
		fmt.Fprintf(fds.out(2), "[%d] %d\n", sh.s.jobs, pid)
	}
	sub := sh.subshell()
	f := *fds
	if !sh.interactive {
		f.setReader(0, strings.NewReader(""))
	}
	sub.isolate(func() int { return sub.execAndOr(ao, &f) })
}

func (sh *shell) execPipeline(pl *pipeline, fds *fdTable) int {
	var status int
	if len(pl.cmds) == 1 {
		status = sh.execCommand(pl.cmds[0], fds)
	} else {
		status = sh.execMulti(pl, fds)
	}
	if pl.bang {
		status = boolStatus(status != 0)
	}
	if pl.timed {
		fmt.Fprint(fds.out(2), "\nreal\t0m0.003s\nuser\t0m0.001s\nsys\t0m0.001s\n")
	}
	return status
}

// execMulti runs a pipeline one command after another, each in its own
// subshell, buffering each command's output as the next one's input.
func (sh *shell) execMulti(pl *pipeline, fds *fdTable) int {
	var input io.Reader
	status := 0
	for i, c := range pl.cmds {
		last := i == len(pl.cmds)-1
		f := *fds
		if i > 0 {
			f.setReader(0, input)
		}
		var buf *cappedBuffer
		if !last {
			buf = &cappedBuffer{max: maxPipe}
			f.setWriter(1, buf)
			if pl.amp[i] {
				f.setWriter(2, buf)
			}
		}
		sub := sh.subshell()
		status = sub.isolate(func() int { return sub.execCommand(c, &f) })
		if !last {
			input = bytes.NewReader(buf.buf.Bytes())
		}
	}
	return status
}

// subshell copies this shell for ( ), $( ), pipelines and background jobs.
func (sh *shell) subshell() *shell {
	c := *sh
	c.s = sh.s.fork()
	c.s.active = &c
	c.forked = true
	c.flow = flowNone
	c.locals = slices.Clone(sh.locals)
	return &c
}

// childShell is a new sh or bash process (sh -c, sh script, ./script).
// It gets a copy of the environment but not the functions.
func (sh *shell) childShell(name0 string, params []string, dash bool) *shell {
	c := &shell{in: sh.in, s: sh.s.fork(), lim: sh.lim, name0: name0, params: params, dash: dash, forked: true, line: 1}
	c.s.active = c
	c.s.funcs = nil
	c.s.Status = 0
	c.s.Interactive = false
	return c
}

// isolate runs fn the way a separate process runs: exit and fatal errors
// end fn with their status instead of unwinding the caller.
func (sh *shell) isolate(fn func() int) (status int) {
	defer func() {
		if r := recover(); r != nil {
			switch sig := r.(type) {
			case exitSignal:
				status = sig.code
			case fatalSignal:
				status = sig.code
			default:
				panic(r)
			}
		}
	}()
	return fn()
}

// enter accounts for one more level of nesting. Past the limit the line
// is stopped the way a real machine would stop it: a recursive function
// that forks (:(){ :|:& };:) runs out of processes, anything else runs
// out of stack.
func (sh *shell) enter(function bool) {
	sh.lim.depth++
	if sh.lim.depth <= maxDepth {
		return
	}
	if function && sh.forked {
		pre := sh.name0 + ": "
		msg := strings.Repeat(pre+"fork: retry: Resource temporarily unavailable\n", 3) + pre + "fork: Resource temporarily unavailable\n"
		panic(abortSignal{code: 254, msg: msg})
	}
	panic(abortSignal{code: 139})
}

func (sh *shell) leave() { sh.lim.depth-- }

// tickLoop counts a loop iteration against the line's budget.
func (sh *shell) tickLoop() {
	sh.lim.iters++
	if sh.lim.iters > maxLoopIters || time.Since(sh.lim.start) > maxLoopTime {
		panic(abortSignal{code: 1})
	}
}

// loopDone handles break/continue/return after an iteration and reports
// whether the loop must stop.
func (sh *shell) loopDone() bool {
	switch sh.flow {
	case flowBreak:
		sh.flowN--
		if sh.flowN <= 0 {
			sh.flow = flowNone
		}
		return true
	case flowContinue:
		sh.flowN--
		if sh.flowN <= 0 {
			sh.flow = flowNone
			return false
		}
		return true
	case flowReturn:
		return true
	}
	return false
}

func boolStatus(ok bool) int {
	if ok {
		return 0
	}
	return 1
}

func (sh *shell) execCommand(c command, fds *fdTable) int {
	switch c := c.(type) {
	case *simpleCmd:
		return sh.execSimple(c, fds)
	case *funcDecl:
		if sh.s.funcs == nil {
			sh.s.funcs = map[string]*funcDecl{}
		}
		sh.s.funcs[c.name] = c
		return 0
	}
	f, err := sh.applyRedirs(redirsOf(c), fds)
	if err != nil {
		return sh.redirFailed(err, fds.out(2))
	}
	switch c := c.(type) {
	case *braceGroup:
		return sh.execList(c.body, f)
	case *subshellCmd:
		sub := sh.subshell()
		return sub.isolate(func() int { return sub.execList(c.body, f) })
	case *ifClause:
		for i, cond := range c.conds {
			st := sh.execList(cond, f)
			if sh.flow != flowNone {
				return st
			}
			if st == 0 {
				return sh.execList(c.bodies[i], f)
			}
		}
		if c.elseBody != nil {
			return sh.execList(c.elseBody, f)
		}
		return 0
	case *forClause:
		return sh.execFor(c, f)
	case *arithFor:
		return sh.execArithFor(c, f)
	case *whileClause:
		return sh.execWhile(c, f)
	case *caseClause:
		return sh.execCase(c, f)
	case *arithCmd:
		sh.line = sh.lineBase + c.line
		v, ok := sh.arithStatement(c.expr, f, "((: ")
		if !ok {
			return 1
		}
		return boolStatus(v != 0)
	case *condCmd:
		sh.line = sh.lineBase + c.line
		return sh.execCond(c, f)
	}
	return 0
}

// arithStatement evaluates (( )) and C-style for parts; an error there
// fails the command without ending the shell.
func (sh *shell) arithStatement(w *word, fds *fdTable, label string) (int64, bool) {
	x := sh.expander(fds)
	s, err := x.str(w)
	if err != nil {
		sh.redirFailed(err, fds.out(2))
		return 0, false
	}
	if strings.TrimSpace(s) == "" {
		return 1, true
	}
	v, err := evalArith(s, shellEnv{sh, fds})
	if err != nil {
		fmt.Fprintf(fds.out(2), "%s%s%s\n", sh.prefix(), label, err)
		return 0, false
	}
	return v, true
}

func (sh *shell) execFor(c *forClause, fds *fdTable) int {
	sh.line = sh.lineBase + c.line
	items := sh.params
	if c.hasIn {
		var err error
		if items, err = sh.expander(fds).words(c.items); err != nil {
			return sh.redirFailed(err, fds.out(2))
		}
	}
	status := 0
	sh.loopDepth++
	defer func() { sh.loopDepth-- }()
	for _, it := range items {
		sh.tickLoop()
		sh.setVar(c.name, it)
		status = sh.execList(c.body, fds)
		if sh.loopDone() {
			break
		}
	}
	return status
}

func (sh *shell) execArithFor(c *arithFor, fds *fdTable) int {
	sh.line = sh.lineBase + c.line
	if strings.TrimSpace(c.init.src) != "" {
		if _, ok := sh.arithStatement(c.init, fds, "((: "); !ok {
			return 1
		}
	}
	status := 0
	sh.loopDepth++
	defer func() { sh.loopDepth-- }()
	for {
		sh.tickLoop()
		v, ok := sh.arithStatement(c.cond, fds, "((: ")
		if !ok {
			return 1
		}
		if v == 0 {
			break
		}
		status = sh.execList(c.body, fds)
		if sh.loopDone() {
			break
		}
		if strings.TrimSpace(c.step.src) != "" {
			if _, ok := sh.arithStatement(c.step, fds, "((: "); !ok {
				return 1
			}
		}
	}
	return status
}

func (sh *shell) execWhile(c *whileClause, fds *fdTable) int {
	status := 0
	sh.loopDepth++
	defer func() { sh.loopDepth-- }()
	for {
		sh.tickLoop()
		st := sh.execList(c.cond, fds)
		if sh.flow != flowNone {
			if sh.loopDone() {
				break
			}
			continue
		}
		if (st == 0) == c.until {
			break
		}
		status = sh.execList(c.body, fds)
		if sh.loopDone() {
			break
		}
	}
	return status
}

func (sh *shell) execCase(c *caseClause, fds *fdTable) int {
	sh.line = sh.lineBase + c.line
	x := sh.expander(fds)
	subj, err := x.str(c.subject)
	if err != nil {
		return sh.redirFailed(err, fds.out(2))
	}
	status := 0
	for i := 0; i < len(c.items); i++ {
		it := c.items[i]
		matched := false
		for _, pw := range it.patterns {
			pat, err := x.pattern(pw)
			if err != nil {
				return sh.redirFailed(err, fds.out(2))
			}
			if globMatch(pat, subj) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		status = sh.execList(it.body, fds)
		for it.term == ";&" && i+1 < len(c.items) && sh.flow == flowNone {
			i++
			it = c.items[i]
			status = sh.execList(it.body, fds)
		}
		if it.term != ";;&" || sh.flow != flowNone {
			return status
		}
	}
	return status
}

func (sh *shell) execSimple(c *simpleCmd, fds *fdTable) int {
	sh.line = sh.lineBase + c.line
	sh.lim.cmds++
	if sh.lim.cmds > maxCommands {
		panic(abortSignal{code: 1})
	}
	x := sh.expander(fds)
	argv, err := x.words(c.words)
	if err != nil {
		return sh.redirFailed(err, fds.out(2))
	}
	type kv struct{ name, val string }
	var assigns []kv
	for _, a := range c.assigns {
		v, err := x.str(a.value)
		if err != nil {
			return sh.redirFailed(err, fds.out(2))
		}
		if a.add {
			old, _ := sh.getVar(a.name)
			v = old + v
		}
		assigns = append(assigns, kv{a.name, v})
	}
	if len(argv) == 0 {
		for _, a := range assigns {
			sh.setVar(a.name, a.val)
		}
		if len(c.redirs) > 0 {
			if _, err := sh.applyRedirs(c.redirs, fds); err != nil {
				return sh.redirFailed(err, fds.out(2))
			}
		}
		if x.hadSubst {
			return x.subStatus
		}
		return 0
	}
	if argv[0] == "exec" && len(argv) == 1 && sh.s.funcs["exec"] == nil {
		// exec with only redirections rewires the shell's own fds.
		nt, err := sh.applyRedirs(c.redirs, fds)
		if err != nil {
			return sh.redirFailed(err, fds.out(2))
		}
		*fds = *nt
		return 0
	}
	f, err := sh.applyRedirs(c.redirs, fds)
	if err != nil {
		return sh.redirFailed(err, fds.out(2))
	}
	var env map[string]string
	if len(assigns) > 0 {
		env = maps.Clone(sh.s.Env)
		for _, a := range assigns {
			env[a.name] = a.val
		}
	}
	return sh.dispatch(argv, env, f, true)
}

func (sh *shell) context(argv []string, env map[string]string, fds *fdTable) *Context {
	return &Context{Sess: sh.s, Interp: sh.in, Args: argv, Env: env,
		Stdin: fds.in(), Stdout: fds.out(1), Stderr: fds.out(2), sh: sh, fds: fds}
}

// dispatch runs argv: a function, a builtin, a file named by path, or an
// unknown command (the model fallback, then "command not found").
func (sh *shell) dispatch(argv []string, env map[string]string, fds *fdTable, funcs bool) int {
	name := argv[0]
	ctx := sh.context(argv, env, fds)
	if hook := sh.in.Hook; hook != nil {
		hook(ctx)
	}
	if funcs {
		if fn := sh.s.funcs[name]; fn != nil {
			return sh.callFunction(fn, argv, env, fds)
		}
	}
	if cmd, ok := sh.in.cmds[name]; ok {
		sh.remember(name)
		return cmd(ctx)
	}
	if strings.ContainsRune(name, '/') {
		return sh.execPath(ctx)
	}
	// A file the attacker put on the PATH runs (or fails) like any other.
	if p := sh.lookPath(name); p != "" {
		if real, err := sh.s.FS.RealPath(sh.s.abs(p)); err == nil && !sh.isSystemBinary(real) {
			return sh.execFile(ctx, p)
		}
	}
	if sh.in.Fallback != nil {
		if code, handled := sh.in.Fallback(ctx); handled {
			return code
		}
	}
	return sh.notFound(ctx)
}

func (sh *shell) notFound(ctx *Context) int {
	if sh.dash {
		sh.errorf(ctx.Stderr, "%s: not found", ctx.Args[0])
	} else {
		sh.errorf(ctx.Stderr, "%s: command not found", ctx.Args[0])
	}
	return 127
}

func (sh *shell) callFunction(fn *funcDecl, argv []string, env map[string]string, fds *fdTable) int {
	sh.enter(true)
	defer sh.leave()
	saved := sh.params
	sh.params = argv[1:]
	sh.funcDepth++
	sh.locals = append(sh.locals, map[string]*string{})
	// NAME=value before a function call holds for the call only.
	for k, v := range env {
		if old, ok := sh.s.Env[k]; !ok || old != v {
			sh.declareLocal(k)
			sh.s.Env[k] = v
		}
	}
	status := sh.execCommand(fn.body, fds)
	if sh.flow == flowReturn {
		sh.flow = flowNone
		status = sh.ret
	}
	sh.popLocals()
	sh.funcDepth--
	sh.params = saved
	return status
}

// declareLocal saves name's value in the innermost function frame so it
// is restored when the function returns.
func (sh *shell) declareLocal(name string) {
	if len(sh.locals) == 0 {
		return
	}
	frame := sh.locals[len(sh.locals)-1]
	if _, done := frame[name]; done {
		return
	}
	if v, ok := sh.s.Env[name]; ok {
		frame[name] = &v
	} else {
		frame[name] = nil
	}
}

func (sh *shell) popLocals() {
	frame := sh.locals[len(sh.locals)-1]
	sh.locals = sh.locals[:len(sh.locals)-1]
	for name, v := range frame {
		if v == nil {
			delete(sh.s.Env, name)
		} else {
			sh.s.Env[name] = *v
		}
	}
}

// systemBinDirs are where the seeded machine keeps its programs.
var systemBinDirs = map[string]bool{"/usr/bin": true, "/usr/sbin": true, "/usr/local/bin": true,
	"/usr/local/sbin": true, "/bin": true, "/sbin": true, "/usr/games": true, "/usr/local/games": true}

// isSystemBinary reports whether real (a resolved path) is one of the
// machine's own programs, untouched since the session began.
func (sh *shell) isSystemBinary(real string) bool {
	if !systemBinDirs[parentOf(real)] {
		return false
	}
	m := sh.s.Machine
	if m == nil || m.FS == nil {
		return false
	}
	ti, err := m.FS.Stat(real)
	if err != nil || ti.IsDir() {
		return false
	}
	si, err := sh.s.FS.Stat(real)
	return err == nil && si.Size == ti.Size && si.ModTime.Equal(ti.ModTime) && si.UID == ti.UID
}

// execPath runs a command named by a path (/bin/ls, ./payload).
func (sh *shell) execPath(ctx *Context) int {
	name := ctx.Args[0]
	abs := sh.s.abs(name)
	info, err := sh.s.FS.Stat(abs)
	if err != nil {
		if errors.Is(err, vfs.ErrNotDir) {
			sh.errorf(ctx.Stderr, "%s: Not a directory", name)
			return 126
		}
		if sh.dash {
			sh.errorf(ctx.Stderr, "%s: not found", name)
		} else {
			sh.errorf(ctx.Stderr, "%s: No such file or directory", name)
		}
		return 127
	}
	if info.IsDir() {
		sh.errorf(ctx.Stderr, "%s: Is a directory", name)
		return 126
	}
	if !permit(sh.s, abs, 'x') {
		sh.errorf(ctx.Stderr, "%s: Permission denied", name)
		return 126
	}
	if real, err := sh.s.FS.RealPath(abs); err == nil && sh.isSystemBinary(real) {
		base := path.Base(name)
		if _, ok := sh.in.cmds[base]; !ok {
			base = path.Base(real)
		}
		if cmd, ok := sh.in.cmds[base]; ok {
			return cmd(ctx) // Args[0] stays as typed, as argv[0] would
		}
		if sh.in.Fallback != nil {
			if code, handled := sh.in.Fallback(ctx); handled {
				return code
			}
		}
		sh.errorf(ctx.Stderr, "%s: cannot execute binary file: Exec format error", name)
		return 126
	}
	return sh.execFile(ctx, name)
}

// execFile "executes" a non-system file: binaries (downloaded payloads)
// cannot run here, text scripts run in a child shell.
func (sh *shell) execFile(ctx *Context, p string) int {
	data, info, err := sh.s.FS.ReadFile(sh.s.abs(p))
	if err != nil || info.Placeholder {
		return 0
	}
	if looksBinary(data) {
		sh.errorf(ctx.Stderr, "%s: cannot execute binary file: Exec format error", ctx.Args[0])
		return 126
	}
	interp := shebang(data)
	dash := false
	switch interp {
	case "", "bash", "rbash":
	case "sh", "dash":
		dash = true
	default:
		return 0 // python, perl...: nothing here can stand in for them
	}
	child := sh.childShell(ctx.Args[0], ctx.Args[1:], dash)
	child.srcName = ctx.Args[0]
	return child.isolate(func() int { return child.runScript(string(data), ctx) })
}

// runScript runs a script's text in this (child) shell.
func (sh *shell) runScript(src string, ctx *Context) int {
	sh.enter(false)
	defer sh.leave()
	return sh.runSource(src, ctx.fdTable())
}

// shebang returns the interpreter's base name from a #! line ("" if none).
func shebang(data []byte) string {
	if !bytes.HasPrefix(data, []byte("#!")) {
		return ""
	}
	line := string(data[2:])
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) == 0 {
		return ""
	}
	name := path.Base(f[0])
	if name == "env" && len(f) > 1 {
		name = path.Base(f[1])
	}
	return name
}

// looksBinary reports content that is not a text script: an ELF header,
// NUL bytes, invalid UTF-8 or a scattering of control characters.
func looksBinary(b []byte) bool {
	if len(b) > 4096 {
		b = b[:4096]
	}
	if bytes.HasPrefix(b, []byte("\x7fELF")) || bytes.IndexByte(b, 0) >= 0 {
		return true
	}
	ctrl := 0
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n == 1 {
			if !utf8.FullRune(b) {
				break // cut mid-character by the 4 KiB window
			}
			return true
		}
		if (r < 0x20 && !strings.ContainsRune("\n\t\r\f\v\b\x1b", r)) || r == 0x7f {
			ctrl++
		}
		b = b[n:]
	}
	return ctrl > 8
}

// lookPath finds name on $PATH in the virtual filesystem.
func (sh *shell) lookPath(name string) string {
	if name == "" || strings.ContainsRune(name, '/') {
		return ""
	}
	pathVar, _ := sh.getVar("PATH")
	for _, dir := range strings.Split(pathVar, ":") {
		if dir == "" {
			dir = "."
		}
		p := strings.TrimSuffix(dir, "/") + "/" + name
		abs := sh.s.abs(p)
		info, err := sh.s.FS.Stat(abs)
		if err == nil && !info.IsDir() && permit(sh.s, abs, 'x') {
			return p
		}
	}
	return ""
}

// remember adds an external command to the hash table, as bash does the
// first time it runs one.
func (sh *shell) remember(name string) {
	if isBashBuiltin(name) || strings.ContainsRune(name, '/') {
		return
	}
	if _, ok := sh.s.hashed[name]; ok {
		return
	}
	if p := sh.lookPath(name); p != "" {
		if sh.s.hashed == nil {
			sh.s.hashed = map[string]string{}
		}
		sh.s.hashed[name] = p
	}
}

// cmdSubst runs $(...) in a subshell and returns its output.
func (sh *shell) cmdSubst(body *list, fds *fdTable) (string, int) {
	sh.enter(false)
	defer sh.leave()
	sub := sh.subshell()
	out := &cappedBuffer{max: maxCapture}
	f := *fds
	f.setWriter(1, out)
	st := sub.isolate(func() int { return sub.execList(body, &f) })
	b := out.buf.Bytes()
	if bytes.IndexByte(b, 0) >= 0 {
		fmt.Fprintf(fds.out(2), "%swarning: command substitution: ignored null byte in input\n", sh.prefix())
		b = bytes.ReplaceAll(b, []byte{0}, nil)
	}
	return string(b), st
}

// --- variables ---

// shellEnv adapts a shell to word expansion.
type shellEnv struct {
	sh  *shell
	fds *fdTable
}

func (e shellEnv) getVar(n string) (string, bool) { return e.sh.getVar(n) }
func (e shellEnv) setVar(n, v string)             { e.sh.setVar(n, v) }
func (e shellEnv) params() []string               { return e.sh.params }
func (e shellEnv) home(u string) (string, bool)   { return e.sh.s.homeOf(u) }
func (e shellEnv) cmdSubst(b *list) (string, int) { return e.sh.cmdSubst(b, e.fds) }
func (e shellEnv) glob(pattern string) []string   { return e.sh.s.globPaths(pattern) }
func (sh *shell) expander(fds *fdTable) *expander { return &expander{env: shellEnv{sh, fds}} }

// flags is $-.
func (sh *shell) flags() string {
	switch {
	case sh.interactive:
		return "himBHs"
	case sh.dash:
		return "c"
	case sh.srcName != "":
		return "hB"
	}
	return "hBc"
}

func (sh *shell) getVar(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	s := sh.s
	switch name {
	case "?":
		return strconv.Itoa(s.Status), true
	case "$":
		return strconv.Itoa(s.PID), true
	case "!":
		if s.prevPID == 0 {
			return "", false
		}
		return strconv.Itoa(s.prevPID), true
	case "#":
		return strconv.Itoa(len(sh.params)), true
	case "@", "*":
		return strings.Join(sh.params, " "), len(sh.params) > 0
	case "-":
		return sh.flags(), true
	case "0":
		return sh.name0, true
	}
	if isDigits(name) {
		n, _ := strconv.Atoi(name)
		if n >= 1 && n <= len(sh.params) {
			return sh.params[n-1], true
		}
		return "", false
	}
	if v, ok := s.Env[name]; ok {
		return v, true
	}
	return sh.dynamicVar(name)
}

// dynamicVar answers the variables bash always has but does not export.
func (sh *shell) dynamicVar(name string) (string, bool) {
	s := sh.s
	switch name {
	case "IFS":
		return " \t\n", true
	case "PPID":
		return strconv.Itoa(s.PID - 2), true
	case "UID", "EUID":
		if sh.dash {
			return "", false
		}
		return strconv.Itoa(s.Cred.UID), true
	case "RANDOM":
		if sh.dash {
			return "", false
		}
		return strconv.Itoa(s.Rand.Intn(32768)), true
	case "LINENO":
		return strconv.Itoa(sh.line), true
	case "OPTIND":
		return "1", true
	case "PS2":
		return "> ", true
	case "PS4":
		return "+ ", true
	}
	if sh.dash {
		return "", false
	}
	switch name {
	case "BASH":
		return "/usr/bin/bash", true
	case "BASH_VERSION":
		return "5.1.16(1)-release", true
	case "BASHPID":
		return strconv.Itoa(s.PID), true
	case "SECONDS":
		return strconv.Itoa(int(s.Machine.Now().Sub(s.started).Seconds())), true
	case "SHLVL":
		return "1", true
	case "OSTYPE":
		return "linux-gnu", true
	case "HOSTTYPE":
		return s.Machine.Profile.Arch, true
	case "MACHTYPE":
		return s.Machine.Profile.Arch + "-pc-linux-gnu", true
	case "OPTERR":
		return "1", true
	case "HISTFILE":
		if home, ok := s.Env["HOME"]; ok {
			return home + "/.bash_history", true
		}
	case "HISTSIZE":
		if sh.interactive {
			return "1000", true
		}
	case "HISTFILESIZE":
		if sh.interactive {
			return "2000", true
		}
	case "PS1":
		if sh.interactive {
			return `${debian_chroot:+($debian_chroot)}\u@\h:\w\$ `, true
		}
	}
	return "", false
}

func (sh *shell) setVar(name, val string) {
	if !isName(name) {
		return
	}
	if name == "PATH" {
		sh.s.hashed = nil
	}
	sh.s.Env[name] = val
}

// --- [[ ... ]] ---

type condEval struct {
	sh    *shell
	x     *expander
	ctx   *Context
	items []condItem
	pos   int
	bad   bool
}

func (sh *shell) execCond(c *condCmd, fds *fdTable) int {
	e := &condEval{sh: sh, x: sh.expander(fds), ctx: sh.context([]string{"[["}, nil, fds), items: c.items}
	v := e.or()
	if e.bad || e.pos != len(e.items) {
		tok := "]]"
		if e.pos < len(e.items) {
			tok = e.text(e.pos)
		}
		sh.errorf(fds.out(2), "syntax error in conditional expression: unexpected token `%s'", tok)
		return 2
	}
	return boolStatus(v)
}

func (e *condEval) isOp(op string) bool {
	return e.pos < len(e.items) && e.items[e.pos].op == op && e.items[e.pos].w == nil
}

func (e *condEval) isWord(s string) bool {
	return e.pos < len(e.items) && e.items[e.pos].w != nil && e.items[e.pos].w.src == s
}

func (e *condEval) text(i int) string {
	if e.items[i].w != nil {
		return e.items[i].w.src
	}
	return e.items[i].op
}

func (e *condEval) str(i int) string {
	s, err := e.x.str(e.items[i].w)
	if err != nil {
		var xe *expandError
		if errors.As(err, &xe) {
			e.sh.expansionFailed(xe, e.ctx.Stderr)
		}
		e.bad = true
	}
	return s
}

func (e *condEval) or() bool {
	v := e.and()
	for e.isOp("||") {
		e.pos++
		r := e.and()
		v = v || r
	}
	return v
}

func (e *condEval) and() bool {
	v := e.not()
	for e.isOp("&&") {
		e.pos++
		r := e.not()
		v = v && r
	}
	return v
}

func (e *condEval) not() bool {
	if e.isWord("!") {
		e.pos++
		return !e.not()
	}
	return e.primary()
}

var condUnary = map[string]bool{"-a": true, "-b": true, "-c": true, "-d": true, "-e": true, "-f": true, "-g": true,
	"-h": true, "-k": true, "-p": true, "-r": true, "-s": true, "-t": true, "-u": true, "-w": true, "-x": true,
	"-G": true, "-L": true, "-N": true, "-O": true, "-S": true, "-z": true, "-n": true, "-v": true, "-o": true}

var condBinary = map[string]bool{"==": true, "=": true, "!=": true, "=~": true, "-eq": true, "-ne": true,
	"-lt": true, "-le": true, "-gt": true, "-ge": true, "-nt": true, "-ot": true, "-ef": true}

func (e *condEval) primary() bool {
	if e.pos >= len(e.items) {
		e.bad = true
		return false
	}
	if e.isOp("(") {
		e.pos++
		v := e.or()
		if !e.isOp(")") {
			e.bad = true
			return false
		}
		e.pos++
		return v
	}
	it := e.items[e.pos]
	if it.w == nil {
		e.bad = true
		return false
	}
	// Unary test: -f file.
	if condUnary[it.w.src] && e.pos+1 < len(e.items) && e.items[e.pos+1].w != nil &&
		!(e.pos+2 < len(e.items) && e.binaryAt(e.pos+1)) {
		op := it.w.src
		arg := e.str(e.pos + 1)
		e.pos += 2
		switch op {
		case "-v":
			_, ok := e.sh.getVar(arg)
			return ok
		case "-o", "-t":
			return false
		}
		return evalUnary(e.ctx, op, arg)
	}
	left := e.str(e.pos)
	e.pos++
	if e.pos < len(e.items) && e.binaryAt(e.pos) {
		op := e.text(e.pos)
		e.pos++
		if e.pos >= len(e.items) || e.items[e.pos].w == nil {
			e.bad = true
			return false
		}
		rw := e.items[e.pos].w
		e.pos++
		switch op {
		case "==", "=", "!=":
			pat, _ := e.x.pattern(rw)
			m := globMatch(pat, left)
			return m == (op != "!=")
		case "=~":
			re, err := regexp.Compile(e.str(e.pos - 1))
			if err != nil {
				e.bad = true
				return false
			}
			return re.MatchString(left)
		case "<":
			return left < e.str(e.pos-1)
		case ">":
			return left > e.str(e.pos-1)
		case "-eq", "-ne", "-lt", "-le", "-gt", "-ge":
			a, errA := evalArith(left, shellEnv{e.sh, e.ctx.fds})
			b, errB := evalArith(e.str(e.pos-1), shellEnv{e.sh, e.ctx.fds})
			if errA != nil || errB != nil {
				e.bad = true
				return false
			}
			switch op {
			case "-eq":
				return a == b
			case "-ne":
				return a != b
			case "-lt":
				return a < b
			case "-le":
				return a <= b
			case "-gt":
				return a > b
			}
			return a >= b
		}
		return evalBinary(left, op, e.str(e.pos-1))
	}
	return left != ""
}

func (e *condEval) binaryAt(i int) bool {
	it := e.items[i]
	if it.w == nil {
		return it.op == "<" || it.op == ">"
	}
	return condBinary[it.w.src]
}
