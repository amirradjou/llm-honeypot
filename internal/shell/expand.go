package shell

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// expandEnv is what word expansion needs from the shell running it. The
// interpreter's shell implements it; Parse's static view uses staticEnv.
type expandEnv interface {
	arithEnv
	params() []string
	home(user string) (string, bool)
	// cmdSubst runs a command substitution and returns its raw output and
	// exit status.
	cmdSubst(body *list) (string, int)
	// glob expands a pathname pattern; nil means no match.
	glob(pattern string) []string
}

// expandError is an expansion failure. Fatal ones end a non-interactive
// shell (and abandon the line in an interactive one), like bash.
type expandError struct {
	msg    string
	dash   string
	status int
	fatal  bool
}

func (e *expandError) Error() string { return e.msg }

// expander performs bash word expansion: tilde, parameter, command and
// arithmetic expansion, then field splitting, pathname expansion and
// quote removal.
type expander struct {
	env       expandEnv
	subStatus int // exit status of the last command substitution
	hadSubst  bool
}

// xrun is a piece of an expanded word.
type xrun struct {
	s      string
	quoted bool // from quotes: never split or globbed
	split  bool // an unquoted expansion: subject to field splitting
	brk    bool // starts a new field ("$@")
}

// words expands command words into argv.
func (x *expander) words(ws []*word) ([]string, error) {
	var out []string
	for _, w := range ws {
		f, err := x.fields(w, true)
		if err != nil {
			return nil, err
		}
		out = append(out, f...)
	}
	return out, nil
}

// fields expands one word into zero or more fields.
func (x *expander) fields(w *word, glob bool) ([]string, error) {
	if w.alts != nil {
		var out []string
		for _, a := range w.alts {
			f, err := x.fields(a, glob)
			if err != nil {
				return nil, err
			}
			out = append(out, f...)
		}
		return out, nil
	}
	runs, err := x.runs(w.parts, false, nil)
	if err != nil {
		return nil, err
	}
	return x.finish(x.split(runs), glob), nil
}

// str expands a word to a single string: no splitting, no globbing (the
// rules for assignments, here-strings and case subjects).
func (x *expander) str(w *word) (string, error) {
	if w == nil {
		return "", nil
	}
	runs, err := x.runs(w.parts, false, nil)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, r := range runs {
		b.WriteString(r.s)
	}
	return b.String(), nil
}

// pattern expands a word into a glob pattern in which quoted characters
// are literal (case patterns, ${x#pattern}).
func (x *expander) pattern(w *word) (string, error) {
	if w == nil {
		return "", nil
	}
	runs, err := x.runs(w.parts, false, nil)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, r := range runs {
		if r.quoted {
			b.WriteString(escapeGlob(r.s))
		} else {
			b.WriteString(r.s)
		}
	}
	return b.String(), nil
}

func (x *expander) runs(parts []wpart, q bool, out []xrun) ([]xrun, error) {
	for _, part := range parts {
		switch p := part.(type) {
		case *wLit:
			out = append(out, xrun{s: p.s, quoted: q})
		case *wQuoted:
			out = append(out, xrun{s: p.s, quoted: true})
		case *wDouble:
			// "$@" with no positional parameters is no word at all.
			if len(p.parts) == 1 {
				if wp, ok := p.parts[0].(*wParam); ok && wp.name == "@" && wp.op == "" && !wp.ind && len(x.env.params()) == 0 {
					continue
				}
			}
			out = append(out, xrun{quoted: true})
			var err error
			if out, err = x.runs(p.parts, true, out); err != nil {
				return nil, err
			}
		case *wTilde:
			out = append(out, xrun{s: x.tilde(p.user), quoted: true})
		case *wParam:
			rs, err := x.param(p, q)
			if err != nil {
				return nil, err
			}
			out = append(out, rs...)
		case *wCmdSub:
			s, st := x.env.cmdSubst(p.body)
			x.subStatus, x.hadSubst = st, true
			out = append(out, xrun{s: strings.TrimRight(s, "\n"), quoted: q, split: !q})
		case *wArith:
			v, err := x.arith(p.expr)
			if err != nil {
				return nil, err
			}
			out = append(out, xrun{s: strconv.FormatInt(v, 10), quoted: q, split: !q})
		}
	}
	return out, nil
}

func (x *expander) arith(w *word) (int64, error) {
	s, err := x.str(w)
	if err != nil {
		return 0, err
	}
	v, err := evalArith(s, x.env)
	if err != nil {
		if ae, ok := err.(*arithError); ok {
			return 0, &expandError{msg: ae.Error(), dash: ae.dashText(), status: 1, fatal: true}
		}
		return 0, err
	}
	return v, nil
}

func (x *expander) tilde(user string) string {
	switch user {
	case "":
		if h, ok := x.env.getVar("HOME"); ok {
			return h
		}
	case "+":
		v, _ := x.env.getVar("PWD")
		return v
	case "-":
		if v, ok := x.env.getVar("OLDPWD"); ok {
			return v
		}
		return "~-"
	}
	if h, ok := x.env.home(user); ok {
		return h
	}
	return "~" + user
}

func (x *expander) ifs() string {
	v, ok := x.env.getVar("IFS")
	if !ok {
		return " \t\n"
	}
	return v
}

func badSubst(src string) error {
	return &expandError{msg: src + ": bad substitution", dash: "Bad substitution", status: 1, fatal: true}
}

// param expands $name and ${name...}.
func (x *expander) param(p *wParam, q bool) ([]xrun, error) {
	if p.op == "bad" {
		return nil, badSubst(p.src)
	}
	name := p.name
	if (name == "@" || name == "*") && !p.ind && (p.op == "" || p.op == "len") {
		ps := x.env.params()
		if p.op == "len" {
			return []xrun{{s: strconv.Itoa(len(ps)), quoted: q, split: !q}}, nil
		}
		if name == "@" || !q {
			rs := make([]xrun, 0, len(ps))
			for i, v := range ps {
				rs = append(rs, xrun{s: v, quoted: q, split: !q, brk: i > 0})
			}
			return rs, nil
		}
		sep := ""
		if ifs := x.ifs(); ifs != "" {
			sep = ifs[:1]
		}
		return []xrun{{s: strings.Join(ps, sep), quoted: true}}, nil
	}
	val, set := x.env.getVar(name)
	if p.ind {
		if !set {
			return nil, &expandError{msg: name + ": invalid indirect expansion", dash: "Bad substitution", status: 1, fatal: true}
		}
		val, set = x.env.getVar(val)
	}
	one := func(s string) []xrun { return []xrun{{s: s, quoted: q, split: !q}} }
	switch p.op {
	case "":
	case "len":
		val = strconv.Itoa(utf8.RuneCountInString(val))
	case ":-", "-":
		if !set || (p.op == ":-" && val == "") {
			return x.argRuns(p.arg, q)
		}
	case ":=", "=":
		if !set || (p.op == ":=" && val == "") {
			v, err := x.str(p.arg)
			if err != nil {
				return nil, err
			}
			if !isName(name) {
				return nil, &expandError{msg: "$" + name + ": cannot assign in this way", dash: "Bad substitution", status: 1, fatal: true}
			}
			x.env.setVar(name, v)
			val = v
		}
	case ":+", "+":
		if set && (p.op == "+" || val != "") {
			return x.argRuns(p.arg, q)
		}
		val = ""
	case ":?", "?":
		if !set || (p.op == ":?" && val == "") {
			msg, err := x.str(p.arg)
			if err != nil {
				return nil, err
			}
			if msg == "" {
				msg = "parameter null or not set"
				if p.op == "?" {
					msg = "parameter not set"
				}
			}
			return nil, &expandError{msg: name + ": " + msg, dash: name + ": " + msg, status: 127, fatal: true}
		}
	case "#", "##", "%", "%%":
		pat, err := x.pattern(p.arg)
		if err != nil {
			return nil, err
		}
		val = trimPattern(val, pat, p.op)
	case "/", "//", "/#", "/%":
		pat, err := x.pattern(p.arg)
		if err != nil {
			return nil, err
		}
		rep, err := x.str(p.arg2)
		if err != nil {
			return nil, err
		}
		val = replacePattern(val, pat, rep, p.op)
	case "^^":
		val = strings.ToUpper(val)
	case ",,":
		val = strings.ToLower(val)
	case "^", ",":
		if r, n := utf8.DecodeRuneInString(val); n > 0 {
			if p.op == "^" {
				r = unicode.ToUpper(r)
			} else {
				r = unicode.ToLower(r)
			}
			val = string(r) + val[n:]
		}
	case ":":
		off, err := x.arith(p.arg)
		if err != nil {
			return nil, err
		}
		rs := []rune(val)
		n := int64(len(rs))
		if off < 0 {
			off += n
			if off < 0 {
				return one(""), nil
			}
		}
		if off > n {
			off = n
		}
		end := n
		if p.arg2 != nil {
			l, err := x.arith(p.arg2)
			if err != nil {
				return nil, err
			}
			if l < 0 {
				end = n + l
				if end < off {
					return nil, &expandError{msg: strconv.FormatInt(l, 10) + ": substring expression < 0", dash: "Bad substitution", status: 1, fatal: true}
				}
			} else if off+l < n {
				end = off + l
			}
		}
		val = string(rs[off:end])
	}
	return one(val), nil
}

// argRuns expands the word of ${x:-word} and friends. Unquoted, its plain
// text is split into fields like any other expansion result.
func (x *expander) argRuns(w *word, q bool) ([]xrun, error) {
	if w == nil {
		return nil, nil
	}
	rs, err := x.runs(w.parts, q, nil)
	if err != nil {
		return nil, err
	}
	if !q {
		for i := range rs {
			if !rs[i].quoted {
				rs[i].split = true
			}
		}
	}
	if len(rs) == 0 && !q {
		return nil, nil
	}
	return rs, nil
}

// field is one word being built during field splitting.
type field struct {
	segs []xrun
	ok   bool // has content or came from quotes, so it is a real word
}

// split performs field splitting on the unquoted expansion results.
func (x *expander) split(runs []xrun) []field {
	ifs := x.ifs()
	var fields []field
	var cur field
	emit := func() {
		fields = append(fields, cur)
		cur = field{}
	}
	wsDelim := false // the last thing seen was a whitespace delimiter
	for _, r := range runs {
		if r.brk && cur.ok {
			emit()
			wsDelim = false
		}
		if !r.split || ifs == "" {
			cur.segs = append(cur.segs, xrun{s: r.s, quoted: r.quoted})
			if r.quoted || r.s != "" {
				cur.ok = true
				wsDelim = false
			}
			continue
		}
		var piece strings.Builder
		flush := func() {
			if piece.Len() > 0 {
				cur.segs = append(cur.segs, xrun{s: piece.String()})
				cur.ok = true
				piece.Reset()
			}
		}
		for _, c := range r.s {
			if !strings.ContainsRune(ifs, c) {
				piece.WriteRune(c)
				wsDelim = false
				continue
			}
			flush()
			if c == ' ' || c == '\t' || c == '\n' {
				if cur.ok {
					emit()
					wsDelim = true
				}
				continue
			}
			if wsDelim {
				wsDelim = false
				continue
			}
			emit()
		}
		flush()
	}
	if cur.ok {
		emit()
	}
	return fields
}

// finish turns fields into strings, globbing those with unquoted pattern
// characters (a pattern with no match stays as typed).
func (x *expander) finish(fields []field, glob bool) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		var text, pat strings.Builder
		meta := false
		for _, s := range f.segs {
			text.WriteString(s.s)
			if s.quoted {
				pat.WriteString(escapeGlob(s.s))
			} else {
				pat.WriteString(s.s)
				if strings.ContainsAny(s.s, "*?[") {
					meta = true
				}
			}
		}
		if glob && meta {
			if m := x.env.glob(pat.String()); len(m) > 0 {
				out = append(out, m...)
				continue
			}
		}
		out = append(out, text.String())
	}
	return out
}

// staticEnv backs Parse's static view: variables come from an Expander
// and nothing runs.
type staticEnv struct{ exp Expander }

func (e staticEnv) getVar(name string) (string, bool) {
	if e.exp == nil {
		return "", false
	}
	return e.exp.Var(name)
}
func (staticEnv) setVar(string, string) {}
func (staticEnv) params() []string      { return nil }
func (e staticEnv) home(user string) (string, bool) {
	if e.exp == nil {
		return "", false
	}
	return e.exp.Home(user)
}
func (staticEnv) cmdSubst(*list) (string, int) { return "", 0 }
func (staticEnv) glob(string) []string         { return nil }

// flattener builds Parse's flat view of a syntax tree.
type flattener struct {
	x  *expander
	ao *AndOr
}

func (f *flattener) list(l *list, top bool) {
	for i, item := range l.items {
		for j, pl := range item.pipes {
			op := ";"
			if j > 0 {
				op = item.ops[j-1]
			}
			var cmds []*SimpleCommand
			for _, c := range pl.cmds {
				cmds = f.command(c, cmds)
			}
			if len(cmds) == 0 {
				continue
			}
			if len(f.ao.Pipelines) > 0 {
				f.ao.Ops = append(f.ao.Ops, op)
			}
			f.ao.Pipelines = append(f.ao.Pipelines, &Pipeline{Cmds: cmds})
		}
		if top && item.bg && i == len(l.items)-1 {
			f.ao.Background = true
		}
	}
}

func (f *flattener) inner(l *list, out []*SimpleCommand) []*SimpleCommand {
	if l == nil {
		return out
	}
	for _, item := range l.items {
		for _, pl := range item.pipes {
			for _, c := range pl.cmds {
				out = f.command(c, out)
			}
		}
	}
	return out
}

func (f *flattener) command(c command, out []*SimpleCommand) []*SimpleCommand {
	switch c := c.(type) {
	case *simpleCmd:
		return append(out, f.simple(c))
	case *braceGroup:
		return f.inner(c.body, out)
	case *subshellCmd:
		return f.inner(c.body, out)
	case *ifClause:
		for i := range c.conds {
			out = f.inner(c.conds[i], out)
			out = f.inner(c.bodies[i], out)
		}
		return f.inner(c.elseBody, out)
	case *forClause:
		return f.inner(c.body, out)
	case *arithFor:
		return f.inner(c.body, out)
	case *whileClause:
		return f.inner(c.body, f.inner(c.cond, out))
	case *caseClause:
		for _, it := range c.items {
			out = f.inner(it.body, out)
		}
		return out
	case *funcDecl:
		return f.command(c.body, out)
	}
	return out
}

func (f *flattener) simple(c *simpleCmd) *SimpleCommand {
	sc := &SimpleCommand{}
	for _, a := range c.assigns {
		v, _ := f.x.str(a.value)
		sc.Assigns = append(sc.Assigns, a.name+"="+v)
	}
	sc.Args, _ = f.x.words(c.words)
	for _, r := range c.redirs {
		target := r.delim
		if r.target != nil {
			target, _ = f.x.str(r.target)
		}
		sc.Redirects = append(sc.Redirects, Redirect{Op: redirOpText(r), Target: target})
	}
	return sc
}

// redirOpText renders a redirection operator with any explicit fd that
// differs from the operator's default ("2>>", ">", "2>&").
func redirOpText(r *redir) string {
	if r.fd < 0 || r.fd == defaultFd(r.op) {
		return r.op
	}
	return strconv.Itoa(r.fd) + r.op
}

func defaultFd(op string) int {
	switch op {
	case "<", "<&", "<>", "<<", "<<-", "<<<":
		return 0
	}
	return 1
}
