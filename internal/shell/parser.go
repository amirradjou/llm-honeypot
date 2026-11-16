// Package shell parses and interprets the part of bash that attackers
// actually use: quoting, every kind of expansion (variables, command
// substitution, arithmetic, globs, braces), pipelines, lists, redirections
// with fd duplication, compound commands (if, for, while, until, case,
// { }, ( )), functions and the common builtins. It never runs anything
// real; commands are Go functions over the virtual machine.
package shell

import "strings"

// Redirect is one I/O redirection in the static view returned by Parse.
type Redirect struct {
	// Op is the operator with any explicit fd, e.g. ">", "2>>", "&>", "2>&".
	Op string
	// Target is the file path or fd (expanded).
	Target string
}

// SimpleCommand is a single command with its arguments and redirections.
// Assignments that precede the command (FOO=bar cmd) are captured too.
type SimpleCommand struct {
	Assigns   []string // "FOO=bar" prefixes
	Args      []string // argv; Args[0] is the command name
	Redirects []Redirect
}

// Pipeline is one or more SimpleCommands joined by "|".
type Pipeline struct {
	Cmds []*SimpleCommand
}

// AndOr is a flat view of a command line: pipelines joined by && / || / ;.
type AndOr struct {
	// Pipelines[i] runs; Ops[i] ("&&", "||", ";") joins to Pipelines[i+1].
	Pipelines []*Pipeline
	Ops       []string
	// Background is true when the whole list ended with '&'.
	Background bool
}

// Expander resolves variables and ~ for Parse's static view.
type Expander interface {
	// Var returns the value of name and whether it was set.
	Var(name string) (string, bool)
	// Home returns the home directory for ~ (empty user = current user).
	Home(user string) (string, bool)
}

// Parse returns a flat, statically expanded view of a command line: every
// simple command it contains (including those inside loops, conditionals
// and functions), with variables resolved through exp. Command and
// arithmetic substitutions expand to nothing and nothing is globbed:
// nothing runs. It is for analysing recorded lines; the interpreter itself
// works on the full syntax tree and expands each command as it runs.
func Parse(line string, exp Expander) (*AndOr, error) {
	p := newParser(line)
	l, err := p.parseProgram()
	if err != nil {
		return nil, err
	}
	ao := &AndOr{}
	f := &flattener{x: &expander{env: staticEnv{exp}}, ao: ao}
	f.list(l, true)
	return ao, nil
}

// parseProgram parses all of the source.
func (p *parser) parseProgram() (l *list, err error) {
	defer func() {
		if r := recover(); r != nil {
			se, ok := r.(*syntaxError)
			if !ok {
				panic(r)
			}
			err = se
		}
	}()
	return p.parseAll(), nil
}

// parseAll parses the whole source as one list.
func (p *parser) parseAll() *list {
	l := p.parseCompoundList(true)
	if t := p.peek(); t.kind != tkEOF {
		p.unexpected(t)
	}
	return l
}

// nextLine parses the next complete command line (up to an unquoted
// newline), the unit bash reads and runs before parsing further. It
// returns nil at the end of the input.
func (p *parser) nextLine() (l *list, err error) {
	defer func() {
		if r := recover(); r != nil {
			se, ok := r.(*syntaxError)
			if !ok {
				panic(r)
			}
			err = se
		}
	}()
	p.skipNewlines()
	if p.peek().kind == tkEOF {
		return nil, nil
	}
	l = &list{}
	for {
		ao := p.parseAndOr()
		l.items = append(l.items, ao)
		t := p.peek()
		if t.kind == tkOp && (t.op == ";" || t.op == "&") {
			p.next()
			ao.bg = t.op == "&"
			t = p.peek()
			if t.kind != tkNewline && t.kind != tkEOF {
				continue // another command on the same line
			}
		}
		switch t.kind {
		case tkNewline:
			p.next()
			return l, nil
		case tkEOF:
			return l, nil
		}
		p.unexpected(t)
	}
}

func (p *parser) skipNewlines() {
	for p.peek().kind == tkNewline {
		p.next()
	}
}

// unexpected panics with a syntax error naming t.
func (p *parser) unexpected(t *token) {
	if t.kind == tkEOF {
		e := &syntaxError{eof: true, line: t.line, dashLine: p.line}
		if n := len(p.closers); n > 0 {
			e.expecting = p.closers[n-1]
		}
		panic(e)
	}
	panic(&syntaxError{tok: t.display(), line: t.line})
}

func isKw(t *token, kw string) bool { return t.kind == tkWord && t.word.src == kw }

func (p *parser) expectWord(kw string) {
	if t := p.next(); !isKw(t, kw) {
		p.closers = append(p.closers, kw)
		p.unexpected(t)
	}
}

func (p *parser) expectOp(op string) {
	if t := p.next(); t.kind != tkOp || t.op != op {
		p.closers = append(p.closers, op)
		p.unexpected(t)
	}
}

func (p *parser) push(kw string) { p.closers = append(p.closers, kw) }
func (p *parser) pop()           { p.closers = p.closers[:len(p.closers)-1] }

var listEnders = map[string]bool{"then": true, "else": true, "elif": true, "fi": true, "do": true, "done": true, "esac": true, "}": true}

// atListEnd reports whether the next token ends a compound list.
func (p *parser) atListEnd() bool {
	t := p.peek()
	switch t.kind {
	case tkEOF:
		return true
	case tkOp:
		return t.op == ")" || t.op == ";;" || t.op == ";&" || t.op == ";;&"
	case tkWord:
		return listEnders[t.word.src]
	}
	return false
}

// parseCompoundList parses and-or lists separated by ; & and newlines up
// to a list terminator (a closing keyword, ")", ";;" or the end).
func (p *parser) parseCompoundList(allowEmpty bool) *list {
	l := &list{}
	for {
		p.skipNewlines()
		if p.atListEnd() {
			break
		}
		ao := p.parseAndOr()
		l.items = append(l.items, ao)
		t := p.peek()
		if t.kind == tkOp && (t.op == ";" || t.op == "&") {
			p.next()
			ao.bg = t.op == "&"
			continue
		}
		if t.kind == tkNewline {
			continue
		}
		if p.atListEnd() {
			break
		}
		p.unexpected(t)
	}
	if !allowEmpty && len(l.items) == 0 {
		p.unexpected(p.peek())
	}
	return l
}

func (p *parser) parseAndOr() *andOr {
	ao := &andOr{line: p.peek().line}
	ao.pipes = append(ao.pipes, p.parsePipeline())
	for {
		t := p.peek()
		if t.kind != tkOp || (t.op != "&&" && t.op != "||") {
			return ao
		}
		p.next()
		p.skipNewlines()
		ao.ops = append(ao.ops, t.op)
		ao.pipes = append(ao.pipes, p.parsePipeline())
	}
}

func (p *parser) parsePipeline() *pipeline {
	pl := &pipeline{}
	for {
		t := p.peek()
		if isKw(t, "!") {
			p.next()
			pl.bang = !pl.bang
			continue
		}
		if isKw(t, "time") {
			p.next()
			pl.timed = true
			if isKw(p.peek(), "-p") {
				p.next()
			}
			continue
		}
		break
	}
	pl.cmds = append(pl.cmds, p.parseCommand())
	for {
		t := p.peek()
		if t.kind != tkOp || (t.op != "|" && t.op != "|&") {
			return pl
		}
		p.next()
		p.skipNewlines()
		pl.amp = append(pl.amp, t.op == "|&")
		pl.cmds = append(pl.cmds, p.parseCommand())
	}
}

func (p *parser) parseCommand() command {
	if p.depth >= maxParseDepth {
		p.unexpected(p.peek())
	}
	p.depth++
	defer func() { p.depth-- }()
	t := p.peek()
	var c command
	switch t.kind {
	case tkWord:
		switch t.word.src {
		case "if":
			c = p.parseIf()
		case "for":
			c = p.parseFor()
		case "while", "until":
			c = p.parseWhile()
		case "case":
			c = p.parseCase()
		case "{":
			p.next()
			p.push("}")
			body := p.parseCompoundList(false)
			p.expectWord("}")
			p.pop()
			c = &braceGroup{body: body}
		case "[[":
			c = p.parseCond()
		case "function":
			return p.parseFunction()
		case "then", "else", "elif", "fi", "do", "done", "esac", "}":
			p.unexpected(t)
		default:
			return p.parseSimple()
		}
	case tkRedir:
		return p.parseSimple()
	case tkOp:
		if t.op != "(" {
			p.unexpected(t)
		}
		p.next()
		p.push(")")
		body := p.parseCompoundList(false)
		p.expectOp(")")
		p.pop()
		c = &subshellCmd{body: body}
	case tkArith:
		p.next()
		c = &arithCmd{expr: p.arithWord(t.text, t.line), line: t.line}
	default:
		p.unexpected(t)
	}
	setRedirs(c, p.trailingRedirs())
	return c
}

// arithWord parses the text of an arithmetic expression as a word.
func (p *parser) arithWord(text string, line int) *word {
	sub := p.subParser(text, line)
	return &word{parts: []wpart{&wDouble{parts: sub.readDQ(dqArith)}}, src: text}
}

func (p *parser) trailingRedirs() []*redir {
	var rs []*redir
	for p.peek().kind == tkRedir {
		rs = append(rs, p.parseRedir(p.next()))
	}
	return rs
}

func (p *parser) parseSimple() command {
	cmd := &simpleCmd{line: p.peek().line}
	for {
		t := p.peek()
		switch t.kind {
		case tkWord:
			p.next()
			if len(cmd.words) == 0 {
				if a := asAssign(t.word); a != nil {
					cmd.assigns = append(cmd.assigns, a)
					continue
				}
				if len(cmd.assigns) == 0 && len(cmd.redirs) == 0 {
					if n := p.peek(); n.kind == tkOp && n.op == "(" {
						return p.parseFuncBody(t)
					}
				}
			}
			cmd.words = append(cmd.words, p.braceWord(t.word))
		case tkRedir:
			p.next()
			cmd.redirs = append(cmd.redirs, p.parseRedir(t))
		default:
			if len(cmd.words)+len(cmd.assigns)+len(cmd.redirs) == 0 {
				p.unexpected(t)
			}
			return cmd
		}
	}
}

// parseFuncBody parses "name () compound-command" after the name.
func (p *parser) parseFuncBody(name *token) command {
	p.next() // (
	if t := p.next(); t.kind != tkOp || t.op != ")" {
		p.unexpected(t)
	}
	p.skipNewlines()
	start := p.peek().pos
	body := p.parseCommand()
	if sc, ok := body.(*simpleCmd); ok {
		if len(sc.words) > 0 {
			panic(&syntaxError{tok: sc.words[0].src, line: sc.line})
		}
		p.unexpected(p.peek())
	}
	return &funcDecl{name: name.word.src, body: body, src: p.textFrom(start), line: name.line}
}

// textFrom returns the source from start up to the next unread token.
func (p *parser) textFrom(start int) string {
	end := p.pos
	if p.peeked != nil {
		end = p.peeked.pos
	}
	return strings.TrimSpace(p.src[start:end])
}

func (p *parser) parseFunction() command {
	p.next() // function
	t := p.next()
	if t.kind != tkWord {
		p.unexpected(t)
	}
	if n := p.peek(); n.kind == tkOp && n.op == "(" {
		p.next()
		p.expectOp(")")
	}
	p.skipNewlines()
	start := p.peek().pos
	body := p.parseCommand()
	if _, ok := body.(*simpleCmd); ok {
		p.unexpected(p.peek())
	}
	return &funcDecl{name: t.word.src, body: body, src: p.textFrom(start), line: t.line}
}

func (p *parser) parseRedir(t *token) *redir {
	r := &redir{fd: t.fd, op: t.op, line: t.line}
	w := p.next()
	if w.kind != tkWord {
		p.unexpected(w)
	}
	if t.op == "<<" || t.op == "<<-" {
		r.delim, r.quoted = heredocDelim(w.word)
		p.heredocs = append(p.heredocs, r)
		return r
	}
	r.target = w.word
	return r
}

// heredocDelim removes quotes from a here-document delimiter and reports
// whether there were any (a quoted delimiter turns off expansion).
func heredocDelim(w *word) (string, bool) {
	var b strings.Builder
	quoted := false
	var walk func(parts []wpart)
	walk = func(parts []wpart) {
		for _, part := range parts {
			switch x := part.(type) {
			case *wLit:
				b.WriteString(x.s)
			case *wQuoted:
				quoted = true
				b.WriteString(x.s)
			case *wDouble:
				quoted = true
				walk(x.parts)
			case *wTilde:
				b.WriteString("~" + x.user)
			case *wParam:
				b.WriteString(x.src)
			case *wCmdSub:
				b.WriteString(x.src)
			case *wArith:
				b.WriteString(x.src)
			}
		}
	}
	walk(w.parts)
	return b.String(), quoted
}

// readHeredocs reads the bodies of pending here-documents; p.pos is at
// the start of the line after the one that introduced them.
func (p *parser) readHeredocs() {
	pending := p.heredocs
	p.heredocs = nil
	for _, r := range pending {
		var body strings.Builder
		startLine := p.line
		closed := false
		for p.pos < len(p.src) {
			end := strings.IndexByte(p.src[p.pos:], '\n')
			var ln string
			if end < 0 {
				ln = p.src[p.pos:]
				p.pos = len(p.src)
			} else {
				ln = p.src[p.pos : p.pos+end]
				p.pos += end + 1
			}
			p.line++
			if r.op == "<<-" {
				ln = strings.TrimLeft(ln, "\t")
			}
			if ln == r.delim {
				closed = true
				break
			}
			body.WriteString(ln)
			body.WriteByte('\n')
		}
		if !closed {
			p.warnings = append(p.warnings, heredocEOF{line: p.line, start: r.line, delim: r.delim})
		}
		text := body.String()
		if r.quoted {
			r.body = &word{parts: []wpart{&wQuoted{s: text}}, src: text}
			continue
		}
		sub := p.subParser(text, startLine)
		r.body = &word{parts: []wpart{&wDouble{parts: sub.readDQ(dqHeredoc)}}, src: text}
	}
}

// isAssignment reports whether s looks like NAME=value with a valid name.
func isAssignment(s string) bool {
	name, _, ok := strings.Cut(s, "=")
	return ok && isName(name)
}

// asAssign recognises NAME=value and NAME+=value.
func asAssign(w *word) *assign {
	if len(w.parts) == 0 {
		return nil
	}
	lit, ok := w.parts[0].(*wLit)
	if !ok {
		return nil
	}
	eq := strings.IndexByte(lit.s, '=')
	if eq <= 0 {
		return nil
	}
	name, add := lit.s[:eq], false
	if strings.HasSuffix(name, "+") {
		name, add = name[:len(name)-1], true
	}
	if !isName(name) {
		return nil
	}
	var parts []wpart
	if rest := lit.s[eq+1:]; rest != "" {
		parts = append(parts, &wLit{s: rest})
	}
	parts = append(parts, w.parts[1:]...)
	src := ""
	if i := strings.IndexByte(w.src, '='); i >= 0 {
		src = w.src[i+1:]
	}
	return &assign{name: name, value: &word{parts: tildeAssign(parts), src: src}, add: add}
}

func (p *parser) parseIf() command {
	c := &ifClause{}
	p.next() // if
	for {
		p.push("then")
		c.conds = append(c.conds, p.parseCompoundList(false))
		p.expectWord("then")
		p.pop()
		p.push("fi")
		c.bodies = append(c.bodies, p.parseCompoundList(false))
		t := p.next()
		switch {
		case isKw(t, "elif"):
			p.pop()
			continue
		case isKw(t, "else"):
			c.elseBody = p.parseCompoundList(false)
			p.expectWord("fi")
			p.pop()
			return c
		case isKw(t, "fi"):
			p.pop()
			return c
		}
		p.unexpected(t)
	}
}

func (p *parser) parseFor() command {
	p.next() // for
	t := p.next()
	if t.kind == tkArith {
		return p.parseArithFor(t)
	}
	if t.kind != tkWord || !isName(t.word.src) {
		p.unexpected(t)
	}
	c := &forClause{name: t.word.src, line: t.line}
	p.skipNewlines()
	if n := p.peek(); isKw(n, "in") {
		p.next()
		c.hasIn = true
		for {
			t := p.next()
			if t.kind == tkWord {
				c.items = append(c.items, p.braceWord(t.word))
				continue
			}
			if t.kind == tkNewline || (t.kind == tkOp && t.op == ";") {
				break
			}
			p.unexpected(t)
		}
	} else if n.kind == tkOp && n.op == ";" {
		p.next()
	}
	p.skipNewlines()
	p.push("do")
	p.expectWord("do")
	p.pop()
	p.push("done")
	c.body = p.parseCompoundList(false)
	p.expectWord("done")
	p.pop()
	return c
}

func (p *parser) parseArithFor(t *token) command {
	parts := strings.Split(t.text, ";")
	if len(parts) != 3 {
		panic(&syntaxError{tok: "((" + t.text + "))", line: t.line})
	}
	c := &arithFor{
		init: p.arithWord(parts[0], t.line),
		cond: p.arithWord(parts[1], t.line),
		step: p.arithWord(parts[2], t.line),
		line: t.line,
	}
	if n := p.peek(); n.kind == tkOp && n.op == ";" {
		p.next()
	}
	p.skipNewlines()
	p.push("do")
	p.expectWord("do")
	p.pop()
	p.push("done")
	c.body = p.parseCompoundList(false)
	p.expectWord("done")
	p.pop()
	return c
}

func (p *parser) parseWhile() command {
	t := p.next()
	c := &whileClause{until: t.word.src == "until"}
	p.push("do")
	c.cond = p.parseCompoundList(false)
	p.expectWord("do")
	p.pop()
	p.push("done")
	c.body = p.parseCompoundList(false)
	p.expectWord("done")
	p.pop()
	return c
}

func (p *parser) parseCase() command {
	start := p.next()
	t := p.next()
	if t.kind != tkWord {
		p.unexpected(t)
	}
	c := &caseClause{subject: t.word, line: start.line}
	p.skipNewlines()
	p.push("in")
	p.expectWord("in")
	p.pop()
	p.push("esac")
	defer p.pop()
	for {
		p.skipNewlines()
		t := p.peek()
		if isKw(t, "esac") {
			p.next()
			return c
		}
		if t.kind == tkOp && t.op == "(" {
			p.next()
		}
		item := &caseItem{}
		for {
			t := p.next()
			if t.kind != tkWord {
				p.unexpected(t)
			}
			item.patterns = append(item.patterns, t.word)
			n := p.next()
			if n.kind == tkOp && n.op == "|" {
				continue
			}
			if n.kind == tkOp && n.op == ")" {
				break
			}
			p.unexpected(n)
		}
		item.body = p.parseCompoundList(true)
		c.items = append(c.items, item)
		t = p.peek()
		if t.kind == tkOp && (t.op == ";;" || t.op == ";&" || t.op == ";;&") {
			p.next()
			item.term = t.op
			continue
		}
		if !isKw(t, "esac") {
			p.unexpected(t)
		}
	}
}

// parseCond parses [[ ... ]]. Inside it && || ( ) < > are operators of the
// conditional expression, so they are kept as text.
func (p *parser) parseCond() command {
	start := p.next()
	c := &condCmd{line: start.line}
	p.push("]]")
	defer p.pop()
	for {
		t := p.next()
		switch t.kind {
		case tkWord:
			if t.word.src == "]]" {
				if len(c.items) == 0 {
					p.unexpected(t)
				}
				return c
			}
			c.items = append(c.items, condItem{w: t.word})
		case tkOp:
			switch t.op {
			case "&&", "||", "(", ")":
				c.items = append(c.items, condItem{op: t.op})
			default:
				p.unexpected(t)
			}
		case tkRedir:
			if (t.op == "<" || t.op == ">") && t.fd < 0 {
				c.items = append(c.items, condItem{op: t.op})
				continue
			}
			p.unexpected(t)
		case tkNewline:
		default:
			p.unexpected(t)
		}
	}
}

// braceWord applies brace expansion to a word's source text.
func (p *parser) braceWord(w *word) *word {
	if !strings.Contains(w.src, "{") {
		return w
	}
	budget := maxBraceWords
	alts := expandBraces(w.src, &budget)
	if len(alts) <= 1 {
		return w
	}
	out := &word{src: w.src}
	for _, a := range alts {
		sub := p.subParser(a, p.line)
		parts := sub.readParts(func(byte) bool { return false })
		out.alts = append(out.alts, &word{parts: tildePrefix(parts), src: a})
	}
	return out
}
