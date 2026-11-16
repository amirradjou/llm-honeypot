package shell

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// The lexer works on demand for the parser: it reads one token at a time
// from the source, so here-documents and $(...) (which is parsed by the
// same parser, recursively) fall out naturally.

type tokKind int

const (
	tkEOF tokKind = iota
	tkNewline
	tkWord
	tkOp    // ; & | && || ;; ;& ;;& ( ) |&
	tkRedir // a redirection operator, with an optional fd number
	tkArith // (( ... )) in command position; text holds the expression
)

type token struct {
	kind tokKind
	op   string
	fd   int
	word *word
	text string
	line int
	pos  int // where the token starts in the source
}

// display is how bash names the token in a syntax error.
func (t *token) display() string {
	switch t.kind {
	case tkNewline:
		return "newline"
	case tkWord:
		return t.word.src
	case tkArith:
		return "(("
	}
	return t.op
}

// syntaxError is a parse failure, worded later for bash or dash.
type syntaxError struct {
	tok       string // offending token; "" with eof set means end of input
	eof       bool
	eofMatch  string // unterminated quote or bracket: "'", "\"", "`", ")", "}"
	expecting string // dash: the keyword the parser was waiting for
	line      int
}

func (e *syntaxError) Error() string {
	switch {
	case e.eofMatch != "":
		return "unexpected EOF while looking for matching `" + e.eofMatch + "'"
	case e.eof:
		return "syntax error: unexpected end of file"
	}
	return "syntax error near unexpected token `" + e.tok + "'"
}

// dashText is the same error in dash's words.
func (e *syntaxError) dashText() string {
	switch {
	case e.eofMatch == "'" || e.eofMatch == "\"" || e.eofMatch == "`":
		return "Unterminated quoted string"
	case e.eofMatch != "":
		return "end of file unexpected (expecting \"" + e.eofMatch + "\")"
	case e.eof && e.expecting != "":
		return "end of file unexpected (expecting \"" + e.expecting + "\")"
	case e.eof:
		return "end of file unexpected"
	case e.tok == "newline":
		return "newline unexpected"
	}
	return "\"" + e.tok + "\" unexpected"
}

// maxParseDepth bounds nesting ($( inside $( inside ...) so a hostile line
// cannot drive the parser into unbounded recursion.
const maxParseDepth = 100

type parser struct {
	src      string
	pos      int
	line     int
	peeked   *token
	depth    int
	heredocs []*redir // waiting for the next newline
	closers  []string // keywords being waited for, innermost last (for dash)
}

func newParser(src string) *parser { return &parser{src: src, line: 1} }

func (p *parser) peek() *token {
	if p.peeked == nil {
		p.peeked = p.lex()
	}
	return p.peeked
}

func (p *parser) next() *token {
	t := p.peek()
	p.peeked = nil
	return t
}

func (p *parser) has(s string) bool { return strings.HasPrefix(p.src[p.pos:], s) }

// eofLine is the line bash blames for "unexpected end of file": the line
// after the last one, since the input ends with an implicit newline.
func (p *parser) eofLine() int {
	if len(p.src) > 0 && p.src[len(p.src)-1] != '\n' {
		return p.line + 1
	}
	return p.line
}

func (p *parser) failEOFMatch(what string) {
	panic(&syntaxError{eofMatch: what, line: p.line})
}

func (p *parser) lex() *token {
	p.skipBlanks()
	start := p.pos
	t := p.lex0()
	t.pos = start
	return t
}

// skipBlanks skips spaces, tabs, escaped newlines and comments.
func (p *parser) skipBlanks() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' {
			p.pos++
			continue
		}
		if c == '\\' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '\n' {
			p.pos += 2
			p.line++
			continue
		}
		if c == '#' {
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		break
	}
}

func (p *parser) lex0() *token {
	if p.pos >= len(p.src) {
		// A here-document with no body before the end of input is empty.
		for _, r := range p.heredocs {
			r.body = &word{}
		}
		p.heredocs = nil
		return &token{kind: tkEOF, line: p.eofLine()}
	}
	line := p.line
	op := func(s string) *token {
		p.pos += len(s)
		return &token{kind: tkOp, op: s, line: line}
	}
	switch p.src[p.pos] {
	case '\n':
		p.pos++
		p.line++
		p.readHeredocs()
		return &token{kind: tkNewline, line: line}
	case ';':
		for _, s := range []string{";;&", ";;", ";&"} {
			if p.has(s) {
				return op(s)
			}
		}
		return op(";")
	case '&':
		switch {
		case p.has("&&"):
			return op("&&")
		case p.has("&>>"):
			p.pos += 3
			return &token{kind: tkRedir, op: "&>>", fd: -1, line: line}
		case p.has("&>"):
			p.pos += 2
			return &token{kind: tkRedir, op: "&>", fd: -1, line: line}
		}
		return op("&")
	case '|':
		if p.has("||") {
			return op("||")
		}
		if p.has("|&") {
			return op("|&")
		}
		return op("|")
	case '(':
		if p.has("((") {
			if end, ok := p.scanArith(p.pos + 2); ok {
				text := p.src[p.pos+2 : end]
				p.line += strings.Count(text, "\n")
				p.pos = end + 2
				return &token{kind: tkArith, text: text, line: line}
			}
		}
		return op("(")
	case ')':
		return op(")")
	case '<', '>':
		return p.lexRedir(-1)
	}
	return p.lexWord()
}

var redirOps = []string{"<<<", "<<-", "<<", "<&", "<>", "<", ">>", ">&", ">|", ">"}

func (p *parser) lexRedir(fd int) *token {
	for _, op := range redirOps {
		if p.has(op) {
			p.pos += len(op)
			return &token{kind: tkRedir, op: op, fd: fd, line: p.line}
		}
	}
	panic("lexRedir called off an operator")
}

// scanArith finds the "))" closing an arithmetic expression whose text
// starts at start. It reports false when the parentheses do not close
// that way, which means "((" was really two subshell parentheses.
func (p *parser) scanArith(start int) (int, bool) {
	depth := 0
	for i := start; i < len(p.src); i++ {
		switch p.src[i] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				if i+1 < len(p.src) && p.src[i+1] == ')' {
					return i, true
				}
				return 0, false
			}
			depth--
		}
	}
	return 0, false
}

func isMeta(c byte) bool {
	switch c {
	case ' ', '\t', '\n', ';', '&', '|', '<', '>', '(', ')':
		return true
	}
	return false
}

func (p *parser) lexWord() *token {
	start, line := p.pos, p.line
	parts := p.readParts(isMeta)
	src := p.src[start:p.pos]
	// An all-digit word right before < or > is a file descriptor number.
	if p.pos < len(p.src) && (p.src[p.pos] == '<' || p.src[p.pos] == '>') && isDigits(src) {
		fd, err := strconv.Atoi(src)
		if err != nil || fd > 9999 {
			fd = 9999
		}
		return p.lexRedir(fd)
	}
	return &token{kind: tkWord, word: &word{parts: tildePrefix(parts), src: src}, line: line}
}

// readParts reads word parts until stop is true for an unquoted byte.
func (p *parser) readParts(stop func(byte) bool) []wpart {
	var parts []wpart
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, &wLit{s: lit.String()})
			lit.Reset()
		}
	}
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if stop(c) {
			break
		}
		switch c {
		case '\\':
			if p.pos+1 >= len(p.src) {
				lit.WriteByte('\\')
				p.pos++
				continue
			}
			if p.src[p.pos+1] == '\n' {
				p.pos += 2
				p.line++
				continue
			}
			flush()
			_, n := utf8.DecodeRuneInString(p.src[p.pos+1:])
			parts = append(parts, &wQuoted{s: p.src[p.pos+1 : p.pos+1+n]})
			p.pos += 1 + n
		case '\'':
			flush()
			parts = append(parts, p.lexSingle())
		case '"':
			flush()
			p.pos++
			parts = append(parts, &wDouble{parts: p.readDQ(dqString)})
		case '`':
			flush()
			parts = append(parts, p.lexBacktick(false))
		case '$':
			if part := p.lexDollar(false); part != nil {
				flush()
				parts = append(parts, part)
			} else {
				lit.WriteByte('$')
				p.pos++
			}
		case '\n':
			p.line++
			lit.WriteByte(c)
			p.pos++
		default:
			lit.WriteByte(c)
			p.pos++
		}
	}
	flush()
	return parts
}

func (p *parser) lexSingle() wpart {
	end := strings.IndexByte(p.src[p.pos+1:], '\'')
	if end < 0 {
		p.line += strings.Count(p.src[p.pos:], "\n")
		p.failEOFMatch("'")
	}
	s := p.src[p.pos+1 : p.pos+1+end]
	p.line += strings.Count(s, "\n")
	p.pos += end + 2
	return &wQuoted{s: s}
}

// Modes for readDQ.
const (
	dqString  = iota // inside "...": ends at the closing quote
	dqHeredoc        // a here-document body: " is literal, ends at EOF
	dqArith          // $((...)): quotes are removed, ends at EOF
)

// readDQ reads double-quote-style text: $ expansions and backquotes are
// recognised, a backslash only escapes $ ` " \ and newline, everything
// else is literal. In dqString mode p.pos is just past the opening quote
// and is left just past the closing one.
func (p *parser) readDQ(mode int) []wpart {
	var parts []wpart
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, &wQuoted{s: lit.String()})
			lit.Reset()
		}
	}
	for {
		if p.pos >= len(p.src) {
			if mode == dqString {
				p.failEOFMatch("\"")
			}
			flush()
			return parts
		}
		c := p.src[p.pos]
		switch c {
		case '"':
			switch mode {
			case dqString:
				p.pos++
				flush()
				return parts
			case dqArith:
				p.pos++
				continue
			}
			lit.WriteByte(c)
			p.pos++
		case '\\':
			if p.pos+1 < len(p.src) {
				n := p.src[p.pos+1]
				if n == '$' || n == '`' || n == '\\' || (n == '"' && mode != dqHeredoc) {
					lit.WriteByte(n)
					p.pos += 2
					continue
				}
				if n == '\n' {
					p.pos += 2
					p.line++
					continue
				}
			}
			lit.WriteByte('\\')
			p.pos++
		case '$':
			if part := p.lexDollar(true); part != nil {
				flush()
				parts = append(parts, part)
			} else {
				lit.WriteByte('$')
				p.pos++
			}
		case '`':
			flush()
			parts = append(parts, p.lexBacktick(mode == dqString))
		case '\n':
			p.line++
			lit.WriteByte(c)
			p.pos++
		default:
			lit.WriteByte(c)
			p.pos++
		}
	}
}

// subParser parses text taken out of this source (backquotes, $((...)),
// here-document bodies) at one more level of nesting.
func (p *parser) subParser(src string, line int) *parser {
	if p.depth >= maxParseDepth {
		panic(&syntaxError{tok: src, line: p.line})
	}
	return &parser{src: src, line: line, depth: p.depth + 1}
}

func (p *parser) lexBacktick(inDQ bool) wpart {
	startLine := p.line
	start := p.pos
	p.pos++
	var b strings.Builder
	for {
		if p.pos >= len(p.src) {
			p.failEOFMatch("`")
		}
		c := p.src[p.pos]
		if c == '`' {
			p.pos++
			break
		}
		if c == '\\' && p.pos+1 < len(p.src) {
			n := p.src[p.pos+1]
			if n == '$' || n == '`' || n == '\\' || (inDQ && n == '"') {
				b.WriteByte(n)
				p.pos += 2
				continue
			}
		}
		if c == '\n' {
			p.line++
		}
		b.WriteByte(c)
		p.pos++
	}
	body := p.subParser(b.String(), startLine).parseAll()
	return &wCmdSub{body: body, src: p.src[start:p.pos]}
}

// lexDollar reads an expansion starting at the $ under p.pos. It returns
// nil, consuming nothing, when the $ is just a literal dollar sign.
func (p *parser) lexDollar(inDQ bool) wpart {
	if p.pos+1 >= len(p.src) {
		return nil
	}
	n := p.src[p.pos+1]
	switch {
	case n == '(':
		if p.pos+2 < len(p.src) && p.src[p.pos+2] == '(' {
			if end, ok := p.scanArith(p.pos + 3); ok {
				start := p.pos
				text := p.src[p.pos+3 : end]
				sub := p.subParser(text, p.line)
				expr := &word{parts: []wpart{&wDouble{parts: sub.readDQ(dqArith)}}, src: text}
				p.line += strings.Count(text, "\n")
				p.pos = end + 2
				return &wArith{expr: expr, src: p.src[start:p.pos]}
			}
		}
		return p.lexCmdSubst()
	case n == '{':
		return p.lexBraceParam()
	case n == '\'' && !inDQ:
		p.pos++
		return p.lexANSIC()
	case n == '"' && !inDQ:
		p.pos += 2
		return &wDouble{parts: p.readDQ(dqString)}
	case isNameStart(rune(n)):
		j := p.pos + 1
		for j < len(p.src) && isNameChar(rune(p.src[j])) {
			j++
		}
		name := p.src[p.pos+1 : j]
		p.pos = j
		return &wParam{name: name, src: "$" + name}
	case n >= '0' && n <= '9', strings.IndexByte("?$!#@*-", n) >= 0:
		p.pos += 2
		return &wParam{name: string(n), src: "$" + string(n)}
	}
	return nil
}

func (p *parser) lexCmdSubst() wpart {
	start, startLine := p.pos, p.line
	if p.depth >= maxParseDepth {
		panic(&syntaxError{tok: "$(", line: p.line})
	}
	p.pos += 2
	p.depth++
	saved := p.peeked
	p.peeked = nil
	body := p.parseCompoundList(true)
	t := p.next()
	if t.kind == tkEOF {
		panic(&syntaxError{eofMatch: ")", line: startLine})
	}
	if t.kind != tkOp || t.op != ")" {
		p.unexpected(t)
	}
	p.depth--
	p.peeked = saved
	return &wCmdSub{body: body, src: p.src[start:p.pos]}
}

// lexANSIC reads $'...' with p.pos on the opening quote.
func (p *parser) lexANSIC() wpart {
	var b strings.Builder
	i := p.pos + 1
	for {
		if i >= len(p.src) {
			p.failEOFMatch("'")
		}
		c := p.src[i]
		if c == '\'' {
			break
		}
		if c == '\n' {
			p.line++
		}
		if c != '\\' || i+1 >= len(p.src) {
			b.WriteByte(c)
			i++
			continue
		}
		i++
		e := p.src[i]
		i++
		switch e {
		case 'a':
			b.WriteByte(7)
		case 'b':
			b.WriteByte(8)
		case 'e', 'E':
			b.WriteByte(27)
		case 'f':
			b.WriteByte(12)
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte(11)
		case '\\', '\'', '"', '?':
			b.WriteByte(e)
		case 'x':
			v, n := 0, 0
			for n < 2 && i < len(p.src) && isHex(p.src[i]) {
				v = v*16 + hexVal(p.src[i])
				i++
				n++
			}
			if n == 0 {
				b.WriteString(`\x`)
			} else {
				b.WriteByte(byte(v))
			}
		case 'u', 'U':
			max := 4
			if e == 'U' {
				max = 8
			}
			v, n := 0, 0
			for n < max && i < len(p.src) && isHex(p.src[i]) {
				v = v*16 + hexVal(p.src[i])
				i++
				n++
			}
			if n == 0 {
				b.WriteByte('\\')
				b.WriteByte(e)
			} else {
				b.WriteRune(rune(v))
			}
		case 'c':
			if i < len(p.src) {
				b.WriteByte(p.src[i] & 0x1f)
				i++
			}
		default:
			if e >= '0' && e <= '7' {
				v, n := int(e-'0'), 1
				for n < 3 && i < len(p.src) && p.src[i] >= '0' && p.src[i] <= '7' {
					v = v*8 + int(p.src[i]-'0')
					i++
					n++
				}
				b.WriteByte(byte(v))
			} else {
				b.WriteByte('\\')
				b.WriteByte(e)
			}
		}
	}
	p.pos = i + 1
	return &wQuoted{s: b.String()}
}

// lexBraceParam reads ${...} with p.pos on the $.
func (p *parser) lexBraceParam() wpart {
	start, startLine := p.pos, p.line
	p.pos += 2
	wp := &wParam{}
	if p.pos+1 < len(p.src) && p.src[p.pos] == '#' && p.src[p.pos+1] != '}' {
		wp.op = "len"
		p.pos++
	} else if p.pos+1 < len(p.src) && p.src[p.pos] == '!' && p.src[p.pos+1] != '}' {
		wp.ind = true
		p.pos++
	}
	wp.name = p.scanParamName()
	if wp.name == "" || p.pos >= len(p.src) {
		return p.badParam(start, startLine)
	}
	finish := func() wpart {
		if p.pos >= len(p.src) || p.src[p.pos] != '}' {
			if p.pos >= len(p.src) {
				panic(&syntaxError{eofMatch: "}", line: startLine})
			}
			return p.badParam(start, startLine)
		}
		p.pos++
		wp.src = p.src[start:p.pos]
		return wp
	}
	if p.src[p.pos] == '}' {
		return finish()
	}
	if wp.op == "len" {
		return p.badParam(start, startLine)
	}
	untilBrace := func(c byte) bool { return c == '}' }
	arg := func(stop func(byte) bool) *word {
		s := p.pos
		parts := p.readParts(stop)
		return &word{parts: parts, src: p.src[s:p.pos]}
	}
	rest := p.src[p.pos:]
	switch {
	case strings.HasPrefix(rest, ":-"), strings.HasPrefix(rest, ":="), strings.HasPrefix(rest, ":?"), strings.HasPrefix(rest, ":+"),
		strings.HasPrefix(rest, "##"), strings.HasPrefix(rest, "%%"), strings.HasPrefix(rest, "^^"), strings.HasPrefix(rest, ",,"):
		wp.op = rest[:2]
		p.pos += 2
		wp.arg = arg(untilBrace)
	case rest[0] == ':':
		wp.op = ":"
		p.pos++
		wp.arg = arg(func(c byte) bool { return c == '}' || c == ':' })
		if p.pos < len(p.src) && p.src[p.pos] == ':' {
			p.pos++
			wp.arg2 = arg(untilBrace)
		}
	case strings.IndexByte("-=?+#%^,", rest[0]) >= 0:
		wp.op = rest[:1]
		p.pos++
		wp.arg = arg(untilBrace)
	case rest[0] == '/':
		wp.op = "/"
		p.pos++
		if p.pos < len(p.src) && strings.IndexByte("/#%", p.src[p.pos]) >= 0 {
			wp.op += string(p.src[p.pos])
			p.pos++
		}
		wp.arg = arg(func(c byte) bool { return c == '}' || c == '/' })
		if p.pos < len(p.src) && p.src[p.pos] == '/' {
			p.pos++
			wp.arg2 = arg(untilBrace)
		}
	default:
		return p.badParam(start, startLine)
	}
	return finish()
}

func (p *parser) scanParamName() string {
	s := p.pos
	if s >= len(p.src) {
		return ""
	}
	c := p.src[s]
	switch {
	case isNameStart(rune(c)):
		j := s
		for j < len(p.src) && isNameChar(rune(p.src[j])) {
			j++
		}
		p.pos = j
	case c >= '0' && c <= '9':
		j := s
		for j < len(p.src) && p.src[j] >= '0' && p.src[j] <= '9' {
			j++
		}
		p.pos = j
	case strings.IndexByte("@*#?$!-", c) >= 0:
		p.pos++
	default:
		return ""
	}
	return p.src[s:p.pos]
}

// badParam skips to the closing brace of a ${...} bash cannot parse; the
// error ("bad substitution") is reported when the word is expanded.
func (p *parser) badParam(start, startLine int) wpart {
	end := strings.IndexByte(p.src[start:], '}')
	if end < 0 {
		panic(&syntaxError{eofMatch: "}", line: startLine})
	}
	p.line += strings.Count(p.src[p.pos:start+end], "\n")
	p.pos = start + end + 1
	return &wParam{op: "bad", src: p.src[start:p.pos]}
}

// tildePrefix turns a leading unquoted ~ or ~user into a wTilde part.
func tildePrefix(parts []wpart) []wpart {
	if len(parts) == 0 {
		return parts
	}
	lit, ok := parts[0].(*wLit)
	if !ok || !strings.HasPrefix(lit.s, "~") {
		return parts
	}
	user, rest := lit.s[1:], ""
	if i := strings.IndexByte(user, '/'); i >= 0 {
		user, rest = user[:i], user[i:]
	} else if len(parts) > 1 {
		return parts // ~"x" or ~$x: the prefix is not plain, bash leaves it
	}
	if user != "+" && user != "-" && !validUser(user) {
		return parts
	}
	out := []wpart{&wTilde{user: user}}
	if rest != "" {
		out = append(out, &wLit{s: rest})
	}
	return append(out, parts[1:]...)
}

// tildeAssign expands ~ at the start of an assignment value and after
// each unquoted colon (PATH=~/bin:~/x).
func tildeAssign(parts []wpart) []wpart {
	var out []wpart
	for i, part := range parts {
		lit, ok := part.(*wLit)
		if !ok {
			out = append(out, part)
			continue
		}
		segs := strings.Split(lit.s, ":")
		for j, seg := range segs {
			if j > 0 {
				out = append(out, &wLit{s: ":"})
			}
			atStart := j > 0 || (i == 0)
			last := j == len(segs)-1 && i < len(parts)-1
			if atStart && strings.HasPrefix(seg, "~") && !last {
				user, rest := seg[1:], ""
				if k := strings.IndexByte(user, '/'); k >= 0 {
					user, rest = user[:k], user[k:]
				}
				if validUser(user) {
					out = append(out, &wTilde{user: user})
					if rest != "" {
						out = append(out, &wLit{s: rest})
					}
					continue
				}
			}
			if seg != "" {
				out = append(out, &wLit{s: seg})
			}
		}
	}
	return out
}

func validUser(u string) bool {
	for _, r := range u {
		if !(isNameChar(r) || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isNameStart(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

func isNameChar(r rune) bool { return isNameStart(r) || (r >= '0' && r <= '9') }

func isName(s string) bool {
	if s == "" || !isNameStart(rune(s[0])) {
		return false
	}
	for _, r := range s {
		if !isNameChar(r) {
			return false
		}
	}
	return true
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' }
