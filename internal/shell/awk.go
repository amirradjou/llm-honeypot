package shell

import (
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// A small awk: enough of the language for the one-liners bots pipe system
// information through (`awk '{print $2}'`, `awk -F: '$3==0 {print $1}'`,
// `awk 'FNR == 2 {print $2;}'`, `{s+=$1} END {print s}`). Patterns, BEGIN and
// END, print/printf, if/else, next/exit, arithmetic, string concatenation,
// regex matching and the common string functions are supported. There are
// no loops, arrays or getline, so a program runs in time linear in its input
// and cannot be made to spin.

const mawkVersion = `mawk 1.3.4 20200120
Copyright 2008-2019,2020, Thomas E. Dickey
Copyright 1991-1996,2014, Michael D. Brennan

random-funcs:       srandom/random
regex-funcs:        internal
compiled limits:
sprintf buffer      8192
maximum-integer     2147483647
`

func cmdAwk(c *Context) int {
	args := c.Args[1:]
	fs := " "
	var assigns []string
	var prog string
	haveProg := false
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--version" || a == "-Wversion" || (a == "-W" && len(args) > 1 && args[1] == "version"):
			c.Print(mawkVersion)
			return 0
		case a == "--":
			args = args[1:]
			goto operands
		case a == "-F" && len(args) > 1:
			fs, args = args[1], args[2:]
		case strings.HasPrefix(a, "-F"):
			fs, args = a[2:], args[1:]
		case a == "-v" && len(args) > 1:
			assigns, args = append(assigns, args[1]), args[2:]
		case strings.HasPrefix(a, "-v") && len(a) > 2:
			assigns, args = append(assigns, a[2:]), args[1:]
		case a == "-f" && len(args) > 1:
			data, err := c.readTarget(args[1])
			if err != nil {
				fmt.Fprintf(c.Stderr, "awk: couldn't open file %s\n", args[1])
				return 2
			}
			prog, haveProg, args = string(data), true, args[2:]
		case strings.HasPrefix(a, "-") && len(a) > 1:
			fmt.Fprintf(c.Stderr, "awk: not an option: %s\n", a)
			return 2
		default:
			goto operands
		}
	}
operands:
	if !haveProg {
		if len(args) == 0 {
			fmt.Fprint(c.Stderr, "usage: awk [-F value] [-v var=value] [--] 'program text' [file ...]\nusage: awk [-F value] [-v var=value] [-f program-file] [--] [file ...]\n")
			return 2
		}
		prog, args = args[0], args[1:]
	}

	p, err := parseAwk(prog)
	if err != nil {
		fmt.Fprintf(c.Stderr, "awk: line 1: %s\n", err)
		return 2
	}
	vm := newAwkVM(c, p)
	vm.setVar("FS", awkStr(unescapeAwk(fs)))
	for _, a := range assigns {
		if name, val, ok := strings.Cut(a, "="); ok {
			vm.setVar(name, awkStrnum(unescapeAwk(val)))
		}
	}
	return vm.run(args)
}

// --- values ---

type awkKind uint8

const (
	kNum    awkKind = iota // a number
	kStr                   // a string
	kStrnum                // input that looks numeric: compares as a number
)

type awkVal struct {
	kind awkKind
	s    string
	n    float64
}

func awkNum(n float64) awkVal { return awkVal{kind: kNum, n: n} }
func awkStr(s string) awkVal  { return awkVal{kind: kStr, s: s} }

// awkStrnum types field and -v input: numeric-looking text compares as a
// number, anything else as a string.
func awkStrnum(s string) awkVal {
	t := strings.TrimSpace(s)
	if f, err := strconv.ParseFloat(t, 64); err == nil && t != "" && !strings.ContainsAny(t, "xXnN") {
		return awkVal{kind: kStrnum, s: s, n: f}
	}
	return awkVal{kind: kStr, s: s}
}

func (v awkVal) num() float64 {
	if v.kind != kStr {
		return v.n
	}
	return leadingNumber(v.s)
}

func (v awkVal) str() string {
	if v.kind == kNum {
		return formatAwkNum(v.n)
	}
	return v.s
}

func (v awkVal) truthy() bool {
	switch v.kind {
	case kNum:
		return v.n != 0
	case kStrnum:
		return v.n != 0
	}
	return v.s != ""
}

func formatAwkNum(n float64) string {
	if n == math.Trunc(n) && math.Abs(n) < 1e16 {
		return strconv.FormatInt(int64(n), 10)
	}
	return strconv.FormatFloat(n, 'g', 6, 64)
}

// leadingNumber reads the numeric prefix of s the way strtod does.
func leadingNumber(s string) float64 {
	s = strings.TrimLeft(s, " \t\n")
	end := 0
	seenDigit, seenDot, seenExp := false, false, false
	for end < len(s) {
		ch := s[end]
		switch {
		case ch >= '0' && ch <= '9':
			seenDigit = true
		case ch == '.' && !seenDot && !seenExp:
			seenDot = true
		case (ch == '+' || ch == '-') && (end == 0 || s[end-1] == 'e' || s[end-1] == 'E'):
		case (ch == 'e' || ch == 'E') && seenDigit && !seenExp:
			seenExp = true
		default:
			goto done
		}
		end++
	}
done:
	for end > 0 {
		if f, err := strconv.ParseFloat(s[:end], 64); err == nil {
			return f
		}
		end--
	}
	return 0
}

// --- lexer ---

type awkTokKind int

const (
	atEOF awkTokKind = iota
	atNewline
	atNumber
	atString
	atRegex
	atName
	atFunc
	atKeyword
	atPunct
)

type awkTok struct {
	kind awkTokKind
	val  string
	num  float64
}

var awkKeywords = map[string]bool{"BEGIN": true, "END": true, "print": true, "printf": true, "if": true, "else": true, "next": true, "exit": true}
var awkFuncs = map[string]bool{"length": true, "substr": true, "index": true, "tolower": true, "toupper": true, "int": true, "sprintf": true, "sub": true, "gsub": true, "match": true}
var awkUnsupported = map[string]bool{"for": true, "while": true, "do": true, "function": true, "getline": true, "delete": true, "in": true, "split": true}

func lexAwk(src string) ([]awkTok, error) {
	var toks []awkTok
	rs := []rune(src)
	// A '/' starts a regex unless the previous token ends an operand.
	regexAllowed := func() bool {
		if len(toks) == 0 {
			return true
		}
		t := toks[len(toks)-1]
		switch t.kind {
		case atNumber, atString, atName, atRegex:
			return false
		case atPunct:
			return t.val != ")" && t.val != "$" && t.val != "++" && t.val != "--"
		case atKeyword:
			return true
		}
		return true
	}
	for i := 0; i < len(rs); {
		ch := rs[i]
		switch {
		case ch == '\\' && i+1 < len(rs) && rs[i+1] == '\n':
			i += 2
		case ch == ' ' || ch == '\t' || ch == '\r':
			i++
		case ch == '\n':
			toks = append(toks, awkTok{kind: atNewline})
			i++
		case ch == '#':
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
		case ch == '"':
			var b strings.Builder
			j := i + 1
			for ; j < len(rs) && rs[j] != '"'; j++ {
				if rs[j] == '\\' && j+1 < len(rs) {
					j++
					b.WriteString(awkEscape(rs[j]))
					continue
				}
				b.WriteRune(rs[j])
			}
			if j >= len(rs) {
				return nil, fmt.Errorf("runaway string constant \"%s ...", string(rs[i+1:min(len(rs), i+11)]))
			}
			toks = append(toks, awkTok{kind: atString, val: b.String()})
			i = j + 1
		case ch == '/' && regexAllowed():
			var b strings.Builder
			j := i + 1
			for ; j < len(rs) && rs[j] != '/'; j++ {
				if rs[j] == '\\' && j+1 < len(rs) {
					if rs[j+1] == '/' {
						b.WriteRune('/')
					} else {
						b.WriteRune('\\')
						b.WriteRune(rs[j+1])
					}
					j++
					continue
				}
				if rs[j] == '\n' {
					break
				}
				b.WriteRune(rs[j])
			}
			if j >= len(rs) || rs[j] != '/' {
				return nil, fmt.Errorf("runaway regular expression /%s ...", string(rs[i+1:min(len(rs), i+11)]))
			}
			toks = append(toks, awkTok{kind: atRegex, val: b.String()})
			i = j + 1
		case unicode.IsDigit(ch) || (ch == '.' && i+1 < len(rs) && unicode.IsDigit(rs[i+1])):
			j := i
			for j < len(rs) && (unicode.IsDigit(rs[j]) || rs[j] == '.' || ((rs[j] == 'e' || rs[j] == 'E') && j+1 < len(rs) && (unicode.IsDigit(rs[j+1]) || rs[j+1] == '-' || rs[j+1] == '+'))) {
				if rs[j] == 'e' || rs[j] == 'E' {
					j++
				}
				j++
			}
			f, _ := strconv.ParseFloat(string(rs[i:j]), 64)
			toks = append(toks, awkTok{kind: atNumber, val: string(rs[i:j]), num: f})
			i = j
		case ch == '_' || unicode.IsLetter(ch):
			j := i
			for j < len(rs) && (rs[j] == '_' || unicode.IsLetter(rs[j]) || unicode.IsDigit(rs[j])) {
				j++
			}
			w := string(rs[i:j])
			switch {
			case awkUnsupported[w]:
				return nil, fmt.Errorf("syntax error at or near %s", w)
			case awkKeywords[w]:
				toks = append(toks, awkTok{kind: atKeyword, val: w})
			case awkFuncs[w]:
				toks = append(toks, awkTok{kind: atFunc, val: w})
			default:
				toks = append(toks, awkTok{kind: atName, val: w})
			}
			i = j
		default:
			for _, op := range []string{"+=", "-=", "*=", "/=", "%=", "^=", "==", "<=", ">=", "!=", "++", "--", "&&", "||", "!~", ">>"} {
				if strings.HasPrefix(string(rs[i:min(len(rs), i+2)]), op) {
					toks = append(toks, awkTok{kind: atPunct, val: op})
					i += 2
					goto next
				}
			}
			if !strings.ContainsRune("{}()[];,+-*/%^!><|?:~$=", ch) {
				return nil, fmt.Errorf("syntax error at or near %c", ch)
			}
			toks = append(toks, awkTok{kind: atPunct, val: string(ch)})
			i++
		next:
		}
	}
	return append(toks, awkTok{kind: atEOF}), nil
}

func awkEscape(r rune) string {
	switch r {
	case 'n':
		return "\n"
	case 't':
		return "\t"
	case 'r':
		return "\r"
	case '\\':
		return "\\"
	case '"':
		return "\""
	case '/':
		return "/"
	case 'a':
		return "\a"
	case 'b':
		return "\b"
	case 'f':
		return "\f"
	case 'v':
		return "\v"
	}
	return "\\" + string(r)
}

// unescapeAwk applies awk string escapes to a command-line value (-F '\t').
func unescapeAwk(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		if rs[i] == '\\' && i+1 < len(rs) {
			i++
			b.WriteString(awkEscape(rs[i]))
			continue
		}
		b.WriteRune(rs[i])
	}
	return b.String()
}

// --- AST ---

type awkExpr interface{}

type (
	awkLit    struct{ v awkVal }
	awkVarRef struct{ name string }
	awkField  struct{ idx awkExpr }
	awkRegex  struct{ re *regexp.Regexp }
	awkUnary  struct {
		op string
		x  awkExpr
	}
	awkBinary struct {
		op   string
		l, r awkExpr
	}
	awkAssign struct {
		op     string
		target awkExpr
		val    awkExpr
	}
	awkIncDec struct {
		op     string // "++" or "--"
		target awkExpr
		prefix bool
	}
	awkCond struct{ cond, a, b awkExpr }
	awkCall struct {
		name string
		args []awkExpr
	}
)

type awkStmt interface{}

type (
	awkPrint struct {
		printf bool
		args   []awkExpr
		dest   awkExpr // nil for stdout
		append bool
	}
	awkIf struct {
		cond      awkExpr
		then, els awkStmt
	}
	awkBlock struct{ stmts []awkStmt }
	awkNext  struct{}
	awkExit  struct{ code awkExpr }
	awkExprS struct{ x awkExpr }
)

type awkItem struct {
	begin, end bool
	pattern    awkExpr // nil matches every record
	pattern2   awkExpr // range end, or nil
	action     *awkBlock
	inRange    bool
}

type awkProg struct{ items []*awkItem }

// --- parser ---

type awkParser struct {
	toks []awkTok
	pos  int
}

func parseAwk(src string) (*awkProg, error) {
	toks, err := lexAwk(src)
	if err != nil {
		return nil, err
	}
	p := &awkParser{toks: toks}
	prog := &awkProg{}
	defer func() {}()
	for {
		p.skipTerminators()
		if p.peek().kind == atEOF {
			return prog, nil
		}
		it, err := p.item()
		if err != nil {
			return nil, err
		}
		prog.items = append(prog.items, it)
	}
}

func (p *awkParser) peek() awkTok { return p.toks[p.pos] }
func (p *awkParser) advance() awkTok {
	t := p.toks[p.pos]
	if t.kind != atEOF {
		p.pos++
	}
	return t
}
func (p *awkParser) is(val string) bool {
	t := p.peek()
	return (t.kind == atPunct || t.kind == atKeyword) && t.val == val
}
func (p *awkParser) expect(val string) error {
	if !p.is(val) {
		return p.errAt()
	}
	p.advance()
	return nil
}
func (p *awkParser) errAt() error {
	t := p.peek()
	switch t.kind {
	case atEOF:
		return fmt.Errorf("syntax error at or near end of file")
	case atNewline:
		return fmt.Errorf("syntax error at or near end of line")
	}
	return fmt.Errorf("syntax error at or near %s", t.val)
}
func (p *awkParser) skipNewlines() {
	for p.peek().kind == atNewline {
		p.advance()
	}
}
func (p *awkParser) skipTerminators() {
	for p.peek().kind == atNewline || p.is(";") {
		p.advance()
	}
}

func (p *awkParser) item() (*awkItem, error) {
	it := &awkItem{}
	switch {
	case p.is("BEGIN"):
		p.advance()
		it.begin = true
	case p.is("END"):
		p.advance()
		it.end = true
	case p.is("{"):
	default:
		pat, err := p.expr(false)
		if err != nil {
			return nil, err
		}
		it.pattern = pat
		if p.is(",") {
			p.advance()
			p.skipNewlines()
			if it.pattern2, err = p.expr(false); err != nil {
				return nil, err
			}
		}
	}
	if !p.is("{") {
		if it.begin || it.end {
			return nil, p.errAt()
		}
		return it, nil // pattern only: print matching records
	}
	b, err := p.block()
	if err != nil {
		return nil, err
	}
	it.action = b
	return it, nil
}

func (p *awkParser) block() (*awkBlock, error) {
	if err := p.expect("{"); err != nil {
		return nil, err
	}
	b := &awkBlock{}
	for {
		p.skipTerminators()
		if p.is("}") {
			p.advance()
			return b, nil
		}
		if p.peek().kind == atEOF {
			return nil, p.errAt()
		}
		s, err := p.stmt()
		if err != nil {
			return nil, err
		}
		b.stmts = append(b.stmts, s)
		if !p.is("}") && !p.is(";") && p.peek().kind != atNewline {
			return nil, p.errAt()
		}
	}
}

func (p *awkParser) simpleOrBlock() (awkStmt, error) {
	p.skipNewlines()
	if p.is("{") {
		return p.block()
	}
	if p.is(";") {
		p.advance()
		return &awkBlock{}, nil
	}
	return p.stmt()
}

func (p *awkParser) stmt() (awkStmt, error) {
	switch {
	case p.is("{"):
		return p.block()
	case p.is("print"), p.is("printf"):
		pr := &awkPrint{printf: p.advance().val == "printf"}
		grouped := false
		if p.is("(") {
			// print (a, b) — a parenthesised list.
			save := p.pos
			p.advance()
			args, err := p.exprList(false)
			if err == nil && p.is(")") {
				p.advance()
				if p.is(">") || p.is(">>") || p.is("|") || p.is(";") || p.is("}") || p.peek().kind == atNewline || p.peek().kind == atEOF {
					pr.args, grouped = args, true
				}
			}
			if !grouped {
				p.pos = save
			}
		}
		if !grouped && !p.is(";") && !p.is("}") && !p.is(">") && !p.is(">>") && p.peek().kind != atNewline && p.peek().kind != atEOF {
			args, err := p.exprList(true)
			if err != nil {
				return nil, err
			}
			pr.args = args
		}
		if p.is(">") || p.is(">>") {
			pr.append = p.advance().val == ">>"
			dest, err := p.concat(true)
			if err != nil {
				return nil, err
			}
			pr.dest = dest
		}
		if p.is("|") {
			return nil, p.errAt()
		}
		if pr.printf && len(pr.args) == 0 {
			return nil, p.errAt()
		}
		return pr, nil
	case p.is("if"):
		p.advance()
		if err := p.expect("("); err != nil {
			return nil, err
		}
		cond, err := p.expr(false)
		if err != nil {
			return nil, err
		}
		if err := p.expect(")"); err != nil {
			return nil, err
		}
		then, err := p.simpleOrBlock()
		if err != nil {
			return nil, err
		}
		st := &awkIf{cond: cond, then: then}
		save := p.pos
		p.skipTerminators()
		if p.is("else") {
			p.advance()
			if st.els, err = p.simpleOrBlock(); err != nil {
				return nil, err
			}
		} else {
			p.pos = save
		}
		return st, nil
	case p.is("next"):
		p.advance()
		return awkNext{}, nil
	case p.is("exit"):
		p.advance()
		st := awkExit{}
		if !p.is(";") && !p.is("}") && p.peek().kind != atNewline && p.peek().kind != atEOF {
			x, err := p.expr(false)
			if err != nil {
				return nil, err
			}
			st.code = x
		}
		return st, nil
	}
	x, err := p.expr(false)
	if err != nil {
		return nil, err
	}
	return awkExprS{x}, nil
}

func (p *awkParser) exprList(noGT bool) ([]awkExpr, error) {
	var out []awkExpr
	for {
		x, err := p.expr(noGT)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
		if !p.is(",") {
			return out, nil
		}
		p.advance()
		p.skipNewlines()
	}
}

func isLvalue(x awkExpr) bool {
	switch x.(type) {
	case *awkVarRef, *awkField:
		return true
	}
	return false
}

// expr parses assignment and the conditional operator. noGT stops '>' from
// being read as a comparison inside a print list, where it is redirection.
func (p *awkParser) expr(noGT bool) (awkExpr, error) {
	lhs, err := p.ternary(noGT)
	if err != nil {
		return nil, err
	}
	for _, op := range []string{"=", "+=", "-=", "*=", "/=", "%=", "^="} {
		if p.is(op) {
			if !isLvalue(lhs) {
				return nil, p.errAt()
			}
			p.advance()
			rhs, err := p.expr(noGT)
			if err != nil {
				return nil, err
			}
			return &awkAssign{op: op, target: lhs, val: rhs}, nil
		}
	}
	return lhs, nil
}

func (p *awkParser) ternary(noGT bool) (awkExpr, error) {
	cond, err := p.or(noGT)
	if err != nil {
		return nil, err
	}
	if !p.is("?") {
		return cond, nil
	}
	p.advance()
	a, err := p.ternary(noGT)
	if err != nil {
		return nil, err
	}
	if err := p.expect(":"); err != nil {
		return nil, err
	}
	b, err := p.ternary(noGT)
	if err != nil {
		return nil, err
	}
	return &awkCond{cond, a, b}, nil
}

func (p *awkParser) or(noGT bool) (awkExpr, error) {
	l, err := p.and(noGT)
	for err == nil && p.is("||") {
		p.advance()
		p.skipNewlines()
		var r awkExpr
		if r, err = p.and(noGT); err == nil {
			l = &awkBinary{"||", l, r}
		}
	}
	return l, err
}

func (p *awkParser) and(noGT bool) (awkExpr, error) {
	l, err := p.match(noGT)
	for err == nil && p.is("&&") {
		p.advance()
		p.skipNewlines()
		var r awkExpr
		if r, err = p.match(noGT); err == nil {
			l = &awkBinary{"&&", l, r}
		}
	}
	return l, err
}

func (p *awkParser) match(noGT bool) (awkExpr, error) {
	l, err := p.compare(noGT)
	for err == nil && (p.is("~") || p.is("!~")) {
		op := p.advance().val
		var r awkExpr
		if r, err = p.compare(noGT); err == nil {
			l = &awkBinary{op, l, r}
		}
	}
	return l, err
}

func (p *awkParser) compare(noGT bool) (awkExpr, error) {
	l, err := p.concat(noGT)
	if err != nil {
		return nil, err
	}
	for _, op := range []string{"<", "<=", "==", "!=", ">=", ">"} {
		if p.is(op) && !(noGT && op == ">") {
			p.advance()
			r, err := p.concat(noGT)
			if err != nil {
				return nil, err
			}
			return &awkBinary{op, l, r}, nil
		}
	}
	return l, nil
}

// startsOperand reports whether the next token can begin a concatenated
// operand.
func (p *awkParser) startsOperand() bool {
	t := p.peek()
	switch t.kind {
	case atNumber, atString, atName, atFunc, atRegex:
		return true
	case atPunct:
		return t.val == "$" || t.val == "(" || t.val == "!" || t.val == "++" || t.val == "--" || t.val == "-"
	}
	return false
}

func (p *awkParser) concat(noGT bool) (awkExpr, error) {
	l, err := p.additive()
	if err != nil {
		return nil, err
	}
	for p.startsOperand() && !p.is("-") && !p.is("!") {
		r, err := p.additive()
		if err != nil {
			return nil, err
		}
		l = &awkBinary{"concat", l, r}
	}
	return l, nil
}

func (p *awkParser) additive() (awkExpr, error) {
	l, err := p.multiplicative()
	for err == nil && (p.is("+") || p.is("-")) {
		op := p.advance().val
		var r awkExpr
		if r, err = p.multiplicative(); err == nil {
			l = &awkBinary{op, l, r}
		}
	}
	return l, err
}

func (p *awkParser) multiplicative() (awkExpr, error) {
	l, err := p.unary()
	for err == nil && (p.is("*") || p.is("/") || p.is("%")) {
		op := p.advance().val
		var r awkExpr
		if r, err = p.unary(); err == nil {
			l = &awkBinary{op, l, r}
		}
	}
	return l, err
}

func (p *awkParser) unary() (awkExpr, error) {
	if p.is("!") || p.is("-") || p.is("+") {
		op := p.advance().val
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &awkUnary{op, x}, nil
	}
	return p.power()
}

func (p *awkParser) power() (awkExpr, error) {
	base, err := p.postfix()
	if err != nil {
		return nil, err
	}
	if p.is("^") {
		p.advance()
		exp, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &awkBinary{"^", base, exp}, nil
	}
	return base, nil
}

func (p *awkParser) postfix() (awkExpr, error) {
	x, err := p.primary()
	if err != nil {
		return nil, err
	}
	if (p.is("++") || p.is("--")) && isLvalue(x) {
		return &awkIncDec{op: p.advance().val, target: x}, nil
	}
	return x, nil
}

func (p *awkParser) primary() (awkExpr, error) {
	t := p.peek()
	switch t.kind {
	case atNumber:
		p.advance()
		return &awkLit{awkNum(t.num)}, nil
	case atString:
		p.advance()
		return &awkLit{awkStr(t.val)}, nil
	case atRegex:
		p.advance()
		re, err := compileRegex(t.val, true, false)
		if err != nil {
			return nil, fmt.Errorf("regular expression compile failed (%s)", t.val)
		}
		return &awkRegex{re}, nil
	case atName:
		p.advance()
		if p.is("[") {
			return nil, p.errAt()
		}
		return &awkVarRef{t.val}, nil
	case atFunc:
		p.advance()
		call := &awkCall{name: t.val}
		if !p.is("(") {
			if t.val == "length" {
				return call, nil
			}
			return nil, p.errAt()
		}
		p.advance()
		if !p.is(")") {
			args, err := p.exprList(false)
			if err != nil {
				return nil, err
			}
			call.args = args
		}
		if err := p.expect(")"); err != nil {
			return nil, err
		}
		return call, nil
	case atPunct:
		switch t.val {
		case "$":
			p.advance()
			idx, err := p.postfixNoIncr()
			if err != nil {
				return nil, err
			}
			return &awkField{idx}, nil
		case "(":
			p.advance()
			x, err := p.expr(false)
			if err != nil {
				return nil, err
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			return x, nil
		case "++", "--":
			p.advance()
			x, err := p.primary()
			if err != nil {
				return nil, err
			}
			if !isLvalue(x) {
				return nil, p.errAt()
			}
			return &awkIncDec{op: t.val, target: x, prefix: true}, nil
		case "-", "!":
			return p.unary()
		}
	}
	return nil, p.errAt()
}

// postfixNoIncr parses what follows '$': a primary, so $NF-1 is ($NF)-1.
func (p *awkParser) postfixNoIncr() (awkExpr, error) {
	if p.is("-") {
		p.advance()
		x, err := p.primary()
		if err != nil {
			return nil, err
		}
		return &awkUnary{"-", x}, nil
	}
	return p.primary()
}

// --- interpreter ---

type awkVM struct {
	c       *Context
	prog    *awkProg
	vars    map[string]awkVal
	fields  []string // fields[0] is $0
	nf      int
	exiting bool
	code    int
	files   map[string]*strings.Builder
	order   []string
	appends map[string]bool
}

type awkNextSignal struct{}

func newAwkVM(c *Context, p *awkProg) *awkVM {
	vm := &awkVM{c: c, prog: p, vars: map[string]awkVal{}, files: map[string]*strings.Builder{}, appends: map[string]bool{}}
	vm.vars["OFS"] = awkStr(" ")
	vm.vars["ORS"] = awkStr("\n")
	vm.vars["FS"] = awkStr(" ")
	vm.vars["SUBSEP"] = awkStr("\x1c")
	vm.vars["NR"] = awkNum(0)
	vm.vars["FNR"] = awkNum(0)
	vm.vars["RSTART"] = awkNum(0)
	vm.vars["RLENGTH"] = awkNum(-1)
	vm.fields = []string{""}
	return vm
}

func (vm *awkVM) setVar(name string, v awkVal) {
	if name == "NF" {
		vm.setNF(int(v.num()))
		return
	}
	vm.vars[name] = v
}

func (vm *awkVM) getVar(name string) awkVal {
	if name == "NF" {
		return awkNum(float64(vm.nf))
	}
	return vm.vars[name]
}

func (vm *awkVM) run(operands []string) (status int) {
	defer func() {
		vm.flushFiles()
		if status == 0 {
			status = vm.code
		}
	}()
	for _, it := range vm.prog.items {
		if it.begin && !vm.exiting {
			vm.runAction(it.action)
		}
	}
	hasMain := false
	for _, it := range vm.prog.items {
		if !it.begin {
			hasMain = true
		}
	}
	if hasMain && !vm.exiting {
		var inputs []string
		for _, a := range operands {
			if name, val, ok := strings.Cut(a, "="); ok && isAssignment(a) {
				_ = name
				_ = val
			}
			inputs = append(inputs, a)
		}
		if len(inputs) == 0 {
			inputs = []string{"-"}
		}
		for _, in := range inputs {
			if vm.exiting {
				break
			}
			if isAssignment(in) && in != "-" {
				name, val, _ := strings.Cut(in, "=")
				vm.setVar(name, awkStrnum(unescapeAwk(val)))
				continue
			}
			var data []byte
			if in == "-" {
				data, _ = io.ReadAll(vm.c.Stdin)
			} else {
				d, err := vm.c.readTarget(in)
				if err != nil {
					fmt.Fprintf(vm.c.Stderr, "awk: cannot open %s (No such file or directory)\n", in)
					vm.code = 2
					continue
				}
				data = d
				vm.vars["FILENAME"] = awkStr(in)
			}
			vm.vars["FNR"] = awkNum(0)
			text := string(data)
			text = strings.TrimSuffix(text, "\n")
			if text == "" && len(data) == 0 {
				continue
			}
			for _, rec := range strings.Split(text, "\n") {
				if vm.exiting {
					break
				}
				vm.vars["NR"] = awkNum(vm.vars["NR"].num() + 1)
				vm.vars["FNR"] = awkNum(vm.vars["FNR"].num() + 1)
				vm.setRecord(rec)
				vm.runRecord()
			}
		}
	}
	vm.exiting = false
	for _, it := range vm.prog.items {
		if it.end && !vm.exiting {
			vm.runAction(it.action)
		}
	}
	return vm.code
}

func (vm *awkVM) runRecord() {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(awkNextSignal); !ok {
				panic(r)
			}
		}
	}()
	for _, it := range vm.prog.items {
		if it.begin || it.end || vm.exiting {
			continue
		}
		if !vm.matches(it) {
			continue
		}
		if it.action == nil {
			vm.emit(nil, false, vm.fields[0]+vm.vars["ORS"].str())
			continue
		}
		vm.runAction(it.action)
	}
}

func (vm *awkVM) matches(it *awkItem) bool {
	if it.pattern == nil {
		return true
	}
	if it.pattern2 == nil {
		return vm.eval(it.pattern).truthy()
	}
	if !it.inRange {
		if vm.eval(it.pattern).truthy() {
			it.inRange = !vm.eval(it.pattern2).truthy()
			return true
		}
		return false
	}
	if vm.eval(it.pattern2).truthy() {
		it.inRange = false
	}
	return true
}

func (vm *awkVM) runAction(b *awkBlock) {
	for _, s := range b.stmts {
		if vm.exiting {
			return
		}
		vm.exec(s)
	}
}

func (vm *awkVM) exec(s awkStmt) {
	switch s := s.(type) {
	case *awkBlock:
		vm.runAction(s)
	case *awkPrint:
		var out string
		if s.printf {
			vals := make([]awkVal, len(s.args))
			for i, a := range s.args {
				vals[i] = vm.eval(a)
			}
			out = awkSprintf(vals[0].str(), vals[1:])
		} else if len(s.args) == 0 {
			out = vm.fields[0] + vm.vars["ORS"].str()
		} else {
			parts := make([]string, len(s.args))
			for i, a := range s.args {
				v := vm.eval(a)
				if v.kind == kNum {
					parts[i] = formatOutputNum(v.n)
				} else {
					parts[i] = v.s
				}
			}
			out = strings.Join(parts, vm.vars["OFS"].str()) + vm.vars["ORS"].str()
		}
		vm.emit(s.dest, s.append, out)
	case *awkIf:
		if vm.eval(s.cond).truthy() {
			vm.exec(s.then)
		} else if s.els != nil {
			vm.exec(s.els)
		}
	case awkNext:
		panic(awkNextSignal{})
	case awkExit:
		if s.code != nil {
			vm.code = int(vm.eval(s.code).num())
		}
		vm.exiting = true
	case awkExprS:
		vm.eval(s.x)
	}
}

func formatOutputNum(n float64) string {
	if n == math.Trunc(n) && math.Abs(n) < 1e16 {
		return strconv.FormatInt(int64(n), 10)
	}
	return strconv.FormatFloat(n, 'g', 6, 64)
}

func (vm *awkVM) emit(dest awkExpr, appendMode bool, s string) {
	if dest == nil {
		vm.c.Print(s)
		return
	}
	name := vm.eval(dest).str()
	if name == "/dev/stdout" || name == "-" {
		vm.c.Print(s)
		return
	}
	if name == "/dev/stderr" {
		io.WriteString(vm.c.Stderr, s)
		return
	}
	b, ok := vm.files[name]
	if !ok {
		b = &strings.Builder{}
		vm.files[name] = b
		vm.order = append(vm.order, name)
		vm.appends[name] = appendMode
	}
	b.WriteString(s)
}

func (vm *awkVM) flushFiles() {
	for _, name := range vm.order {
		abs := vm.c.Sess.abs(name)
		data := []byte(vm.files[name].String())
		var err error
		if vm.appends[name] {
			err = vm.c.FS().AppendFile(abs, data, vm.c.writeOpts())
		} else {
			err = vm.c.FS().WriteFile(abs, data, vm.c.writeOpts())
		}
		if err != nil {
			fmt.Fprintf(vm.c.Stderr, "awk: cannot open \"%s\" for output\n", name)
			vm.code = 2
		}
	}
}

func (vm *awkVM) setRecord(rec string) {
	vm.fields = append(vm.fields[:0], rec)
	vm.fields = append(vm.fields, vm.split(rec)...)
	vm.nf = len(vm.fields) - 1
}

func (vm *awkVM) split(rec string) []string {
	fs := vm.vars["FS"].str()
	switch {
	case fs == " ":
		return strings.Fields(rec)
	case rec == "":
		return nil
	case len([]rune(fs)) == 1 && fs != "\\":
		return strings.Split(rec, fs)
	}
	re, err := compileRegex(fs, true, false)
	if err != nil {
		return strings.Split(rec, fs)
	}
	return re.Split(rec, -1)
}

func (vm *awkVM) field(i int) string {
	if i < 0 {
		return ""
	}
	if i < len(vm.fields) {
		return vm.fields[i]
	}
	return ""
}

func (vm *awkVM) setField(i int, s string) {
	if i == 0 {
		vm.setRecord(s)
		return
	}
	if i > 100000 {
		return
	}
	for len(vm.fields) <= i {
		vm.fields = append(vm.fields, "")
	}
	vm.fields[i] = s
	if i > vm.nf {
		vm.nf = i
	}
	vm.rebuild()
}

func (vm *awkVM) setNF(n int) {
	if n < 0 || n > 100000 {
		return
	}
	for len(vm.fields) <= n {
		vm.fields = append(vm.fields, "")
	}
	vm.fields = vm.fields[:n+1]
	vm.nf = n
	vm.rebuild()
}

func (vm *awkVM) rebuild() {
	vm.fields[0] = strings.Join(vm.fields[1:vm.nf+1], vm.vars["OFS"].str())
}

func (vm *awkVM) get(target awkExpr) awkVal {
	switch t := target.(type) {
	case *awkVarRef:
		return vm.getVar(t.name)
	case *awkField:
		return awkStrnum(vm.field(int(vm.eval(t.idx).num())))
	}
	return awkStr("")
}

func (vm *awkVM) set(target awkExpr, v awkVal) {
	switch t := target.(type) {
	case *awkVarRef:
		vm.setVar(t.name, v)
	case *awkField:
		vm.setField(int(vm.eval(t.idx).num()), v.str())
	}
}

// eval evaluates a parsed awk expression. It is a tree walk over the AST in
// Go: nothing here runs attacker text as code.
func (vm *awkVM) eval(x awkExpr) awkVal {
	switch x := x.(type) {
	case *awkLit:
		return x.v
	case *awkVarRef:
		return vm.getVar(x.name)
	case *awkField:
		return awkStrnum(vm.field(int(vm.eval(x.idx).num())))
	case *awkRegex:
		return boolVal(x.re.MatchString(vm.fields[0]))
	case *awkUnary:
		v := vm.eval(x.x)
		switch x.op {
		case "!":
			return boolVal(!v.truthy())
		case "-":
			return awkNum(-v.num())
		}
		return awkNum(v.num())
	case *awkCond:
		if vm.eval(x.cond).truthy() {
			return vm.eval(x.a)
		}
		return vm.eval(x.b)
	case *awkAssign:
		v := vm.eval(x.val)
		if x.op != "=" {
			v = awkNum(arith(x.op[:1], vm.get(x.target).num(), v.num()))
		}
		vm.set(x.target, v)
		return v
	case *awkIncDec:
		old := vm.get(x.target).num()
		nv := old + 1
		if x.op == "--" {
			nv = old - 1
		}
		vm.set(x.target, awkNum(nv))
		if x.prefix {
			return awkNum(nv)
		}
		return awkNum(old)
	case *awkBinary:
		return vm.binary(x)
	case *awkCall:
		return vm.call(x)
	}
	return awkStr("")
}

func boolVal(b bool) awkVal {
	if b {
		return awkNum(1)
	}
	return awkNum(0)
}

func arith(op string, a, b float64) float64 {
	switch op {
	case "+":
		return a + b
	case "-":
		return a - b
	case "*":
		return a * b
	case "/":
		if b == 0 {
			return math.Inf(1)
		}
		return a / b
	case "%":
		if b == 0 {
			return math.NaN()
		}
		return math.Mod(a, b)
	case "^":
		return math.Pow(a, b)
	}
	return 0
}

func (vm *awkVM) binary(x *awkBinary) awkVal {
	switch x.op {
	case "&&":
		return boolVal(vm.eval(x.l).truthy() && vm.eval(x.r).truthy())
	case "||":
		return boolVal(vm.eval(x.l).truthy() || vm.eval(x.r).truthy())
	case "concat":
		return awkStr(vm.eval(x.l).str() + vm.eval(x.r).str())
	case "~", "!~":
		s := vm.eval(x.l).str()
		var re *regexp.Regexp
		if r, ok := x.r.(*awkRegex); ok {
			re = r.re
		} else {
			var err error
			if re, err = compileRegex(vm.eval(x.r).str(), true, false); err != nil {
				return awkNum(0)
			}
		}
		return boolVal(re.MatchString(s) == (x.op == "~"))
	case "<", "<=", "==", "!=", ">=", ">":
		l, r := vm.eval(x.l), vm.eval(x.r)
		var cmp int
		if l.kind != kStr && r.kind != kStr {
			switch {
			case l.n < r.n:
				cmp = -1
			case l.n > r.n:
				cmp = 1
			}
		} else {
			cmp = strings.Compare(l.str(), r.str())
		}
		switch x.op {
		case "<":
			return boolVal(cmp < 0)
		case "<=":
			return boolVal(cmp <= 0)
		case "==":
			return boolVal(cmp == 0)
		case "!=":
			return boolVal(cmp != 0)
		case ">=":
			return boolVal(cmp >= 0)
		}
		return boolVal(cmp > 0)
	}
	if x.op == "/" || x.op == "%" {
		if vm.eval(x.r).num() == 0 {
			fmt.Fprintf(vm.c.Stderr, "awk: division by zero\n")
			vm.code = 2
			vm.exiting = true
			return awkNum(0)
		}
	}
	return awkNum(arith(x.op, vm.eval(x.l).num(), vm.eval(x.r).num()))
}

func (vm *awkVM) call(x *awkCall) awkVal {
	arg := func(i int) awkVal {
		if i < len(x.args) {
			return vm.eval(x.args[i])
		}
		return awkStr("")
	}
	switch x.name {
	case "length":
		if len(x.args) == 0 {
			return awkNum(float64(len([]rune(vm.fields[0]))))
		}
		return awkNum(float64(len([]rune(arg(0).str()))))
	case "substr":
		rs := []rune(arg(0).str())
		start := int(math.Round(arg(1).num()))
		end := len(rs) + 1
		if len(x.args) > 2 {
			end = start + int(math.Round(arg(2).num()))
		}
		start = max(start, 1)
		end = min(end, len(rs)+1)
		if start >= end {
			return awkStr("")
		}
		return awkStr(string(rs[start-1 : end-1]))
	case "index":
		i := strings.Index(arg(0).str(), arg(1).str())
		if i < 0 {
			return awkNum(0)
		}
		return awkNum(float64(len([]rune(arg(0).str()[:i])) + 1))
	case "tolower":
		return awkStr(strings.ToLower(arg(0).str()))
	case "toupper":
		return awkStr(strings.ToUpper(arg(0).str()))
	case "int":
		return awkNum(math.Trunc(arg(0).num()))
	case "sprintf":
		if len(x.args) == 0 {
			return awkStr("")
		}
		vals := make([]awkVal, len(x.args)-1)
		for i := range vals {
			vals[i] = vm.eval(x.args[i+1])
		}
		return awkStr(awkSprintf(arg(0).str(), vals))
	case "match":
		re := vm.regexArg(x.args, 1)
		if re == nil {
			return awkNum(0)
		}
		s := arg(0).str()
		loc := re.FindStringIndex(s)
		if loc == nil {
			vm.vars["RSTART"], vm.vars["RLENGTH"] = awkNum(0), awkNum(-1)
			return awkNum(0)
		}
		vm.vars["RSTART"] = awkNum(float64(len([]rune(s[:loc[0]])) + 1))
		vm.vars["RLENGTH"] = awkNum(float64(len([]rune(s[loc[0]:loc[1]]))))
		return vm.vars["RSTART"]
	case "sub", "gsub":
		re := vm.regexArg(x.args, 0)
		if re == nil {
			return awkNum(0)
		}
		var target awkExpr = &awkField{&awkLit{awkNum(0)}}
		if len(x.args) > 2 && isLvalue(x.args[2]) {
			target = x.args[2]
		}
		src := vm.get(target).str()
		repl := arg(1).str()
		n := 0
		out := re.ReplaceAllStringFunc(src, func(m string) string {
			if x.name == "sub" && n > 0 {
				return m
			}
			n++
			return awkReplacement(repl, m)
		})
		if n > 0 {
			vm.set(target, awkStr(out))
		}
		return awkNum(float64(n))
	}
	return awkStr("")
}

func (vm *awkVM) regexArg(args []awkExpr, i int) *regexp.Regexp {
	if i >= len(args) {
		return nil
	}
	if r, ok := args[i].(*awkRegex); ok {
		return r.re
	}
	re, err := compileRegex(vm.eval(args[i]).str(), true, false)
	if err != nil {
		return nil
	}
	return re
}

// awkReplacement expands & (the match) and \& (a literal &) in a sub/gsub
// replacement.
func awkReplacement(repl, match string) string {
	var b strings.Builder
	for i := 0; i < len(repl); i++ {
		switch {
		case repl[i] == '\\' && i+1 < len(repl) && repl[i+1] == '&':
			b.WriteByte('&')
			i++
		case repl[i] == '&':
			b.WriteString(match)
		default:
			b.WriteByte(repl[i])
		}
	}
	return b.String()
}

// awkSprintf implements printf's conversions over awk values.
func awkSprintf(format string, vals []awkVal) string {
	var b strings.Builder
	next := 0
	nextVal := func() awkVal {
		if next < len(vals) {
			next++
			return vals[next-1]
		}
		return awkStr("")
	}
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			b.WriteByte(format[i])
			continue
		}
		j := i + 1
		for j < len(format) && strings.IndexByte("-+ #0", format[j]) >= 0 {
			j++
		}
		for j < len(format) && (format[j] >= '0' && format[j] <= '9' || format[j] == '.' || format[j] == '*') {
			j++
		}
		if j >= len(format) {
			b.WriteString(format[i:])
			break
		}
		spec := format[i:j]
		verb := format[j]
		i = j
		switch verb {
		case '%':
			b.WriteByte('%')
		case 'd', 'i':
			fmt.Fprintf(&b, spec+"d", int64(nextVal().num()))
		case 'u':
			fmt.Fprintf(&b, spec+"d", uint64(math.Abs(nextVal().num())))
		case 'o', 'x', 'X':
			fmt.Fprintf(&b, spec+string(verb), int64(nextVal().num()))
		case 'e', 'E', 'f', 'F', 'g', 'G':
			fmt.Fprintf(&b, spec+string(verb), nextVal().num())
		case 'c':
			v := nextVal()
			if v.kind == kNum {
				fmt.Fprintf(&b, spec+"c", rune(int(v.n)))
			} else if r := []rune(v.s); len(r) > 0 {
				fmt.Fprintf(&b, spec+"c", r[0])
			}
		case 's':
			fmt.Fprintf(&b, spec+"s", nextVal().str())
		default:
			b.WriteString(spec)
			b.WriteByte(verb)
		}
	}
	return b.String()
}
