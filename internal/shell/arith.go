package shell

import (
	"strconv"
	"strings"
)

// Shell arithmetic: $((...)), ((...)), let and ${x:offset}. Integers are
// 64-bit and wrap like bash's; errors carry bash's exact wording.

type arithEnv interface {
	getVar(name string) (string, bool)
	setVar(name, value string)
}

// arithError is an arithmetic failure, e.g.
// `1/0: division by 0 (error token is "0")`.
type arithError struct {
	expr, msg, token string
}

func (e *arithError) Error() string {
	return e.expr + ": " + e.msg + " (error token is \"" + e.token + "\")"
}

// dashText is the same failure in dash's words.
func (e *arithError) dashText() string {
	if e.msg == "division by 0" {
		return "arithmetic expression: division by zero: \"" + e.expr + "\""
	}
	return "arithmetic expression: " + strings.TrimPrefix(e.msg, "syntax error: ") + ": \"" + e.expr + "\""
}

// maxArithDepth bounds variables whose values are themselves expressions.
const maxArithDepth = 32

func evalArith(expr string, env arithEnv) (int64, error) { return evalArithDepth(expr, env, 0) }

func evalArithDepth(expr string, env arithEnv, depth int) (v int64, err error) {
	a := &arithParser{env: env, src: expr, depth: depth}
	a.expr = strings.TrimLeft(expr, " \t\n")
	defer func() {
		if r := recover(); r != nil {
			ae, ok := r.(*arithError)
			if !ok {
				panic(r)
			}
			err = ae
		}
	}()
	a.advance()
	if a.tok == "" {
		return 0, nil
	}
	v = a.comma()
	if a.tok != "" {
		a.failAt("syntax error in expression", a.curStart)
	}
	return v, nil
}

type arithParser struct {
	env       arithEnv
	src, expr string
	pos       int
	tok       string // current token; "" at end
	num       int64  // value when tok is a number
	isNum     bool
	curStart  int // where the current token starts
	prevStart int // where the previous token started
	noeval    int // >0 while evaluating a branch whose value is discarded
	depth     int
}

func (a *arithParser) failAt(msg string, at int) {
	tok := ""
	if at >= 0 && at <= len(a.src) {
		tok = a.src[at:]
	}
	panic(&arithError{expr: a.expr, msg: msg, token: tok})
}

func (a *arithParser) fail(msg string) { a.failAt(msg, a.prevStart) }

var arithOps = []string{"<<=", ">>=", "**", "++", "--", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||",
	"+=", "-=", "*=", "/=", "%=", "&=", "^=", "|=",
	"+", "-", "*", "/", "%", "<", ">", "!", "~", "&", "^", "|", "?", ":", "=", ",", "(", ")"}

// advance reads the next token.
func (a *arithParser) advance() {
	for a.pos < len(a.src) && strings.IndexByte(" \t\n\r", a.src[a.pos]) >= 0 {
		a.pos++
	}
	a.prevStart = a.curStart
	a.curStart = a.pos
	a.isNum = false
	if a.pos >= len(a.src) {
		a.tok = ""
		a.curStart = a.prevStart
		return
	}
	c := a.src[a.pos]
	switch {
	case c >= '0' && c <= '9':
		j := a.pos
		for j < len(a.src) && (isNameChar(rune(a.src[j])) || a.src[j] == '#' || a.src[j] == '@') {
			j++
		}
		a.tok = a.src[a.pos:j]
		a.pos = j
		n, ok := parseArithNumber(a.tok)
		if !ok {
			a.failAt("value too great for base", a.curStart)
		}
		a.num, a.isNum = n, true
	case isNameStart(rune(c)):
		j := a.pos
		for j < len(a.src) && isNameChar(rune(a.src[j])) {
			j++
		}
		a.tok = a.src[a.pos:j]
		a.pos = j
	default:
		for _, op := range arithOps {
			if strings.HasPrefix(a.src[a.pos:], op) {
				a.tok = op
				a.pos += len(op)
				return
			}
		}
		a.tok = a.src[a.pos : a.pos+1]
		a.pos++
		a.failAt("syntax error: invalid arithmetic operator", a.curStart)
	}
}

// parseArithNumber reads 123, 0x1f, 017 and base#digits.
func parseArithNumber(s string) (int64, bool) {
	base := 10
	digits := s
	switch {
	case strings.Contains(s, "#"):
		b, d, _ := strings.Cut(s, "#")
		n, err := strconv.Atoi(b)
		if err != nil || n < 2 || n > 64 || d == "" {
			return 0, false
		}
		base, digits = n, d
	case strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"):
		base, digits = 16, s[2:]
		if digits == "" {
			return 0, false
		}
	case len(s) > 1 && s[0] == '0':
		base, digits = 8, s[1:]
	}
	var v int64
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		var d int
		switch {
		case c >= '0' && c <= '9':
			d = int(c - '0')
		case c >= 'a' && c <= 'z':
			d = int(c-'a') + 10
		case c >= 'A' && c <= 'Z':
			d = int(c-'A') + 10
			if base > 36 {
				d = int(c-'A') + 36
			}
		case c == '@':
			d = 62
		case c == '_':
			d = 63
		default:
			return 0, false
		}
		if d >= base {
			return 0, false
		}
		v = v*int64(base) + int64(d)
	}
	return v, true
}

func (a *arithParser) is(op string) bool { return !a.isNum && a.tok == op }

func (a *arithParser) comma() int64 {
	v := a.assign()
	for a.is(",") {
		a.advance()
		v = a.assign()
	}
	return v
}

var assignOps = map[string]string{"=": "", "+=": "+", "-=": "-", "*=": "*", "/=": "/", "%=": "%",
	"<<=": "<<", ">>=": ">>", "&=": "&", "^=": "^", "|=": "|"}

func (a *arithParser) assign() int64 {
	// An assignment needs a bare variable name on the left.
	if !a.isNum && isName(a.tok) {
		save := *a
		name := a.tok
		a.advance()
		if bin, ok := assignOps[a.tok]; ok && !a.isNum {
			a.advance()
			rhs := a.assign()
			v := rhs
			if bin != "" {
				v = a.binary(bin, a.variable(name), rhs)
			}
			if a.noeval == 0 {
				a.env.setVar(name, strconv.FormatInt(v, 10))
			}
			return v
		}
		*a = save
	}
	return a.ternary()
}

func (a *arithParser) ternary() int64 {
	cond := a.logOr()
	if !a.is("?") {
		return cond
	}
	a.advance()
	if cond == 0 {
		a.noeval++
	}
	t := a.comma()
	if cond == 0 {
		a.noeval--
	}
	if !a.is(":") {
		a.fail("syntax error: `:' expected for conditional expression")
	}
	a.advance()
	if cond != 0 {
		a.noeval++
	}
	f := a.ternary()
	if cond != 0 {
		a.noeval--
		return t
	}
	return f
}

func (a *arithParser) logOr() int64 {
	v := a.logAnd()
	for a.is("||") {
		a.advance()
		if v != 0 {
			a.noeval++
			a.logAnd()
			a.noeval--
			v = 1
		} else {
			v = b2i(a.logAnd() != 0)
		}
	}
	return v
}

func (a *arithParser) logAnd() int64 {
	v := a.binLevel(0)
	for a.is("&&") {
		a.advance()
		if v == 0 {
			a.noeval++
			a.binLevel(0)
			a.noeval--
		} else {
			v = b2i(a.binLevel(0) != 0)
		}
	}
	return v
}

// Binary operator levels from loosest to tightest (below && and above **).
var binLevels = [][]string{{"|"}, {"^"}, {"&"}, {"==", "!="}, {"<=", ">=", "<", ">"}, {"<<", ">>"}, {"+", "-"}, {"*", "/", "%"}}

func (a *arithParser) binLevel(n int) int64 {
	if n == len(binLevels) {
		return a.power()
	}
	v := a.binLevel(n + 1)
	for {
		op := ""
		for _, o := range binLevels[n] {
			if a.is(o) {
				op = o
			}
		}
		if op == "" {
			return v
		}
		a.advance()
		v = a.binary(op, v, a.binLevel(n+1))
	}
}

func (a *arithParser) binary(op string, x, y int64) int64 {
	switch op {
	case "|":
		return x | y
	case "^":
		return x ^ y
	case "&":
		return x & y
	case "==":
		return b2i(x == y)
	case "!=":
		return b2i(x != y)
	case "<=":
		return b2i(x <= y)
	case ">=":
		return b2i(x >= y)
	case "<":
		return b2i(x < y)
	case ">":
		return b2i(x > y)
	case "<<":
		return x << uint64(y&63)
	case ">>":
		return x >> uint64(y&63)
	case "+":
		return x + y
	case "-":
		return x - y
	case "*":
		return x * y
	case "/", "%":
		if a.noeval > 0 {
			return 0
		}
		if y == 0 {
			a.fail("division by 0")
		}
		if y == -1 {
			if op == "/" {
				return -x
			}
			return 0
		}
		if op == "/" {
			return x / y
		}
		return x % y
	}
	return 0
}

func (a *arithParser) power() int64 {
	base := a.unary()
	if !a.is("**") {
		return base
	}
	a.advance()
	exp := a.power()
	if exp < 0 {
		if a.noeval > 0 {
			return 0
		}
		a.fail("exponent less than 0")
	}
	v := int64(1)
	for exp > 0 { // square-and-multiply: 2**1000000000 must stay cheap
		if exp&1 == 1 {
			v *= base
		}
		base *= base
		exp >>= 1
	}
	return v
}

func (a *arithParser) unary() int64 {
	switch {
	case a.is("+"):
		a.advance()
		return a.unary()
	case a.is("-"):
		a.advance()
		return -a.unary()
	case a.is("!"):
		a.advance()
		return b2i(a.unary() == 0)
	case a.is("~"):
		a.advance()
		return ^a.unary()
	case a.is("++"), a.is("--"):
		op := a.tok
		a.advance()
		if a.isNum || !isName(a.tok) {
			a.fail("syntax error: operand expected")
		}
		name := a.tok
		a.advance()
		v := a.variable(name)
		if op == "++" {
			v++
		} else {
			v--
		}
		if a.noeval == 0 {
			a.env.setVar(name, strconv.FormatInt(v, 10))
		}
		return v
	}
	return a.postfix()
}

func (a *arithParser) postfix() int64 {
	if a.is("(") {
		a.advance()
		v := a.comma()
		if !a.is(")") {
			a.fail("syntax error: `)' expected")
		}
		a.advance()
		return v
	}
	if a.isNum {
		v := a.num
		a.advance()
		return v
	}
	if a.tok == "" || !isName(a.tok) {
		a.fail("syntax error: operand expected")
	}
	name := a.tok
	a.advance()
	v := a.variable(name)
	if a.is("++") || a.is("--") {
		nv := v + 1
		if a.tok == "--" {
			nv = v - 1
		}
		if a.noeval == 0 {
			a.env.setVar(name, strconv.FormatInt(nv, 10))
		}
		a.advance()
	}
	return v
}

// variable evaluates a variable; its value is itself an expression.
func (a *arithParser) variable(name string) int64 {
	s, _ := a.env.getVar(name)
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if a.depth+1 >= maxArithDepth {
		a.fail("expression recursion level exceeded")
	}
	v, err := evalArithDepth(s, a.env, a.depth+1)
	if err != nil {
		panic(err)
	}
	return v
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
