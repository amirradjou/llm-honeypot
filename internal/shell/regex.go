package shell

import (
	"regexp"
	"strings"
)

// compileRegex compiles a grep/sed pattern. Basic regular expressions (the
// default for grep and sed) treat ( ) { } | + ? as literal characters and
// their backslashed forms as operators, the opposite of Go's syntax, so a
// bot's `grep "^CPU(s)"` must not become a group. Extended expressions
// (grep -E, sed -E) are close enough to RE2 to pass through.
func compileRegex(pattern string, extended, ignoreCase bool) (*regexp.Regexp, error) {
	expr := pattern
	if !extended {
		expr = breToRE2(pattern)
	} else {
		expr = gnuWordBounds(pattern)
	}
	if ignoreCase {
		expr = "(?i)" + expr
	}
	return regexp.Compile(expr)
}

// breToRE2 rewrites a POSIX basic regular expression into RE2 syntax.
func breToRE2(p string) string {
	var b strings.Builder
	inBracket := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		if inBracket {
			b.WriteByte(c)
			if c == ']' {
				inBracket = false
			}
			continue
		}
		switch c {
		case '[':
			inBracket = true
			b.WriteByte(c)
			// A ']' right after '[' or '[^' is a literal member.
			if i+1 < len(p) && p[i+1] == '^' {
				b.WriteByte('^')
				i++
			}
			if i+1 < len(p) && p[i+1] == ']' {
				b.WriteString(`\]`)
				i++
			}
		case '(', ')', '{', '}', '|', '+', '?':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '*':
			// A leading '*' (or one right after a group start) is literal.
			if b.Len() == 0 || strings.HasSuffix(b.String(), "(") || strings.HasSuffix(b.String(), "^") {
				b.WriteString(`\*`)
			} else {
				b.WriteByte(c)
			}
		case '\\':
			if i+1 >= len(p) {
				b.WriteString(`\\`)
				continue
			}
			i++
			switch n := p[i]; n {
			case '(', ')', '{', '}', '|', '+', '?':
				b.WriteByte(n)
			case '<', '>':
				b.WriteString(`\b`)
			default:
				b.WriteByte('\\')
				b.WriteByte(n)
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// gnuWordBounds maps GNU's \< and \> to RE2's \b.
func gnuWordBounds(p string) string {
	return strings.NewReplacer(`\<`, `\b`, `\>`, `\b`).Replace(p)
}
