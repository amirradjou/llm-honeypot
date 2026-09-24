package shell

import (
	"fmt"
	"strings"
)

// wordBuilder assembles one shell word from segments. Literal text (from
// unquoted literals and from quotes) is appended verbatim; expanded text
// from an unquoted $VAR or ~ is subject to field splitting on whitespace,
// exactly like bash. Splitting can turn one word into several, so the
// builder emits completed words as it goes.
type wordBuilder struct {
	field   strings.Builder
	started bool // a word has begun (even if empty via quotes)
	words   []token
}

// addLiteral appends text that must not be split (literal or quoted).
func (w *wordBuilder) addLiteral(s string) {
	w.field.WriteString(s)
	w.started = true
}

// markStarted notes that a (possibly empty) quoted section began the word,
// so that `cmd ""` still yields an empty argument.
func (w *wordBuilder) markStarted() { w.started = true }

// addExpanded appends the result of an unquoted expansion, splitting it on
// runs of whitespace into separate fields.
func (w *wordBuilder) addExpanded(s string) {
	if s == "" {
		return
	}
	// Split preserving whether there is leading/trailing whitespace.
	leadWS := isSpace(rune(s[0]))
	pieces := strings.Fields(s)
	if len(pieces) == 0 {
		// All whitespace: it ends the current field if one has content.
		if w.field.Len() > 0 {
			w.emit()
		}
		return
	}
	if leadWS && w.field.Len() > 0 {
		w.emit()
	}
	for i, p := range pieces {
		if i > 0 {
			w.emit()
		}
		w.field.WriteString(p)
		w.started = true
	}
	if isSpace(rune(s[len(s)-1])) {
		w.emit()
	}
}

// emit finishes the current field as a word if one is in progress.
func (w *wordBuilder) emit() {
	if w.started {
		w.words = append(w.words, token{kind: tWord, val: w.field.String()})
		w.field.Reset()
		w.started = false
	}
}

// take returns the words built so far and resets. quotedEmpty forces an
// empty quoted word ("") to survive.
func (w *wordBuilder) take() []token {
	w.emit()
	out := w.words
	w.words = nil
	return out
}

func isSpace(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '\r' }

// tokenize splits a line into words and operators, applying quote removal
// and $VAR / ${VAR} / ~ expansion with field splitting on unquoted
// expansions. It errors only on unterminated quotes.
func tokenize(line string, exp Expander) ([]token, error) {
	var toks []token
	wb := &wordBuilder{}
	// quoted records that the current word contained a quote, so an empty
	// result is still a real (empty) argument.
	quoted := false

	flush := func() {
		words := wb.take()
		if quoted && len(words) == 0 {
			words = []token{{kind: tWord, val: ""}}
		}
		for _, t := range words {
			t.quoted = quoted
			toks = append(toks, t)
		}
		quoted = false
	}
	op := func(k tokKind, v string) {
		flush()
		toks = append(toks, token{kind: k, val: v})
	}

	rs := []rune(line)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			flush()
		case '#':
			if !wb.started && wb.field.Len() == 0 && !quoted {
				return toks, nil // comment
			}
			wb.addLiteral("#")
		case '\'':
			quoted = true
			wb.markStarted()
			j := i + 1
			for j < len(rs) && rs[j] != '\'' {
				j++
			}
			if j >= len(rs) {
				return nil, fmt.Errorf("unexpected EOF while looking for matching `''")
			}
			wb.addLiteral(string(rs[i+1 : j]))
			i = j
		case '"':
			quoted = true
			wb.markStarted()
			j, err := scanDoubleQuoted(rs, i+1, wb, exp)
			if err != nil {
				return nil, err
			}
			i = j
		case '\\':
			if i+1 < len(rs) {
				wb.addLiteral(string(rs[i+1]))
				i++
			} else {
				wb.addLiteral(`\`)
			}
		case '$':
			val, j, _ := expandDollar(rs, i, exp)
			wb.addExpanded(val)
			i = j
		case '~':
			if !wb.started && wb.field.Len() == 0 {
				val, j := expandTilde(rs, i, exp)
				wb.addLiteral(val) // tilde result is not field-split
				i = j
			} else {
				wb.addLiteral("~")
			}
		case '|':
			if i+1 < len(rs) && rs[i+1] == '|' {
				op(tOr, "||")
				i++
			} else {
				op(tPipe, "|")
			}
		case '&':
			switch {
			case i+1 < len(rs) && rs[i+1] == '&':
				op(tAnd, "&&")
				i++
			case i+1 < len(rs) && rs[i+1] == '>':
				op(tRedir, "&>")
				i++
			default:
				op(tBg, "&")
			}
		case ';':
			op(tSemi, ";")
		case '>':
			if i+1 < len(rs) && rs[i+1] == '>' {
				op(tRedir, ">>")
				i++
			} else {
				op(tRedir, ">")
			}
		case '<':
			op(tRedir, "<")
		case '2', '1':
			if !wb.started && wb.field.Len() == 0 && !quoted && i+1 < len(rs) && rs[i+1] == '>' {
				o := ">"
				if c == '2' {
					o = "2>"
				}
				if i+2 < len(rs) && rs[i+2] == '>' {
					o += ">"
					if c == '1' {
						o = ">>"
					}
					op(tRedir, o)
					i += 2
				} else {
					op(tRedir, o)
					i++
				}
			} else {
				wb.addLiteral(string(c))
			}
		default:
			wb.addLiteral(string(c))
		}
	}
	flush()
	return toks, nil
}

// scanDoubleQuoted reads until the closing quote, expanding $ but keeping
// everything else literal (no field splitting inside quotes). Returns the
// index of the closing quote.
func scanDoubleQuoted(rs []rune, start int, wb *wordBuilder, exp Expander) (int, error) {
	for i := start; i < len(rs); i++ {
		switch rs[i] {
		case '"':
			return i, nil
		case '\\':
			if i+1 < len(rs) {
				n := rs[i+1]
				if n == '$' || n == '`' || n == '"' || n == '\\' {
					wb.addLiteral(string(n))
					i++
					continue
				}
			}
			wb.addLiteral(`\`)
		case '$':
			val, j, _ := expandDollar(rs, i, exp)
			wb.addLiteral(val) // quoted: no splitting
			i = j
		default:
			wb.addLiteral(string(rs[i]))
		}
	}
	return len(rs), fmt.Errorf("unexpected EOF while looking for matching `\"'")
}

// expandDollar handles $VAR, ${VAR}, $?, $$, and $(...) (not executed;
// command substitution yields empty, which is what a locked-down fake
// shell should do). It returns the expansion, the index of the last
// consumed rune, and whether it was a command substitution.
func expandDollar(rs []rune, i int, exp Expander) (string, int, bool) {
	if i+1 >= len(rs) {
		return "$", i, false
	}
	next := rs[i+1]
	switch {
	case next == '{':
		j := i + 2
		for j < len(rs) && rs[j] != '}' {
			j++
		}
		if j < len(rs) {
			name := string(rs[i+2 : j])
			v, _ := exp.Var(stripBraceOps(name))
			return v, j, false
		}
		return "", len(rs) - 1, false
	case next == '(':
		depth := 0
		j := i + 1
		for ; j < len(rs); j++ {
			if rs[j] == '(' {
				depth++
			} else if rs[j] == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		return "", j, true
	case next == '?' || next == '$' || next == '!' || next == '#' || next == '*' || next == '@' || next == '-':
		v, _ := exp.Var(string(next))
		return v, i + 1, false
	case isNameStart(next):
		j := i + 1
		for j < len(rs) && isNameChar(rs[j]) {
			j++
		}
		v, _ := exp.Var(string(rs[i+1 : j]))
		return v, j - 1, false
	default:
		return "$", i, false
	}
}

func stripBraceOps(s string) string {
	for _, op := range []string{":-", ":=", ":?", ":+", "-", "=", "?", "+", "#", "%", "/"} {
		if idx := strings.Index(s, op); idx > 0 {
			return s[:idx]
		}
	}
	return s
}

func expandTilde(rs []rune, i int, exp Expander) (string, int) {
	j := i + 1
	for j < len(rs) && rs[j] != '/' && rs[j] != ' ' && rs[j] != '\t' {
		j++
	}
	user := string(rs[i+1 : j])
	if home, ok := exp.Home(user); ok {
		return home, j - 1
	}
	return string(rs[i:j]), j - 1
}

func isNameStart(r rune) bool {
	return r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}
func isNameChar(r rune) bool { return isNameStart(r) || (r >= '0' && r <= '9') }
