package shell

import (
	"strconv"
	"strings"
)

// maxBraceWords caps how many words one brace expansion may produce, so
// {1..99999999} or {a,b}{a,b}{a,b}... cannot exhaust memory.
const maxBraceWords = 4096

// expandBraces performs bash brace expansion ({a,b,c}, {1..5}, {a..e},
// {01..10..2}) on the raw text of a word, leaving quoted text and $-
// expansions alone. It returns the text unchanged when there is nothing to
// expand. budget counts the expansion steps left.
func expandBraces(s string, budget *int) []string {
	*budget--
	if *budget < 0 || len(s) > 1<<16 {
		return []string{s}
	}
	open, end, alts := findBrace(s)
	if open < 0 {
		return []string{s}
	}
	var out []string
	for _, a := range alts {
		if *budget <= 0 {
			break
		}
		out = append(out, expandBraces(s[:open]+a+s[end+1:], budget)...)
	}
	return out
}

// skipQuoted returns the index just past a quoted or $-construct starting
// at i, or i itself when s[i] starts none.
func skipQuoted(s string, i int) int {
	switch s[i] {
	case '\\':
		return min(i+2, len(s))
	case '\'':
		if j := strings.IndexByte(s[i+1:], '\''); j >= 0 {
			return i + j + 2
		}
		return len(s)
	case '"':
		for j := i + 1; j < len(s); j++ {
			if s[j] == '\\' {
				j++
			} else if s[j] == '"' {
				return j + 1
			}
		}
		return len(s)
	case '`':
		if j := strings.IndexByte(s[i+1:], '`'); j >= 0 {
			return i + j + 2
		}
		return len(s)
	case '$':
		if i+1 < len(s) && (s[i+1] == '{' || s[i+1] == '(') {
			o, c := s[i+1], byte('}')
			if o == '(' {
				c = ')'
			}
			depth := 0
			for j := i + 1; j < len(s); j++ {
				switch s[j] {
				case o:
					depth++
				case c:
					depth--
					if depth == 0 {
						return j + 1
					}
				case '\\':
					j++
				}
			}
			return len(s)
		}
	}
	return i
}

// findBrace locates the first expandable brace expression: its braces and
// the alternatives it stands for.
func findBrace(s string) (int, int, []string) {
	for i := 0; i < len(s); i++ {
		if j := skipQuoted(s, i); j != i {
			i = j - 1
			continue
		}
		if s[i] != '{' {
			continue
		}
		if end, alts := braceBody(s, i); end >= 0 {
			return i, end, alts
		}
	}
	return -1, -1, nil
}

// braceBody parses the brace expression opening at s[open].
func braceBody(s string, open int) (int, []string) {
	depth := 0
	var commas []int
	for i := open + 1; i < len(s); i++ {
		if j := skipQuoted(s, i); j != i {
			i = j - 1
			continue
		}
		switch s[i] {
		case '{':
			depth++
		case ',':
			if depth == 0 {
				commas = append(commas, i)
			}
		case '}':
			if depth > 0 {
				depth--
				continue
			}
			if len(commas) > 0 {
				var alts []string
				prev := open + 1
				for _, c := range commas {
					alts = append(alts, s[prev:c])
					prev = c + 1
				}
				return i, append(alts, s[prev:i])
			}
			if seq := braceSequence(s[open+1 : i]); seq != nil {
				return i, seq
			}
			return -1, nil
		}
	}
	return -1, nil
}

// braceSequence expands x..y[..step] for integers or single letters.
func braceSequence(body string) []string {
	f := strings.Split(body, "..")
	if len(f) != 2 && len(f) != 3 {
		return nil
	}
	step := int64(1)
	if len(f) == 3 {
		n, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil {
			return nil
		}
		if n < 0 {
			n = -n
		}
		if n != 0 {
			step = n
		}
	}
	var out []string
	a, errA := strconv.ParseInt(f[0], 10, 64)
	b, errB := strconv.ParseInt(f[1], 10, 64)
	if errA == nil && errB == nil {
		width := 0
		for _, e := range f[:2] {
			d := strings.TrimPrefix(e, "-")
			if len(d) > 1 && d[0] == '0' && len(e) > width {
				width = len(e)
			}
		}
		for v := a; ; {
			n := strconv.FormatInt(v, 10)
			if width > 0 {
				neg := strings.HasPrefix(n, "-")
				n = strings.TrimPrefix(n, "-")
				pad := width - len(n)
				if neg {
					pad--
				}
				if pad > 0 {
					n = strings.Repeat("0", pad) + n
				}
				if neg {
					n = "-" + n
				}
			}
			out = append(out, n)
			if len(out) >= maxBraceWords || v == b {
				break
			}
			if a < b {
				if v+step > b {
					break
				}
				v += step
			} else {
				if v-step < b {
					break
				}
				v -= step
			}
		}
		return out
	}
	if len(f[0]) == 1 && len(f[1]) == 1 && isAlpha(f[0][0]) && isAlpha(f[1][0]) {
		x, y := int64(f[0][0]), int64(f[1][0])
		for v := x; ; {
			out = append(out, string(rune(v)))
			if v == y {
				break
			}
			if x < y {
				if v+step > y {
					break
				}
				v += step
			} else {
				if v-step < y {
					break
				}
				v -= step
			}
		}
		return out
	}
	return nil
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
