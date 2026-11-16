package shell

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// globMatch reports whether name matches the shell pattern pat: * ? and
// [...] (with ! or ^ negation, ranges and [:class:]); a backslash makes the
// next character literal. It backtracks only to the last star, so a
// hostile pattern cannot make it exponential.
func globMatch(pat, name string) bool {
	px, nx := 0, 0
	starPx, starNx := -1, -1
	for px < len(pat) || nx < len(name) {
		if px < len(pat) {
			switch pat[px] {
			case '*':
				starPx, starNx = px, nx
				px++
				continue
			case '?':
				if nx < len(name) {
					_, n := utf8.DecodeRuneInString(name[nx:])
					px++
					nx += n
					continue
				}
			case '[':
				if nx < len(name) {
					r, n := utf8.DecodeRuneInString(name[nx:])
					if ok, width, valid := matchClass(pat[px:], r); valid {
						if ok {
							px += width
							nx += n
							continue
						}
					} else if r == '[' {
						px++
						nx += n
						continue
					}
				}
			case '\\':
				if px+1 < len(pat) && nx < len(name) {
					pr, pn := utf8.DecodeRuneInString(pat[px+1:])
					nr, nn := utf8.DecodeRuneInString(name[nx:])
					if pr == nr {
						px += 1 + pn
						nx += nn
						continue
					}
				}
			default:
				if nx < len(name) {
					pr, pn := utf8.DecodeRuneInString(pat[px:])
					nr, nn := utf8.DecodeRuneInString(name[nx:])
					if pr == nr {
						px += pn
						nx += nn
						continue
					}
				}
			}
		}
		if starPx >= 0 && starNx < len(name) {
			_, n := utf8.DecodeRuneInString(name[starNx:])
			starNx += n
			px, nx = starPx+1, starNx
			continue
		}
		return false
	}
	return true
}

// matchClass matches r against the bracket expression at the start of
// pat. valid is false when the bracket never closes (it is then literal).
func matchClass(pat string, r rune) (ok bool, width int, valid bool) {
	i := 1
	negate := false
	if i < len(pat) && (pat[i] == '!' || pat[i] == '^') {
		negate = true
		i++
	}
	first := true
	for i < len(pat) {
		c := pat[i]
		if c == ']' && !first {
			return ok != negate, i + 1, true
		}
		first = false
		if c == '[' && i+1 < len(pat) && pat[i+1] == ':' {
			if end := strings.Index(pat[i+2:], ":]"); end >= 0 {
				if classMatch(pat[i+2:i+2+end], r) {
					ok = true
				}
				i += end + 4
				continue
			}
		}
		if c == '\\' && i+1 < len(pat) {
			i++
		}
		lo, n := utf8.DecodeRuneInString(pat[i:])
		i += n
		hi := lo
		if i+1 < len(pat) && pat[i] == '-' && pat[i+1] != ']' {
			i++
			if pat[i] == '\\' && i+1 < len(pat) {
				i++
			}
			hi, n = utf8.DecodeRuneInString(pat[i:])
			i += n
		}
		if lo <= r && r <= hi {
			ok = true
		}
	}
	return false, 0, false
}

func classMatch(class string, r rune) bool {
	switch class {
	case "alpha":
		return isAlpha(byte(r)) && r < 128
	case "digit":
		return r >= '0' && r <= '9'
	case "alnum":
		return r < 128 && (isAlpha(byte(r)) || (r >= '0' && r <= '9'))
	case "upper":
		return r >= 'A' && r <= 'Z'
	case "lower":
		return r >= 'a' && r <= 'z'
	case "space":
		return r == ' ' || (r >= '\t' && r <= '\r')
	case "blank":
		return r == ' ' || r == '\t'
	case "punct":
		return r > 32 && r < 127 && !(isAlpha(byte(r)) || (r >= '0' && r <= '9'))
	case "xdigit":
		return r < 128 && isHex(byte(r))
	case "print":
		return r >= 32 && r != 127
	case "graph":
		return r > 32 && r != 127
	case "cntrl":
		return r < 32 || r == 127
	}
	return false
}

// hasGlobMeta reports whether s contains an unescaped * ? or [.
func hasGlobMeta(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '*', '?', '[':
			return true
		}
	}
	return false
}

// unescapeGlob removes pattern backslashes from a literal component.
func unescapeGlob(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// escapeGlob makes every character of s literal in a pattern.
func escapeGlob(s string) string {
	if !strings.ContainsAny(s, `*?[]\`) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`*?[]\`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// maxGlobMatches bounds one pathname expansion.
const maxGlobMatches = 10000

// globPaths expands a pathname pattern against the session filesystem,
// relative to the cwd. Matches come back sorted; nil means no match.
// Dotfiles only match a component that starts with a literal dot.
func (s *Session) globPaths(pattern string) []string {
	abs := strings.HasPrefix(pattern, "/")
	comps := strings.Split(pattern, "/")
	// Each candidate is the path as it will be printed.
	cands := []string{""}
	if abs {
		cands = []string{"/"}
		comps = comps[1:]
	}
	for ci, comp := range comps {
		last := ci == len(comps)-1
		if comp == "" {
			// "a//b" or a trailing slash: keep the slash.
			for i := range cands {
				cands[i] = joinGlob(cands[i], "")
			}
			continue
		}
		var next []string
		if !hasGlobMeta(comp) {
			lit := unescapeGlob(comp)
			for _, c := range cands {
				p := joinGlob(c, lit)
				if last || s.FS.Exists(s.abs(p)) {
					next = append(next, p)
				}
			}
		} else {
			for _, c := range cands {
				dir := c
				if dir == "" {
					dir = "."
				}
				infos, err := s.FS.ReadDir(s.abs(dir))
				if err != nil || !permit(s, s.abs(dir), 'r') {
					continue
				}
				names := make([]string, 0, len(infos)+2)
				if strings.HasPrefix(comp, ".") {
					names = append(names, ".", "..")
				}
				for _, in := range infos {
					names = append(names, in.Name)
				}
				var matched []string
				for _, n := range names {
					if strings.HasPrefix(n, ".") && !strings.HasPrefix(comp, ".") {
						continue
					}
					if globMatch(comp, n) {
						matched = append(matched, n)
					}
				}
				sort.Strings(matched)
				for _, n := range matched {
					next = append(next, joinGlob(c, n))
					if len(next) > maxGlobMatches {
						break
					}
				}
			}
		}
		cands = next
		if len(cands) == 0 {
			return nil
		}
	}
	if len(cands) == 1 && cands[0] == "/" && !abs {
		return nil
	}
	// Every candidate must exist (a literal last component was not checked).
	out := cands[:0]
	for _, c := range cands {
		if s.FS.Exists(s.abs(c)) || c == "/" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func joinGlob(dir, name string) string {
	switch {
	case dir == "":
		return name
	case strings.HasSuffix(dir, "/"):
		return dir + name
	}
	return dir + "/" + name
}

// trimPattern implements ${x#p} ${x##p} ${x%p} ${x%%p}.
func trimPattern(val, pat, op string) string {
	if fast, ok := trimFast(val, pat, op); ok {
		return fast
	}
	if len(val) > 4096 {
		return val
	}
	switch op {
	case "#":
		for i := 0; i <= len(val); i++ {
			if utf8.RuneStart(byteAt(val, i)) && globMatch(pat, val[:i]) {
				return val[i:]
			}
		}
	case "##":
		for i := len(val); i >= 0; i-- {
			if utf8.RuneStart(byteAt(val, i)) && globMatch(pat, val[:i]) {
				return val[i:]
			}
		}
	case "%":
		for i := len(val); i >= 0; i-- {
			if utf8.RuneStart(byteAt(val, i)) && globMatch(pat, val[i:]) {
				return val[:i]
			}
		}
	case "%%":
		for i := 0; i <= len(val); i++ {
			if utf8.RuneStart(byteAt(val, i)) && globMatch(pat, val[i:]) {
				return val[:i]
			}
		}
	}
	return val
}

// byteAt returns s[i], or a rune-start byte at the end of the string.
func byteAt(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}

// trimFast handles the usual literal, "*lit" and "lit*" patterns in linear
// time, so ${path##*/} on a large value stays cheap.
func trimFast(val, pat, op string) (string, bool) {
	if !hasGlobMeta(pat) {
		lit := unescapeGlob(pat)
		switch op {
		case "#", "##":
			return strings.TrimPrefix(val, lit), true
		default:
			return strings.TrimSuffix(val, lit), true
		}
	}
	if strings.HasPrefix(pat, "*") && !hasGlobMeta(pat[1:]) && (op == "#" || op == "##") {
		lit := unescapeGlob(pat[1:])
		i := strings.Index(val, lit)
		if op == "##" {
			i = strings.LastIndex(val, lit)
		}
		if i < 0 {
			return val, true
		}
		return val[i+len(lit):], true
	}
	if strings.HasSuffix(pat, "*") && !strings.HasSuffix(pat, `\*`) && !hasGlobMeta(pat[:len(pat)-1]) && (op == "%" || op == "%%") {
		lit := unescapeGlob(pat[:len(pat)-1])
		i := strings.LastIndex(val, lit)
		if op == "%%" {
			i = strings.Index(val, lit)
		}
		if i < 0 {
			return val, true
		}
		return val[:i], true
	}
	return "", false
}

// replacePattern implements ${x/p/r} ${x//p/r} ${x/#p/r} ${x/%p/r}.
func replacePattern(val, pat, rep, op string) string {
	if pat == "" {
		return val
	}
	if !hasGlobMeta(pat) && (op == "/" || op == "//") {
		lit := unescapeGlob(pat)
		if op == "//" {
			return strings.ReplaceAll(val, lit, rep)
		}
		return strings.Replace(val, lit, rep, 1)
	}
	if len(val) > 2048 {
		return val
	}
	switch op {
	case "/#":
		for j := len(val); j >= 0; j-- {
			if utf8.RuneStart(byteAt(val, j)) && globMatch(pat, val[:j]) {
				return rep + val[j:]
			}
		}
		return val
	case "/%":
		for i := 0; i <= len(val); i++ {
			if utf8.RuneStart(byteAt(val, i)) && globMatch(pat, val[i:]) {
				return val[:i] + rep
			}
		}
		return val
	}
	var b strings.Builder
	i := 0
	replaced := false
	for i < len(val) {
		if replaced && op == "/" {
			break
		}
		end := -1
		for j := len(val); j > i; j-- {
			if utf8.RuneStart(byteAt(val, j)) && globMatch(pat, val[i:j]) {
				end = j
				break
			}
		}
		if end < 0 {
			_, n := utf8.DecodeRuneInString(val[i:])
			b.WriteString(val[i : i+n])
			i += n
			continue
		}
		b.WriteString(rep)
		i = end
		replaced = true
	}
	b.WriteString(val[i:])
	return b.String()
}
