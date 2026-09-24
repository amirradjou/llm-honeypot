package shell

import (
	"io/fs"
	"strconv"
	"strings"
)

// parseMode parses a chmod mode argument, octal ("755", "0644") or
// symbolic ("u+x", "go-w", "a=r"), against the current permission bits.
func parseMode(s string, cur fs.FileMode) (fs.FileMode, error) {
	if n, err := strconv.ParseInt(s, 8, 32); err == nil && !strings.ContainsAny(s, "ugoa+-=rwxXst") {
		return fs.FileMode(n) & fs.ModePerm, nil
	}
	mode := cur & fs.ModePerm
	for _, clause := range strings.Split(s, ",") {
		var who string
		i := 0
		for i < len(clause) && strings.ContainsRune("ugoa", rune(clause[i])) {
			who += string(clause[i])
			i++
		}
		if who == "" {
			who = "a"
		}
		if i >= len(clause) {
			return 0, errBadMode
		}
		op := clause[i]
		i++
		perms := clause[i:]
		var bits fs.FileMode
		for _, r := range perms {
			switch r {
			case 'r':
				bits |= 0o444
			case 'w':
				bits |= 0o222
			case 'x', 'X':
				bits |= 0o111
			}
		}
		mask := whoMask(who)
		bits &= mask
		switch op {
		case '+':
			mode |= bits
		case '-':
			mode &^= bits
		case '=':
			mode = (mode &^ mask) | bits
		default:
			return 0, errBadMode
		}
	}
	return mode, nil
}

func whoMask(who string) fs.FileMode {
	var m fs.FileMode
	for _, r := range who {
		switch r {
		case 'u':
			m |= 0o700
		case 'g':
			m |= 0o070
		case 'o':
			m |= 0o007
		case 'a':
			m |= 0o777
		}
	}
	return m
}

type modeError struct{}

func (modeError) Error() string { return "invalid mode" }

var errBadMode = modeError{}

// filepathSkipDir returns the sentinel used by vfs.Walk to skip a subtree.
func filepathSkipDir() error { return fs.SkipDir }
