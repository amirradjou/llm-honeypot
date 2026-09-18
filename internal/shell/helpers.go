package shell

import (
	"io/fs"
	"sort"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

func sortStrings(s []string) { sort.Strings(s) }

func fsFileMode(n int64) fs.FileMode { return fs.FileMode(n) }

// permit checks access for the session credential: mode is 'r', 'w' or 'x'.
func permit(s *Session, path string, mode byte) bool {
	perm := map[byte]vfs.Perm{'r': vfs.R, 'w': vfs.W, 'x': vfs.X}[mode]
	return s.FS.Access(path, s.Cred, perm) == nil
}

// vfsRoot and vfsCred build credentials for sudo/su.
func vfsRoot() vfs.Cred { return vfs.Cred{UID: 0, GIDs: []int{0}} }

func vfsCred(uid, gid int) vfs.Cred { return vfs.Cred{UID: uid, GIDs: []int{gid}} }

// shellQuoteJoin turns an argv back into a command line, quoting args that
// contain shell metacharacters so re-parsing yields the same words.
func shellQuoteJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || containsAny(a, " \t\n\"'\\$&|;<>()*?[]{}#~`!") {
			out[i] = "'" + replaceAll(a, "'", `'\''`) + "'"
		} else {
			out[i] = a
		}
	}
	return joinSpace(out)
}

func containsAny(s, chars string) bool {
	for _, r := range s {
		for _, c := range chars {
			if r == c {
				return true
			}
		}
	}
	return false
}

func replaceAll(s, old, new string) string {
	var b []byte
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			b = append(b, new...)
			i += len(old)
		} else {
			b = append(b, s[i])
			i++
		}
	}
	return string(b)
}

func joinSpace(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

// uuidFromShell builds a stable UUID-shaped string from a seed.
func uuidFromShell(seed string) string {
	h := seedInode(seed)
	h2 := seedInode(seed + "x")
	hex := "0123456789abcdef"
	var b [32]byte
	for i := 0; i < 16; i++ {
		b[i] = hex[(h>>(uint(i)*4))&0xf]
	}
	for i := 0; i < 16; i++ {
		b[16+i] = hex[(h2>>(uint(i)*4))&0xf]
	}
	s := string(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:32]
}
