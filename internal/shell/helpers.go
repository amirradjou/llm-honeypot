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
