package shell

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

type lsFlags struct {
	all      bool // -a
	almost   bool // -A
	long     bool // -l
	human    bool // -h
	one      bool // -1
	reverse  bool // -r
	byTime   bool // -t
	bySize   bool // -S
	dirSelf  bool // -d
	inode    bool // -i
	classify bool // -F
	recurse  bool // -R
}

func cmdLs(c *Context) int {
	var fl lsFlags
	var paths []string
	for _, a := range c.Args[1:] {
		if len(a) > 1 && a[0] == '-' && a != "--" {
			for _, r := range a[1:] {
				switch r {
				case 'a':
					fl.all = true
				case 'A':
					fl.almost = true
				case 'l':
					fl.long = true
				case 'h':
					fl.human = true
				case '1':
					fl.one = true
				case 'r':
					fl.reverse = true
				case 't':
					fl.byTime = true
				case 'S':
					fl.bySize = true
				case 'd':
					fl.dirSelf = true
				case 'i':
					fl.inode = true
				case 'F':
					fl.classify = true
				case 'R':
					fl.recurse = true
				case 'n', 'G', 'o', 'g', 'c', 'u', 'p':
					// accepted, minor formatting flags we treat as no-ops
				}
			}
			continue
		}
		paths = append(paths, a)
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	names := newIDNames(c)
	status := 0

	// Separate file args from dir args, like real ls.
	var fileInfos []vfs.Info
	var filePaths []string
	var dirs []string
	for _, p := range paths {
		abs := c.Sess.abs(p)
		info, err := c.FS().Lstat(abs)
		if err != nil {
			c.Errorf("cannot access '%s': %s", p, vfs.Strerror(err))
			status = 2
			continue
		}
		if info.IsDir() && !fl.dirSelf {
			dirs = append(dirs, p)
		} else {
			fileInfos = append(fileInfos, info)
			filePaths = append(filePaths, p)
		}
	}

	if len(fileInfos) > 0 {
		c.printListing(fl, names, "", filePaths, fileInfos)
		if len(dirs) > 0 {
			c.Print("\n")
		}
	}
	for i, d := range dirs {
		multi := len(paths) > 1 || fl.recurse
		if err := c.lsDir(fl, names, d, multi, i > 0 || len(fileInfos) > 0); err != nil {
			status = 2
		}
	}
	return status
}

func (c *Context) lsDir(fl lsFlags, names *idNames, dir string, header, blank bool) error {
	abs := c.Sess.abs(dir)
	entries, err := c.FS().ReadDir(abs)
	if err != nil {
		c.Errorf("cannot open directory '%s': %s", dir, vfs.Strerror(err))
		return err
	}
	if blank {
		c.Print("\n")
	}
	if header {
		c.Printf("%s:\n", dir)
	}
	// Inject . and .. for -a.
	var infos []vfs.Info
	var disp []string
	if fl.all {
		self, _ := c.FS().Stat(abs)
		self.Name = "."
		parent, _ := c.FS().Stat(path.Dir(abs))
		parent.Name = ".."
		infos = append(infos, self, parent)
		disp = append(disp, ".", "..")
	}
	for _, e := range entries {
		if !fl.all && !fl.almost && strings.HasPrefix(e.Name, ".") {
			continue
		}
		infos = append(infos, e)
		disp = append(disp, e.Name)
	}
	c.printListing(fl, names, abs, disp, infos)

	if fl.recurse {
		for _, e := range entries {
			if e.IsDir() && !strings.HasPrefix(e.Name, ".") {
				sub := path.Join(dir, e.Name)
				_ = c.lsDir(fl, names, sub, true, true)
			}
		}
	}
	return nil
}

func (c *Context) printListing(fl lsFlags, names *idNames, base string, disp []string, infos []vfs.Info) {
	order := make([]int, len(infos))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ia, ib := infos[order[a]], infos[order[b]]
		switch {
		case fl.byTime && !ia.ModTime.Equal(ib.ModTime):
			return ia.ModTime.After(ib.ModTime)
		case fl.bySize && ia.Size != ib.Size:
			return ia.Size > ib.Size
		}
		return disp[order[a]] < disp[order[b]]
	})
	if fl.reverse {
		for i, j := 0, len(order)-1; i < j; i, j = i+1, j-1 {
			order[i], order[j] = order[j], order[i]
		}
	}

	if fl.long {
		var total int64
		var w colWidths
		for _, i := range order {
			total += blocksFor(infos[i].Size)
			w.user = maxInt(w.user, len(names.user(infos[i].UID)))
			w.group = maxInt(w.group, len(names.group(infos[i].GID)))
			w.size = maxInt(w.size, len(humanSize(infos[i].Size, fl.human)))
			w.link = maxInt(w.link, len(itoa(nlinkFor(infos[i]))))
		}
		if base != "" {
			c.Printf("total %d\n", total)
		}
		for _, i := range order {
			c.Print(c.longLine(fl, names, w, base, disp[i], infos[i]))
		}
		return
	}
	// Short format: one per line for -1 or when piped; otherwise names
	// separated by two spaces (columnisation is not worth emulating and
	// bots do not care).
	sep := "  "
	if fl.one {
		sep = "\n"
	}
	parts := make([]string, len(order))
	for k, i := range order {
		parts[k] = disp[i] + classifySuffix(fl, infos[i])
	}
	if len(parts) > 0 {
		c.Print(strings.Join(parts, sep) + "\n")
	}
}

type colWidths struct{ user, group, size, link int }

func nlinkFor(info vfs.Info) int {
	if info.IsDir() {
		return 2
	}
	return 1
}

func (c *Context) longLine(fl lsFlags, names *idNames, w colWidths, base, name string, info vfs.Info) string {
	perm := modeString(info.Mode)
	size := humanSize(info.Size, fl.human)
	when := lsTime(info.ModTime, c.Sess.Machine.Now())
	display := name + classifySuffix(fl, info)
	if info.IsSymlink() {
		display = name + " -> " + info.Target
	}
	inode := ""
	if fl.inode {
		inode = fmt.Sprintf("%d ", inodeFor(base, name))
	}
	return fmt.Sprintf("%s%s %*d %-*s %-*s %*s %s %s\n",
		inode, perm, w.link, nlinkFor(info), w.user, names.user(info.UID), w.group, names.group(info.GID), w.size, size, when, display)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// modeString renders the 10-character mode field, e.g. "drwxr-xr-x".
func modeString(m fs.FileMode) string {
	var b [10]byte
	switch {
	case m.IsDir():
		b[0] = 'd'
	case m&fs.ModeSymlink != 0:
		b[0] = 'l'
	case m&fs.ModeCharDevice != 0:
		b[0] = 'c'
	case m&fs.ModeDevice != 0:
		b[0] = 'b'
	case m&fs.ModeNamedPipe != 0:
		b[0] = 'p'
	case m&fs.ModeSocket != 0:
		b[0] = 's'
	default:
		b[0] = '-'
	}
	const rwx = "rwxrwxrwx"
	perm := m.Perm()
	for i := 0; i < 9; i++ {
		if perm&(1<<uint(8-i)) != 0 {
			b[i+1] = rwx[i]
		} else {
			b[i+1] = '-'
		}
	}
	if m&fs.ModeSetuid != 0 {
		b[3] = setBit(b[3], 's', 'S')
	}
	if m&fs.ModeSetgid != 0 {
		b[6] = setBit(b[6], 's', 'S')
	}
	if m&fs.ModeSticky != 0 {
		b[9] = setBit(b[9], 't', 'T')
	}
	return string(b[:])
}

func setBit(cur byte, set, unset byte) byte {
	if cur == 'x' {
		return set
	}
	return unset
}

func classifySuffix(fl lsFlags, info vfs.Info) string {
	if !fl.classify {
		return ""
	}
	switch {
	case info.IsDir():
		return "/"
	case info.IsSymlink():
		return "@"
	case info.Mode.Perm()&0o111 != 0 && !info.IsDevice():
		return "*"
	}
	return ""
}

func blocksFor(size int64) int64 {
	// ls reports 1K blocks (2 * 512-byte blocks rounded up).
	if size <= 0 {
		return 0
	}
	return (size + 4095) / 4096 * 4
}

func humanSize(size int64, human bool) string {
	if !human {
		return fmt.Sprintf("%d", size)
	}
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d", size)
	}
	units := []string{"K", "M", "G", "T", "P"}
	f := float64(size)
	i := -1
	for f >= unit && i < len(units)-1 {
		f /= unit
		i++
	}
	if f < 10 {
		return fmt.Sprintf("%.1f%s", f, units[i])
	}
	return fmt.Sprintf("%.0f%s", f, units[i])
}

// lsTime renders the date column: "Jan _2 15:04" for the last six months,
// "Jan _2  2006" otherwise, matching coreutils.
func lsTime(t, now time.Time) string {
	if now.Sub(t) < 180*24*time.Hour && t.Before(now.Add(24*time.Hour)) {
		return t.Format("Jan _2 15:04")
	}
	return t.Format("Jan _2  2006")
}

func inodeFor(base, name string) int {
	return int(seedInode(base+"/"+name)%8_000_000) + 100000
}

func seedInode(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
