package shell

import (
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/amirradjou/llm-honeypot/internal/vfs"
)

func (in *Interp) registerFiles() {
	in.Register("ls", cmdLs)
	in.Register("dir", cmdLs)
	in.Register("cat", cmdCat)
	in.Register("tac", cmdTac)
	in.Register("head", cmdHead)
	in.Register("tail", cmdTail)
	in.Register("touch", cmdTouch)
	in.Register("mkdir", cmdMkdir)
	in.Register("rmdir", cmdRmdir)
	in.Register("rm", cmdRm)
	in.Register("cp", cmdCp)
	in.Register("mv", cmdMv)
	in.Register("ln", cmdLn)
	in.Register("chmod", cmdChmod)
	in.Register("chown", cmdChown)
	in.Register("chgrp", func(c *Context) int { return 0 })
	in.Register("wc", cmdWc)
	in.Register("grep", cmdGrep)
	in.Register("egrep", cmdGrep)
	in.Register("fgrep", cmdGrep)
	in.Register("which", cmdWhich)
	in.Register("find", cmdFind)
	in.Register("stat", cmdStat)
	in.Register("du", cmdDu)
	in.Register("basename", cmdBasename)
	in.Register("dirname", cmdDirname)
	in.Register("readlink", cmdReadlink)
	in.Register("realpath", cmdRealpath)
	in.Register("cut", cmdCut)
	in.Register("sort", cmdSort)
	in.Register("uniq", cmdUniq)
	in.Register("tr", cmdTr)
	in.Register("tee", cmdTee)
	in.Register("cksum", func(c *Context) int { return readEachOrStdin(c, cksumOne) })
	in.Register("md5sum", func(c *Context) int { return sumCmd(c, "md5") })
	in.Register("sha1sum", func(c *Context) int { return sumCmd(c, "sha1") })
	in.Register("sha256sum", func(c *Context) int { return sumCmd(c, "sha256") })
}

// inputFiles returns the non-flag arguments; flags are the ones starting '-'.
func splitFlags(args []string) (flags, files []string) {
	rest := false
	for _, a := range args {
		if a == "--" {
			rest = true
			continue
		}
		if !rest && len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
		} else {
			files = append(files, a)
		}
	}
	return
}

func hasFlag(flags []string, letters string) bool {
	for _, f := range flags {
		for _, r := range f[1:] {
			if strings.ContainsRune(letters, r) {
				return true
			}
		}
	}
	return false
}

// readTarget reads a file for a command, handling placeholders (which the
// model fallback fills later) and returning a bash-style error string.
func (c *Context) readTarget(arg string) ([]byte, error) {
	abs := c.Sess.abs(arg)
	info, err := c.FS().Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", arg, vfs.Strerror(err))
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s: Is a directory", arg)
	}
	if !permit(c.Sess, abs, 'r') {
		return nil, fmt.Errorf("%s: Permission denied", arg)
	}
	data, dinfo, err := c.FS().ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("%s: %s", arg, vfs.Strerror(err))
	}
	if dinfo.Placeholder {
		if gen := c.Interp.FileContent; gen != nil {
			if filled, ok := gen(c, abs, dinfo); ok {
				return filled, nil
			}
		}
		return nil, nil
	}
	return data, nil
}

func cmdCat(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	if len(files) == 0 {
		io.Copy(c.Stdout, c.Stdin)
		return 0
	}
	status := 0
	for _, f := range files {
		if f == "-" {
			io.Copy(c.Stdout, c.Stdin)
			continue
		}
		data, err := c.readTarget(f)
		if err != nil {
			c.Errorf("%s", err)
			status = 1
			continue
		}
		c.Stdout.Write(data)
	}
	return status
}

func cmdTac(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	var data []byte
	if len(files) == 0 {
		data, _ = io.ReadAll(c.Stdin)
	} else {
		for _, f := range files {
			d, err := c.readTarget(f)
			if err != nil {
				c.Errorf("%s", err)
				return 1
			}
			data = append(data, d...)
		}
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		c.Print(lines[i] + "\n")
	}
	return 0
}

func cmdHead(c *Context) int { return headTail(c, true) }
func cmdTail(c *Context) int { return headTail(c, false) }

func headTail(c *Context, head bool) int {
	n := 10
	var files []string
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-n" && i+1 < len(args):
			n, _ = strconv.Atoi(strings.TrimPrefix(args[i+1], "+"))
			i++
		case strings.HasPrefix(a, "-n"):
			n, _ = strconv.Atoi(a[2:])
		case strings.HasPrefix(a, "-") && len(a) > 1 && a[1] >= '0' && a[1] <= '9':
			n, _ = strconv.Atoi(a[1:])
		case a == "-f" || a == "-q" || a == "-v" || a == "-c":
			// -f (follow) can't really follow; treat as no-op
		default:
			files = append(files, a)
		}
	}
	emit := func(data []byte) {
		lines := strings.SplitAfter(string(data), "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		if head {
			if n < len(lines) {
				lines = lines[:n]
			}
		} else {
			if n < len(lines) {
				lines = lines[len(lines)-n:]
			}
		}
		for _, l := range lines {
			c.Print(l)
		}
	}
	if len(files) == 0 {
		data, _ := io.ReadAll(c.Stdin)
		emit(data)
		return 0
	}
	status := 0
	for i, f := range files {
		data, err := c.readTarget(f)
		if err != nil {
			c.Errorf("%s", err)
			status = 1
			continue
		}
		if len(files) > 1 {
			if i > 0 {
				c.Print("\n")
			}
			c.Printf("==> %s <==\n", f)
		}
		emit(data)
	}
	return status
}

func cmdTouch(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	status := 0
	for _, f := range files {
		abs := c.Sess.abs(f)
		if err := c.FS().Touch(abs, c.writeOpts()); err != nil {
			c.Errorf("cannot touch '%s': %s", f, vfs.Strerror(err))
			status = 1
		}
	}
	return status
}

func cmdMkdir(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	parents := hasFlag(flags, "p")
	status := 0
	for _, f := range files {
		abs := c.Sess.abs(f)
		var err error
		if parents {
			err = c.FS().MkdirAll(abs, c.writeOptsMode(0o755))
		} else {
			err = c.FS().Mkdir(abs, c.writeOptsMode(0o755))
		}
		if err != nil {
			c.Errorf("cannot create directory '%s': %s", f, vfs.Strerror(err))
			status = 1
		}
	}
	return status
}

func cmdRmdir(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	status := 0
	for _, f := range files {
		if err := c.FS().Remove(c.Sess.abs(f)); err != nil {
			c.Errorf("failed to remove '%s': %s", f, vfs.Strerror(err))
			status = 1
		}
	}
	return status
}

func cmdRm(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	recursive := hasFlag(flags, "rR")
	force := hasFlag(flags, "f")
	status := 0
	for _, f := range files {
		abs := c.Sess.abs(f)
		info, err := c.FS().Lstat(abs)
		if err != nil {
			if !force {
				c.Errorf("cannot remove '%s': %s", f, vfs.Strerror(err))
				status = 1
			}
			continue
		}
		if info.IsDir() && !recursive {
			c.Errorf("cannot remove '%s': Is a directory", f)
			status = 1
			continue
		}
		var rmErr error
		if recursive {
			rmErr = c.FS().RemoveAll(abs)
		} else {
			rmErr = c.FS().Remove(abs)
		}
		if rmErr != nil && !force {
			c.Errorf("cannot remove '%s': %s", f, vfs.Strerror(rmErr))
			status = 1
		}
	}
	return status
}

func cmdCp(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	recursive := hasFlag(flags, "rRa")
	if len(files) < 2 {
		c.Errorf("missing destination file operand")
		return 1
	}
	dst := files[len(files)-1]
	srcs := files[:len(files)-1]
	status := 0
	for _, src := range srcs {
		if err := c.copyOne(src, dst, recursive, len(srcs) > 1); err != nil {
			c.Errorf("%s", err)
			status = 1
		}
	}
	return status
}

func (c *Context) copyOne(src, dst string, recursive, dstIsDir bool) error {
	sabs := c.Sess.abs(src)
	dabs := c.Sess.abs(dst)
	sinfo, err := c.FS().Stat(sabs)
	if err != nil {
		return fmt.Errorf("cannot stat '%s': %s", src, vfs.Strerror(err))
	}
	if dinfo, derr := c.FS().Stat(dabs); derr == nil && dinfo.IsDir() {
		dabs = path.Join(dabs, path.Base(sabs))
		dstIsDir = true
	}
	_ = dstIsDir
	if sinfo.IsDir() {
		if !recursive {
			return fmt.Errorf("-r not specified; omitting directory '%s'", src)
		}
		return c.copyTree(sabs, dabs)
	}
	data, _, err := c.FS().ReadFile(sabs)
	if err != nil {
		return fmt.Errorf("cannot read '%s': %s", src, vfs.Strerror(err))
	}
	return c.FS().WriteFile(dabs, data, vfs.WriteOptions{Mode: sinfo.Mode.Perm(), UID: c.Sess.Cred.UID, GID: c.gid()})
}

func (c *Context) copyTree(src, dst string) error {
	// Collect the tree first: Walk holds a read lock, so we must not mutate
	// the filesystem from inside the callback.
	type entry struct {
		path string
		info vfs.Info
	}
	var entries []entry
	if err := c.FS().Walk(src, func(p string, info vfs.Info) error {
		entries = append(entries, entry{p, info})
		return nil
	}); err != nil {
		return err
	}
	for _, e := range entries {
		target := dst + strings.TrimPrefix(e.path, src)
		opts := vfs.WriteOptions{Mode: e.info.Mode.Perm(), UID: c.Sess.Cred.UID, GID: c.gid()}
		if e.info.IsDir() {
			if err := c.FS().MkdirAll(target, opts); err != nil {
				return err
			}
			continue
		}
		data, _, _ := c.FS().ReadFile(e.path)
		if err := c.FS().WriteFile(target, data, opts); err != nil {
			return err
		}
	}
	return nil
}

func cmdMv(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	if len(files) < 2 {
		c.Errorf("missing destination file operand")
		return 1
	}
	dst := files[len(files)-1]
	status := 0
	for _, src := range files[:len(files)-1] {
		if err := c.FS().Rename(c.Sess.abs(src), c.Sess.abs(dst)); err != nil {
			c.Errorf("cannot move '%s' to '%s': %s", src, dst, vfs.Strerror(err))
			status = 1
		}
	}
	return status
}

func cmdLn(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	if !hasFlag(flags, "s") {
		// Hard links: emulate as a copy of metadata; for a honeypot a
		// second name is enough. We just symlink instead.
	}
	if len(files) < 2 {
		c.Errorf("missing file operand")
		return 1
	}
	target, linkName := files[0], files[1]
	if err := c.FS().Symlink(target, c.Sess.abs(linkName), c.writeOpts()); err != nil {
		c.Errorf("failed to create symbolic link '%s': %s", linkName, vfs.Strerror(err))
		return 1
	}
	return 0
}

func cmdChmod(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	_ = flags
	if len(files) < 2 {
		c.Errorf("missing operand")
		return 1
	}
	modeStr, targets := files[0], files[1:]
	status := 0
	for _, t := range targets {
		abs := c.Sess.abs(t)
		info, err := c.FS().Stat(abs)
		if err != nil {
			c.Errorf("cannot access '%s': %s", t, vfs.Strerror(err))
			status = 1
			continue
		}
		mode, err := parseMode(modeStr, info.Mode.Perm())
		if err != nil {
			c.Errorf("invalid mode: '%s'", modeStr)
			return 1
		}
		if err := c.FS().Chmod(abs, mode); err != nil {
			c.Errorf("changing permissions of '%s': %s", t, vfs.Strerror(err))
			status = 1
		}
	}
	return status
}

func cmdChown(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	if len(files) < 2 {
		c.Errorf("missing operand")
		return 1
	}
	spec, targets := files[0], files[1:]
	if !c.Sess.Cred.IsRoot() {
		c.Errorf("changing ownership of '%s': Operation not permitted", targets[0])
		return 1
	}
	names := newIDNames(c)
	owner, group, _ := strings.Cut(spec, ":")
	status := 0
	for _, t := range targets {
		abs := c.Sess.abs(t)
		info, err := c.FS().Stat(abs)
		if err != nil {
			c.Errorf("cannot access '%s': %s", t, vfs.Strerror(err))
			status = 1
			continue
		}
		uid, gid := info.UID, info.GID
		if owner != "" {
			uid = resolveID(owner, names.users)
		}
		if group != "" {
			gid = resolveID(group, names.groups)
		}
		if err := c.FS().Chown(abs, uid, gid); err != nil {
			c.Errorf("changing ownership of '%s': %s", t, vfs.Strerror(err))
			status = 1
		}
	}
	return status
}

func resolveID(s string, table map[int]string) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	for id, name := range table {
		if name == s {
			return id
		}
	}
	return 0
}

func cmdWc(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	wantL := hasFlag(flags, "l")
	wantW := hasFlag(flags, "w")
	wantC := hasFlag(flags, "cm")
	if !wantL && !wantW && !wantC {
		wantL, wantW, wantC = true, true, true
	}
	count := func(data []byte) (int, int, int) {
		lines := 0
		for _, b := range data {
			if b == '\n' {
				lines++
			}
		}
		return lines, len(strings.Fields(string(data))), len(data)
	}
	format := func(l, w, ch int, name string) string {
		var parts []string
		if wantL {
			parts = append(parts, fmt.Sprintf("%7d", l))
		}
		if wantW {
			parts = append(parts, fmt.Sprintf("%7d", w))
		}
		if wantC {
			parts = append(parts, fmt.Sprintf("%7d", ch))
		}
		s := strings.Join(parts, "")
		if name != "" {
			s += " " + name
		}
		return s + "\n"
	}
	if len(files) == 0 {
		data, _ := io.ReadAll(c.Stdin)
		l, w, ch := count(data)
		c.Print(format(l, w, ch, ""))
		return 0
	}
	var tl, tw, tc int
	status := 0
	for _, f := range files {
		data, err := c.readTarget(f)
		if err != nil {
			c.Errorf("%s", err)
			status = 1
			continue
		}
		l, w, ch := count(data)
		tl, tw, tc = tl+l, tw+w, tc+ch
		c.Print(format(l, w, ch, f))
	}
	if len(files) > 1 {
		c.Print(format(tl, tw, tc, "total"))
	}
	return status
}

func cmdGrep(c *Context) int {
	var pattern string
	var files []string
	ignoreCase, invert, count, lineNum, recursive, fixed, wholeLine, quiet, listFiles := false, false, false, false, false, false, false, false, false
	args := c.Args[1:]
	if c.Args[0] == "fgrep" {
		fixed = true
	}
	havePat := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" && !havePat {
			if a == "-e" && i+1 < len(args) {
				pattern, havePat = args[i+1], true
				i++
				continue
			}
			for _, r := range a[1:] {
				switch r {
				case 'i':
					ignoreCase = true
				case 'v':
					invert = true
				case 'c':
					count = true
				case 'n':
					lineNum = true
				case 'r', 'R':
					recursive = true
				case 'F':
					fixed = true
				case 'w':
					wholeLine = true
				case 'q':
					quiet = true
				case 'l':
					listFiles = true
				case 'E':
				}
			}
			continue
		}
		if !havePat {
			pattern, havePat = a, true
		} else {
			files = append(files, a)
		}
	}
	if !havePat {
		c.Errorf("usage: grep [OPTION]... PATTERN [FILE]...")
		return 2
	}

	var re *regexp.Regexp
	if !fixed {
		expr := pattern
		if wholeLine {
			expr = `\b(?:` + expr + `)\b`
		}
		if ignoreCase {
			expr = "(?i)" + expr
		}
		var err error
		re, err = regexp.Compile(expr)
		if err != nil {
			c.Errorf("invalid pattern")
			return 2
		}
	}
	match := func(line string) bool {
		var m bool
		if re != nil {
			m = re.MatchString(line)
		} else {
			hay, needle := line, pattern
			if ignoreCase {
				hay, needle = strings.ToLower(line), strings.ToLower(pattern)
			}
			if wholeLine {
				m = hay == needle
			} else {
				m = strings.Contains(hay, needle)
			}
		}
		return m != invert
	}

	found := false
	grepData := func(name string, data []byte, withName bool) int {
		n := 0
		for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if match(line) {
				n++
				found = true
				if quiet || count || listFiles {
					continue
				}
				prefix := ""
				if withName {
					prefix = name + ":"
				}
				if lineNum {
					prefix += strconv.Itoa(i+1) + ":"
				}
				c.Print(prefix + line + "\n")
			}
		}
		if listFiles && n > 0 {
			c.Print(name + "\n")
		}
		if count {
			if withName {
				c.Printf("%s:%d\n", name, n)
			} else {
				c.Printf("%d\n", n)
			}
		}
		return n
	}

	if len(files) == 0 {
		data, _ := io.ReadAll(c.Stdin)
		grepData("(standard input)", data, false)
	} else {
		withName := len(files) > 1 || recursive
		for _, f := range files {
			abs := c.Sess.abs(f)
			if recursive {
				var paths []string
				_ = c.FS().Walk(abs, func(p string, info vfs.Info) error {
					if !info.IsDir() && !info.Placeholder {
						paths = append(paths, p)
					}
					return nil
				})
				for _, p := range paths {
					d, _, _ := c.FS().ReadFile(p)
					grepData(p, d, true)
				}
				continue
			}
			data, err := c.readTarget(f)
			if err != nil {
				c.Errorf("%s", err)
				continue
			}
			grepData(f, data, withName)
		}
	}
	if quiet {
		if found {
			return 0
		}
		return 1
	}
	if found {
		return 0
	}
	return 1
}

func cmdWhich(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	pathDirs := strings.Split(c.Getenv("PATH"), ":")
	status := 0
	for _, name := range files {
		found := ""
		for _, d := range pathDirs {
			cand := path.Join(d, name)
			if info, err := c.FS().Stat(cand); err == nil && !info.IsDir() && info.Mode.Perm()&0o111 != 0 {
				found = cand
				break
			}
		}
		if found == "" {
			status = 1
			continue
		}
		c.Print(found + "\n")
	}
	return status
}

func cmdFind(c *Context) int {
	root := "."
	args := c.Args[1:]
	i := 0
	for i < len(args) && !strings.HasPrefix(args[i], "-") {
		root = args[i]
		i++
	}
	var namePat, typ string
	maxDepth := -1
	for ; i < len(args); i++ {
		switch args[i] {
		case "-name", "-iname":
			if i+1 < len(args) {
				namePat = args[i+1]
				i++
			}
		case "-type":
			if i+1 < len(args) {
				typ = args[i+1]
				i++
			}
		case "-maxdepth":
			if i+1 < len(args) {
				maxDepth, _ = strconv.Atoi(args[i+1])
				i++
			}
		case "-print", "-print0":
		}
	}
	abs := c.Sess.abs(root)
	rootDepth := strings.Count(strings.TrimRight(abs, "/"), "/")
	status := 0
	err := c.FS().Walk(abs, func(p string, info vfs.Info) error {
		if maxDepth >= 0 {
			depth := strings.Count(strings.TrimRight(p, "/"), "/") - rootDepth
			if depth > maxDepth {
				if info.IsDir() {
					return filepathSkipDir()
				}
				return nil
			}
		}
		if namePat != "" {
			if ok, _ := path.Match(namePat, path.Base(p)); !ok {
				return nil
			}
		}
		switch typ {
		case "f":
			if info.IsDir() || info.IsSymlink() {
				return nil
			}
		case "d":
			if !info.IsDir() {
				return nil
			}
		case "l":
			if !info.IsSymlink() {
				return nil
			}
		}
		disp := p
		if root != abs {
			disp = root + strings.TrimPrefix(p, abs)
		}
		c.Print(disp + "\n")
		return nil
	})
	if err != nil {
		c.Errorf("'%s': %s", root, vfs.Strerror(err))
		status = 1
	}
	return status
}

func cmdStat(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	terse := hasFlag(flags, "t")
	names := newIDNames(c)
	status := 0
	for _, f := range files {
		abs := c.Sess.abs(f)
		info, err := c.FS().Lstat(abs)
		if err != nil {
			c.Errorf("cannot stat '%s': %s", f, vfs.Strerror(err))
			status = 1
			continue
		}
		kind := "regular file"
		switch {
		case info.IsDir():
			kind = "directory"
		case info.IsSymlink():
			kind = "symbolic link"
		case info.IsDevice():
			kind = "character special file"
		case info.Size == 0:
			kind = "regular empty file"
		}
		if terse {
			c.Printf("%s %d %o %d %d\n", f, info.Size, info.Mode.Perm(), info.UID, info.GID)
			continue
		}
		c.Printf("  File: %s\n", f)
		c.Printf("  Size: %-15d Blocks: %-10d IO Block: 4096   %s\n", info.Size, blocksFor(info.Size), kind)
		c.Printf("Access: (%04o/%s)  Uid: (%5d/%8s)   Gid: (%5d/%8s)\n",
			info.Mode.Perm(), modeString(info.Mode), info.UID, names.user(info.UID), info.GID, names.group(info.GID))
		t := info.ModTime.Format("2006-01-02 15:04:05.000000000 -0700")
		c.Printf("Access: %s\nModify: %s\nChange: %s\n Birth: -\n", t, t, t)
	}
	return status
}

func cmdDu(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	human := hasFlag(flags, "h")
	summary := hasFlag(flags, "s")
	if len(files) == 0 {
		files = []string{"."}
	}
	status := 0
	for _, f := range files {
		abs := c.Sess.abs(f)
		var total int64
		err := c.FS().Walk(abs, func(p string, info vfs.Info) error {
			total += blocksFor(info.Size)
			if !summary && info.IsDir() {
				// print per-directory in a full du; keep it simple: only totals
			}
			return nil
		})
		if err != nil {
			c.Errorf("cannot access '%s': %s", f, vfs.Strerror(err))
			status = 1
			continue
		}
		if human {
			c.Printf("%s\t%s\n", humanSize(total*1024, true), f)
		} else {
			c.Printf("%d\t%s\n", total, f)
		}
	}
	return status
}

func cmdBasename(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	if len(files) == 0 {
		c.Errorf("missing operand")
		return 1
	}
	name := path.Base(files[0])
	if len(files) > 1 {
		name = strings.TrimSuffix(name, files[1])
	}
	c.Print(name + "\n")
	return 0
}

func cmdDirname(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	if len(files) == 0 {
		c.Errorf("missing operand")
		return 1
	}
	c.Print(path.Dir(files[0]) + "\n")
	return 0
}

func cmdReadlink(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	canon := hasFlag(flags, "f")
	status := 0
	for _, f := range files {
		abs := c.Sess.abs(f)
		if canon {
			real, err := c.FS().RealPath(abs)
			if err != nil {
				status = 1
				continue
			}
			c.Print(real + "\n")
			continue
		}
		info, err := c.FS().Lstat(abs)
		if err != nil || !info.IsSymlink() {
			status = 1
			continue
		}
		c.Print(info.Target + "\n")
	}
	return status
}

func cmdRealpath(c *Context) int {
	_, files := splitFlags(c.Args[1:])
	status := 0
	for _, f := range files {
		real, err := c.FS().RealPath(c.Sess.abs(f))
		if err != nil {
			c.Errorf("%s: %s", f, vfs.Strerror(err))
			status = 1
			continue
		}
		c.Print(real + "\n")
	}
	return status
}

func cmdCut(c *Context) int {
	delim := "\t"
	var fields string
	var files []string
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "-d"):
			if a == "-d" && i+1 < len(args) {
				delim = args[i+1]
				i++
			} else {
				delim = a[2:]
			}
		case strings.HasPrefix(a, "-f"):
			if a == "-f" && i+1 < len(args) {
				fields = args[i+1]
				i++
			} else {
				fields = a[2:]
			}
		default:
			files = append(files, a)
		}
	}
	sel := parseFieldList(fields)
	process := func(data []byte) {
		for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			cols := strings.Split(line, delim)
			var out []string
			for _, idx := range sel {
				if idx >= 1 && idx <= len(cols) {
					out = append(out, cols[idx-1])
				}
			}
			c.Print(strings.Join(out, delim) + "\n")
		}
	}
	if len(files) == 0 {
		data, _ := io.ReadAll(c.Stdin)
		process(data)
		return 0
	}
	for _, f := range files {
		data, err := c.readTarget(f)
		if err != nil {
			c.Errorf("%s", err)
			return 1
		}
		process(data)
	}
	return 0
}

func parseFieldList(s string) []int {
	var out []int
	for _, part := range strings.Split(s, ",") {
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, _ := strconv.Atoi(lo)
			b, _ := strconv.Atoi(hi)
			for i := a; i <= b && i > 0; i++ {
				out = append(out, i)
			}
		} else if n, err := strconv.Atoi(part); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func cmdSort(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	numeric := hasFlag(flags, "n")
	reverse := hasFlag(flags, "r")
	unique := hasFlag(flags, "u")
	var data []byte
	if len(files) == 0 {
		data, _ = io.ReadAll(c.Stdin)
	} else {
		for _, f := range files {
			d, err := c.readTarget(f)
			if err != nil {
				c.Errorf("%s", err)
				return 1
			}
			data = append(data, d...)
		}
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return 0
	}
	sort.SliceStable(lines, func(i, j int) bool {
		if numeric {
			a, _ := strconv.ParseFloat(strings.TrimSpace(lines[i]), 64)
			b, _ := strconv.ParseFloat(strings.TrimSpace(lines[j]), 64)
			return a < b
		}
		return lines[i] < lines[j]
	})
	if reverse {
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
	}
	var prev string
	first := true
	for _, l := range lines {
		if unique && !first && l == prev {
			continue
		}
		c.Print(l + "\n")
		prev, first = l, false
	}
	return 0
}

func cmdUniq(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	countMode := hasFlag(flags, "c")
	var data []byte
	if len(files) == 0 {
		data, _ = io.ReadAll(c.Stdin)
	} else {
		data, _ = c.readTarget(files[0])
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	i := 0
	for i < len(lines) {
		j := i + 1
		for j < len(lines) && lines[j] == lines[i] {
			j++
		}
		if countMode {
			c.Printf("%7d %s\n", j-i, lines[i])
		} else {
			c.Print(lines[i] + "\n")
		}
		i = j
	}
	return 0
}

func cmdTr(c *Context) int {
	_, sets := splitFlags(c.Args[1:])
	del := hasFlag(c.Args[1:], "d")
	data, _ := io.ReadAll(c.Stdin)
	s := string(data)
	if del && len(sets) >= 1 {
		s = strings.Map(func(r rune) rune {
			if strings.ContainsRune(expandTrSet(sets[0]), r) {
				return -1
			}
			return r
		}, s)
	} else if len(sets) >= 2 {
		from, to := expandTrSet(sets[0]), expandTrSet(sets[1])
		s = strings.Map(func(r rune) rune {
			if idx := strings.IndexRune(from, r); idx >= 0 {
				if idx < len(to) {
					return rune(to[idx])
				}
				return rune(to[len(to)-1])
			}
			return r
		}, s)
	}
	c.Print(s)
	return 0
}

func expandTrSet(s string) string {
	switch s {
	case "[:upper:]", "A-Z":
		return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case "[:lower:]", "a-z":
		return "abcdefghijklmnopqrstuvwxyz"
	case "[:digit:]", "0-9":
		return "0123456789"
	}
	return s
}

func cmdTee(c *Context) int {
	flags, files := splitFlags(c.Args[1:])
	appnd := hasFlag(flags, "a")
	data, _ := io.ReadAll(c.Stdin)
	c.Stdout.Write(data)
	status := 0
	for _, f := range files {
		var err error
		if appnd {
			err = c.FS().AppendFile(c.Sess.abs(f), data, c.writeOpts())
		} else {
			err = c.FS().WriteFile(c.Sess.abs(f), data, c.writeOpts())
		}
		if err != nil {
			c.Errorf("%s: %s", f, vfs.Strerror(err))
			status = 1
		}
	}
	return status
}

// --- context write-option helpers ---

func (c *Context) gid() int {
	if len(c.Sess.Cred.GIDs) > 0 {
		return c.Sess.Cred.GIDs[0]
	}
	return 0
}

func (c *Context) writeOpts() vfs.WriteOptions {
	return vfs.WriteOptions{Mode: 0o644 &^ c.Sess.Umask, UID: c.Sess.Cred.UID, GID: c.gid()}
}

func (c *Context) writeOptsMode(mode uint32) vfs.WriteOptions {
	return vfs.WriteOptions{Mode: fsFileMode(int64(mode)) &^ c.Sess.Umask, UID: c.Sess.Cred.UID, GID: c.gid()}
}
