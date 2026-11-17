package shell

import (
	"fmt"
	"io"
	"io/fs"
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
	in.registerText()
	in.registerProcTools()
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
	type result struct {
		l, w, ch int
		name     string
	}
	var results []result
	status := 0
	// GNU wc pads every column to one width: 1 when a single count of a
	// single input is printed, otherwise the digits of the total size of
	// the regular files read, and at least 7 when stdin is among them.
	width, total, stdin := 1, 0, false
	if len(files) == 0 {
		data, _ := io.ReadAll(c.Stdin)
		l, w, ch := count(data)
		results = append(results, result{l, w, ch, ""})
		stdin = true
	}
	for _, f := range files {
		data, err := c.readTarget(f)
		if err != nil {
			c.Errorf("%s", err)
			status = 1
			continue
		}
		l, w, ch := count(data)
		results = append(results, result{l, w, ch, f})
		total += ch
	}
	if len(files) > 1 {
		var t result
		for _, r := range results {
			t.l, t.w, t.ch = t.l+r.l, t.w+r.w, t.ch+r.ch
		}
		t.name = "total"
		results = append(results, t)
	}
	ncounts := 0
	for _, b := range []bool{wantL, wantW, wantC} {
		if b {
			ncounts++
		}
	}
	if !(ncounts == 1 && len(results) == 1) {
		width = len(strconv.Itoa(total))
		if stdin && width < 7 {
			width = 7
		}
	}
	for _, r := range results {
		var parts []string
		if wantL {
			parts = append(parts, fmt.Sprintf("%*d", width, r.l))
		}
		if wantW {
			parts = append(parts, fmt.Sprintf("%*d", width, r.w))
		}
		if wantC {
			parts = append(parts, fmt.Sprintf("%*d", width, r.ch))
		}
		line := strings.Join(parts, " ")
		if r.name != "" {
			line += " " + r.name
		}
		c.Print(line + "\n")
	}
	return status
}

func cmdGrep(c *Context) int {
	var pattern string
	var files []string
	ignoreCase, invert, count, lineNum, recursive, fixed, wholeLine, quiet, listFiles := false, false, false, false, false, false, false, false, false
	args := c.Args[1:]
	extended := path.Base(c.Args[0]) == "egrep"
	if path.Base(c.Args[0]) == "fgrep" {
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
					extended = true
				case 'G':
					extended = false
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
		expr := gnuWordBounds(pattern)
		if !extended {
			expr = breToRE2(pattern)
		}
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
	var format string
	printf := false
	var rest []string
	args := c.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "-c" || a == "--format" || a == "--printf") && i+1 < len(args):
			format, printf = args[i+1], a == "--printf"
			i++
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "--printf="):
			format, printf = strings.TrimPrefix(a, "--printf="), true
		case strings.HasPrefix(a, "-c") && len(a) > 2:
			format = a[2:]
		default:
			rest = append(rest, a)
		}
	}
	flags, files := splitFlags(rest)
	terse := hasFlag(flags, "t")
	if len(files) == 0 {
		fmt.Fprint(c.Stderr, "stat: missing operand\nTry 'stat --help' for more information.\n")
		return 1
	}
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
		if format != "" {
			out := statFormat(format, f, kind, info, names)
			if printf {
				c.Print(expandEscapes(out))
			} else {
				c.Print(out + "\n")
			}
			continue
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

// statFormat expands GNU stat's %-sequences for one file.
func statFormat(format, name, kind string, info vfs.Info, names *idNames) string {
	var b strings.Builder
	t := info.ModTime
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			b.WriteByte(format[i])
			continue
		}
		i++
		switch format[i] {
		case 'a':
			perm := uint32(info.Mode.Perm())
			if info.Mode&fs.ModeSetuid != 0 {
				perm |= 0o4000
			}
			if info.Mode&fs.ModeSetgid != 0 {
				perm |= 0o2000
			}
			if info.Mode&fs.ModeSticky != 0 {
				perm |= 0o1000
			}
			fmt.Fprintf(&b, "%o", perm)
		case 'A':
			b.WriteString(modeString(info.Mode))
		case 'b':
			fmt.Fprintf(&b, "%d", blocksFor(info.Size))
		case 'B':
			b.WriteString("512")
		case 'd':
			b.WriteString("64769")
		case 'F':
			b.WriteString(kind)
		case 'g':
			fmt.Fprintf(&b, "%d", info.GID)
		case 'G':
			b.WriteString(names.group(info.GID))
		case 'h':
			fmt.Fprintf(&b, "%d", nlinkFor(info))
		case 'i':
			fmt.Fprintf(&b, "%d", seedInode(name)%3000000+130000)
		case 'n':
			b.WriteString(name)
		case 'N':
			b.WriteString("'" + name + "'")
		case 'o':
			b.WriteString("4096")
		case 's':
			fmt.Fprintf(&b, "%d", info.Size)
		case 'u':
			fmt.Fprintf(&b, "%d", info.UID)
		case 'U':
			b.WriteString(names.user(info.UID))
		case 'w':
			b.WriteString("-")
		case 'W':
			b.WriteString("0")
		case 'x', 'y', 'z':
			b.WriteString(t.Format("2006-01-02 15:04:05.000000000 -0700"))
		case 'X', 'Y', 'Z':
			fmt.Fprintf(&b, "%d", t.Unix())
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
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
	outDelim := ""
	var spec, mode string // mode is 'f', 'c' or 'b'
	onlyDelimited := false
	var files []string
	args := c.Args[1:]
	takeVal := func(i *int, a, flag string) string {
		if a == flag && *i+1 < len(args) {
			*i++
			return args[*i]
		}
		return strings.TrimPrefix(a, flag)
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--output-delimiter="):
			outDelim = strings.TrimPrefix(a, "--output-delimiter=")
		case a == "-s" || a == "--only-delimited":
			onlyDelimited = true
		case strings.HasPrefix(a, "-d"):
			delim = takeVal(&i, a, "-d")
		case strings.HasPrefix(a, "-f"), strings.HasPrefix(a, "-c"), strings.HasPrefix(a, "-b"):
			mode = a[1:2]
			spec = takeVal(&i, a, a[:2])
		default:
			files = append(files, a)
		}
	}
	if mode == "" {
		fmt.Fprint(c.Stderr, "cut: you must specify a list of bytes, characters, or fields\nTry 'cut --help' for more information.\n")
		return 1
	}
	ranges, ok := parseCutRanges(spec)
	if !ok {
		fmt.Fprintf(c.Stderr, "cut: invalid field value '%s'\nTry 'cut --help' for more information.\n", spec)
		return 1
	}
	if delim == "" {
		delim = "\t"
	}
	delim = delim[:1]
	if outDelim == "" && mode == "f" {
		outDelim = delim
	}
	process := func(data []byte) {
		text := string(data)
		if text == "" {
			return
		}
		for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
			if mode != "f" {
				var b []byte
				for k := 0; k < len(line); k++ {
					if inCutRanges(ranges, k+1) {
						b = append(b, line[k])
					}
				}
				c.Print(string(b) + "\n")
				continue
			}
			if !strings.Contains(line, delim) {
				if !onlyDelimited {
					c.Print(line + "\n")
				}
				continue
			}
			var out []string
			for k, col := range strings.Split(line, delim) {
				if inCutRanges(ranges, k+1) {
					out = append(out, col)
				}
			}
			c.Print(strings.Join(out, outDelim) + "\n")
		}
	}
	if len(files) == 0 {
		data, _ := io.ReadAll(c.Stdin)
		process(data)
		return 0
	}
	status := 0
	for _, f := range files {
		data, err := c.readTarget(f)
		if err != nil {
			fmt.Fprintf(c.Stderr, "cut: %s: No such file or directory\n", f)
			status = 1
			continue
		}
		process(data)
	}
	return status
}

// cutRange is one piece of a cut LIST: N, N-M, N- or -M (hi 0 = open).
type cutRange struct{ lo, hi int }

func parseCutRanges(spec string) ([]cutRange, bool) {
	var out []cutRange
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		r := cutRange{}
		var err error
		if lo != "" {
			if r.lo, err = strconv.Atoi(lo); err != nil || r.lo < 1 {
				return nil, false
			}
		} else {
			r.lo = 1
		}
		switch {
		case !isRange:
			r.hi = r.lo
		case hi != "":
			if r.hi, err = strconv.Atoi(hi); err != nil || r.hi < r.lo {
				return nil, false
			}
		}
		if lo == "" && hi == "" {
			return nil, false
		}
		out = append(out, r)
	}
	return out, len(out) > 0
}

func inCutRanges(rs []cutRange, n int) bool {
	for _, r := range rs {
		if n >= r.lo && (r.hi == 0 || n <= r.hi) {
			return true
		}
	}
	return false
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
	del, squeeze, complement := false, false, false
	var sets []string
	for _, a := range c.Args[1:] {
		if strings.HasPrefix(a, "-") && len(a) > 1 && len(sets) == 0 {
			for _, r := range a[1:] {
				switch r {
				case 'd':
					del = true
				case 's':
					squeeze = true
				case 'c', 'C':
					complement = true
				}
			}
			continue
		}
		sets = append(sets, a)
	}
	if len(sets) == 0 || (!del && !squeeze && len(sets) < 2) {
		if len(sets) == 0 {
			fmt.Fprint(c.Stderr, "tr: missing operand\nTry 'tr --help' for more information.\n")
		} else {
			fmt.Fprintf(c.Stderr, "tr: missing operand after %s\nTwo strings must be given when translating.\nTry 'tr --help' for more information.\n", shellQuoteJoin(sets[:1]))
		}
		return 1
	}
	data, _ := io.ReadAll(c.Stdin)
	set1 := expandTrSet(sets[0])
	in1 := func(b byte) bool { return strings.IndexByte(set1, b) >= 0 != complement }
	var out []byte
	switch {
	case del:
		for _, b := range data {
			if !in1(b) {
				out = append(out, b)
			}
		}
		if squeeze && len(sets) > 1 {
			out = squeezeBytes(out, expandTrSet(sets[1]))
		}
	case len(sets) >= 2:
		set2 := expandTrSet(sets[1])
		for _, b := range data {
			idx := strings.IndexByte(set1, b)
			switch {
			case complement && idx < 0 && set2 != "":
				out = append(out, set2[len(set2)-1])
			case !complement && idx >= 0 && set2 != "":
				out = append(out, set2[min(idx, len(set2)-1)])
			default:
				out = append(out, b)
			}
		}
		if squeeze {
			out = squeezeBytes(out, set2)
		}
	default: // -s with one set
		out = squeezeBytes(data, set1)
	}
	c.Stdout.Write(out)
	return 0
}

func squeezeBytes(data []byte, set string) []byte {
	var out []byte
	for i, b := range data {
		if i > 0 && b == data[i-1] && strings.IndexByte(set, b) >= 0 {
			continue
		}
		out = append(out, b)
	}
	return out
}

// expandTrSet expands a tr SET: backslash escapes, a-z ranges and
// [:class:] names, as bytes.
func expandTrSet(s string) string {
	classes := map[string]string{
		"[:upper:]":  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"[:lower:]":  "abcdefghijklmnopqrstuvwxyz",
		"[:digit:]":  "0123456789",
		"[:space:]":  " \t\n\v\f\r",
		"[:blank:]":  " \t",
		"[:alpha:]":  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"[:alnum:]":  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"[:punct:]":  "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
		"[:xdigit:]": "0123456789ABCDEFabcdef",
	}
	var raw []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '[' {
			if j := strings.Index(s[i:], ":]"); j > 0 {
				if cls, ok := classes[s[i:i+j+2]]; ok {
					raw = append(raw, cls...)
					i += j + 1
					continue
				}
			}
		}
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				raw = append(raw, '\n')
			case 't':
				raw = append(raw, '\t')
			case 'r':
				raw = append(raw, '\r')
			case 'v':
				raw = append(raw, '\v')
			case 'f':
				raw = append(raw, '\f')
			case '0', '1', '2', '3', '4', '5', '6', '7':
				j := i
				for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
				n, _ := strconv.ParseUint(s[i:j], 8, 8)
				raw = append(raw, byte(n))
				i = j - 1
			default:
				raw = append(raw, s[i])
			}
			continue
		}
		raw = append(raw, s[i])
	}
	var out []byte
	for i := 0; i < len(raw); i++ {
		if i+2 < len(raw) && raw[i+1] == '-' && raw[i] <= raw[i+2] {
			for b := int(raw[i]); b <= int(raw[i+2]); b++ {
				out = append(out, byte(b))
			}
			i += 2
			continue
		}
		out = append(out, raw[i])
	}
	return string(out)
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
